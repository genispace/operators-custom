/**
 * Minimal GeniSpace authentication middleware (must not throw).
 *
 * Supported headers:
 * - Authorization: GeniSpace <api_key>
 * - GeniSpace: <api_key>
 *
 * Does not use `Authorization: Bearer <token>` to avoid clashing with custom operators.
 *
 * Usage:
 * 1. Enable GeniSpace authentication for API-type operators in runtime config when needed.
 * 2. The platform may forward a system API key for verification.
 * 3. On success, `req.genispace` holds user, client, apiKey, and keyInfo.
 * 4. Operators that require auth should call `checkAuth()` in the route handler.
 *
 * Example:
 * ```javascript
 * app.post('/my-operator', auth(), (req, res) => {
 *   if (req.genispace) {
 *     console.log('User:', req.genispace.user.name);
 *     console.log('Team ID:', req.genispace.keyInfo?.teamId);
 *   }
 *   // operator logic...
 * });
 * ```
 */

const GeniSpace = require('genispace');
const config = require('../config/env');
const logger = require('../utils/logger');

// In-memory validation cache (can be replaced with Redis for multi-instance setups)
const authCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Periodically drop expired cache entries
setInterval(() => {
  const now = Date.now();
  for (const [key, item] of authCache.entries()) {
    if (item.expiresAt <= now) {
      authCache.delete(key);
    }
  }
}, CACHE_TTL);

/** Extract API key; does not support Bearer scheme (avoids clashes with custom operators). */
function extractApiKey(req) {
  try {
    // Prefer dedicated GeniSpace header when present
    const geniSpaceHeader = req.headers.genispace;
    if (geniSpaceHeader) {
      return geniSpaceHeader;
    }

    // Authorization: GeniSpace <api_key>
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('GeniSpace ')) {
      return authHeader.substring(10);
    }
    
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Validate an API key via the GeniSpace SDK (`apiKeys.validate` when available,
 * otherwise profile fetch as a fallback).
 */
async function validateApiKeyViaSDK(apiKey) {
  try {
    const baseUrl = config.genispace?.auth?.baseUrl || 'https://api.genispace.com';
    const timeout = config.genispace?.auth?.timeout || 10000;
    
    logger.debug('Creating GeniSpace SDK client', {
      baseUrl,
      timeout,
      envBaseUrl: process.env.GENISPACE_API_BASE_URL,
      configBaseUrl: config.genispace?.auth?.baseUrl
    });
    
    const client = new GeniSpace({
      apiKey: apiKey,
      baseURL: baseUrl,
      timeout: timeout
    });

    if (client.apiKeys && typeof client.apiKeys.validate === 'function') {
      const validationResult = await client.apiKeys.validate(apiKey);
      
      if (validationResult.success && validationResult.data.valid) {
        return {
          success: true,
          user: {
            id: validationResult.data.keyInfo.owner.id,
            email: validationResult.data.keyInfo.owner.email,
            name: validationResult.data.keyInfo.owner.name,
            company: null
          },
          keyInfo: {
            id: validationResult.data.keyInfo.id,
            name: validationResult.data.keyInfo.name,
            application: validationResult.data.keyInfo.application,
            permissions: validationResult.data.keyInfo.permissions || []
          },
          client: client
        };
      } else {
        return {
          success: false,
          error: validationResult.data?.reason || 'API key validation failed'
        };
      }
    } else {
      // Fallback when validate() is unavailable: prove the key by loading profile
      const user = await client.users.getProfile();
      
      return {
        success: true,
        user: {
          id: user.id || 'unknown',
          email: user.email || 'unknown',
          name: user.name || 'unknown',
          company: user.company || null
        },
        client: client
      };
    }

  } catch (e) {
    logger.error('SDK API key validation failed', {
      error: e.message,
      code: e.code
    });
    
    return {
      success: false,
      error: 'API key validation failed'
    };
  }
}

/** Public wrapper around {@link validateApiKeyViaSDK} with top-level error handling. */
async function validateApiKey(apiKey) {
  try {
    return await validateApiKeyViaSDK(apiKey);

  } catch (e) {
    logger.error('API key validation error', {
      error: e.message
    });
    
    return {
      success: false,
      error: 'API key validation service error'
    };
  }
}

/** Return a cached auth result if TTL has not expired. */
function getCache(apiKey) {
  try {
    const key = `auth:${apiKey.substring(0, 8)}`;
    const cached = authCache.get(key);
    
    if (cached && cached.expiresAt > Date.now()) {
      return cached.result;
    }
    
    return null;
  } catch (e) {
    return null;
  }
}

/** Persist a successful validation in the in-memory cache. */
function setCache(apiKey, result) {
  try {
    const key = `auth:${apiKey.substring(0, 8)}`;
    authCache.set(key, {
      result,
      expiresAt: Date.now() + CACHE_TTL
    });
  } catch (e) {
    // Ignore cache write failures
  }
}

/**
 * Express middleware: when an API key is present on API routes, validate it and
 * attach `req.genispace`. Operators still call `checkAuth()` for strict enforcement.
 */
function auth() {
  return async (req, res, next) => {
    try {
      const apiPrefix = config.apiPrefix || '/api';

      // Unauthenticated entry points (home, docs, operator list, definitions, health)
      const publicPaths = [
        apiPrefix,
        '/health',
        `${apiPrefix}/docs`,
        `${apiPrefix}/docs.json`,
        `${apiPrefix}/operators`
      ];

      if (publicPaths.includes(req.path) || 
          req.path.startsWith(`${apiPrefix}/docs/`) ||
          new RegExp(`^${apiPrefix}/operators/[^/]+/[^/]+/definition$`).test(req.path)) {
        return next();
      }

      // Non-API routes are untouched
      if (!req.path.startsWith(apiPrefix)) {
        return next();
      }

      const apiKey = extractApiKey(req);

      // If a key exists, try to validate and populate req.genispace; operators decide auth requirements
      if (apiKey) {
        try {
          logger.debug('Validating API key', {
            path: req.path,
            apiKeyPrefix: apiKey.substring(0, 8) + '...',
            baseUrl: config.genispace?.auth?.baseUrl,
            timeout: config.genispace?.auth?.timeout
          });

          let authResult = getCache(apiKey);
          
          if (!authResult) {
            authResult = await validateApiKey(apiKey);
            
            if (authResult && authResult.success) {
              setCache(apiKey, authResult);
              logger.debug('API key validation succeeded', {
                path: req.path,
                userId: authResult.user?.id
              });
            } else {
              logger.warn('API key validation failed', {
                path: req.path,
                apiKeyPrefix: apiKey.substring(0, 8) + '...',
                error: authResult?.error || 'unknown error',
                baseUrl: config.genispace?.auth?.baseUrl
              });
            }
          } else {
            logger.debug('Using cached API key validation result', {
              path: req.path,
              userId: authResult.user?.id
            });
          }

          if (authResult && authResult.success) {
            req.genispace = {
              user: authResult.user,
              client: authResult.client,
              apiKey: apiKey,
              keyInfo: authResult.keyInfo
            };
            logger.debug('req.genispace set', {
              path: req.path,
              hasClient: !!req.genispace.client,
              userId: req.genispace.user?.id
            });
          } else {
            logger.warn('req.genispace not set; validation failed', {
              path: req.path,
              hasAuthResult: !!authResult,
              authSuccess: authResult?.success,
              error: authResult?.error
            });
          }
        } catch (error) {
          // Log but continue: let the operator respond with 401 if checkAuth() fails
          logger.error('API key validation error', {
            path: req.path,
            error: error.message,
            stack: error.stack,
            baseUrl: config.genispace?.auth?.baseUrl
          });
        }
      } else {
        logger.debug('No API key in request', {
          path: req.path,
          headers: Object.keys(req.headers).filter(h => {
            const lower = h.toLowerCase();
            return lower.includes('genispace') || lower.includes('authorization');
          })
        });
      }

      next();

    } catch (error) {
      // Should be rare: respond 500 without throwing further
      logger.error('Auth middleware error', {
        error: error ? (error.message || String(error)) : 'Unknown error',
        endpoint: req.path,
        stack: error ? error.stack : 'No stack trace'
      });
      
      return res.status(500).json({
        success: false,
        error: 'Authentication service error'
      });
    }
  };
}

module.exports = {
  auth,
  extractApiKey,
  validateApiKey,
  validateApiKeyViaSDK
};
