/**
 * Environment and runtime configuration (central place for env-derived settings).
 */

const path = require('path');

const config = {
  // Server
  port: parseInt(process.env.PORT) || 8080,
  host: process.env.HOST || '0.0.0.0',
  
  // Environment
  env: process.env.NODE_ENV || 'development',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
  isProduction: process.env.NODE_ENV === 'production',
  
  // API
  apiPrefix: process.env.API_PREFIX || '/api',
  
  // CORS: comma-separated allowlist; if the value is exactly "*", keep the string "*"
  // (splitting "*," would turn production CORS_ORIGIN=* into a broken list)
  corsOrigin: (() => {
    const raw = process.env.CORS_ORIGIN;
    if (!raw || !String(raw).trim()) return '*';
    const parts = String(raw)
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);
    if (parts.length === 1 && parts[0] === '*') return '*';
    return parts;
  })(),
  
  // Request limits
  maxRequestSize: process.env.MAX_REQUEST_SIZE || '10mb',
  requestTimeout: parseInt(process.env.REQUEST_TIMEOUT) || 30000,

  // Rate limiting (express-rate-limit)
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // default 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // max requests per window per IP
    skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESS === 'true'
  },

  // Logging
  log: {
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    console: process.env.LOG_CONSOLE !== 'false' // default: log to console
  },

  // Operator discovery and caching
  operators: {
    directory: process.env.OPERATORS_DIR || path.join(process.cwd(), 'operators'),
    cacheEnabled: process.env.OPERATORS_CACHE_ENABLED !== 'false',
    cacheTTL: parseInt(process.env.OPERATORS_CACHE_TTL) || 3600, // seconds; default 1 hour
    autoReload: process.env.OPERATORS_AUTO_RELOAD === 'true'
  },
  
  // Monitoring
  monitoring: {
    enabled: process.env.MONITORING_ENABLED === 'true',
    metricsPath: process.env.METRICS_PATH || '/metrics',
    healthPath: process.env.HEALTH_PATH || '/health'
  },
  
  // Security
  security: {
    enableCors: process.env.SECURITY_CORS !== 'false',
    enableRateLimit: process.env.SECURITY_RATE_LIMIT !== 'false',
    trustProxy: process.env.TRUST_PROXY === 'true'
  },
  
  /** Public service root for chat remote plugin URLs; falls back to getServiceBaseUrl() */
  publicBaseUrl: process.env.PUBLIC_BASE_URL || null,

  /** Ingress path prefix to strip (e.g. /operators/internal) so /api, /static, /health match */
  ingressStripPrefix: (process.env.INGRESS_STRIP_PREFIX && process.env.INGRESS_STRIP_PREFIX.trim()) || null,

  // GeniSpace API key auth
  genispace: {
    auth: {
      baseUrl: process.env.GENISPACE_API_BASE_URL || 'https://api.genispace.com',
      timeout: parseInt(process.env.GENISPACE_AUTH_TIMEOUT) || 10000,
      cacheTTL: parseInt(process.env.GENISPACE_AUTH_CACHE_TTL) || 300 // seconds; default 5 minutes
    }
  },
  
  // Optional cache (e.g. Redis)
  cache: {
    enabled: process.env.CACHE_ENABLED === 'true',
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB) || 0
    }
  },

  // Reserved for external integrations (databases, third-party APIs, etc.)
  services: {}
};

/**
 * Service base URL (no path).
 * Prefers OPERATORS_BASE_URL when set (often differs from bind address in containers).
 * Otherwise builds from PROTOCOL, HOST, PORT.
 */
function getServiceBaseUrl() {
  if (process.env.OPERATORS_BASE_URL) {
    return process.env.OPERATORS_BASE_URL;
  }

  // Fallback: listen host/port may be 0.0.0.0 — callers that need a public URL should set OPERATORS_BASE_URL
  const protocol = process.env.PROTOCOL || 'http';
  const host = process.env.HOST || 'localhost';
  const port = process.env.PORT || 8080;
  return `${protocol}://${host}:${port}`;
}

/**
 * Replace 0.0.0.0 / [::] hostnames with `localhost` so links work in a desktop browser.
 * @param {string} url
 * @returns {string}
 */
function normalizeServiceUrlForBrowser(url) {
  if (!url || typeof url !== 'string') return url;
  try {
    const u = new URL(url);
    if (u.hostname === '0.0.0.0') u.hostname = 'localhost';
    if (u.hostname === '[::]' || u.hostname === '::') u.hostname = 'localhost';
    const origin =
      u.port && String(u.port) !== ''
        ? `${u.protocol}//${u.hostname}:${u.port}`
        : `${u.protocol}//${u.hostname}`;
    const path = u.pathname === '/' ? '' : u.pathname;
    return `${origin}${path}${u.search}${u.hash}`;
  } catch {
    return url;
  }
}

/**
 * Same source as {@link getServiceBaseUrl}, normalized for browser-friendly hostnames.
 * @returns {string}
 */
function getBrowserBaseUrl() {
  return normalizeServiceUrlForBrowser(getServiceBaseUrl());
}

/**
 * Normalize a path prefix: ensure leading slash, strip trailing slash.
 * @param {string} p
 * @returns {string}
 */
function normalizePathPrefixForCompare(p) {
  const s = (p && String(p).trim()) || '';
  if (!s) return '';
  const withSlash = s.startsWith('/') ? s : `/${s}`;
  return withSlash.replace(/\/$/, '') || '';
}

/**
 * Public URL root for routes like `/docs` and `/operators` (includes `apiPrefix` when needed).
 * If OPERATORS_BASE_URL already ends with the same path as `apiPrefix`, it is not appended twice
 * (prevents `/operators/internal/operators/internal/docs`).
 * @returns {string}
 */
function getPublicRouteBaseUrl() {
  const apiPx = normalizePathPrefixForCompare(config.apiPrefix || '/api');
  const serviceUrl = (getBrowserBaseUrl() || '').replace(/\/$/, '');
  if (!serviceUrl) {
    return apiPx;
  }
  try {
    const u = new URL(serviceUrl);
    const pathname = normalizePathPrefixForCompare(u.pathname || '');
    if (pathname === apiPx) {
      return serviceUrl;
    }
  } catch {
    return `${serviceUrl}${apiPx}`;
  }
  return `${serviceUrl}${apiPx}`;
}

/** @returns {string} API base URL including `apiPrefix` */
function getApiBaseUrl() {
  return getPublicRouteBaseUrl();
}

// Expose URL helpers on the exported config object
config.getServiceBaseUrl = getServiceBaseUrl;
config.getBrowserBaseUrl = getBrowserBaseUrl;
config.getPublicRouteBaseUrl = getPublicRouteBaseUrl;
config.getApiBaseUrl = getApiBaseUrl;

function validateConfig() {
  const required = [];
  
  if (!config.port || config.port < 1 || config.port > 65535) {
    required.push('PORT must be a valid port number (1-65535)');
  }
  
  if (required.length > 0) {
    throw new Error(`Configuration validation failed:\n${required.join('\n')}`);
  }
}

// Fail fast on invalid required settings
try {
  validateConfig();
} catch (error) {
  console.error('Configuration validation failed:', error.message);
  process.exit(1);
}

module.exports = config;
