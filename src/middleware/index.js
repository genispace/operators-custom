/**
 * Central Express middleware stack (security headers, CORS, body parsing, rate limit, logging, auth).
 * Error handlers are attached in `src/index.js` after routes.
 */

const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const express = require('express');

const { requestLogger } = require('./logger');
const logger = require('../utils/logger');

/**
 * @param {import('express').Application} app
 * @param {object} config from `./config/env`
 */
function setupMiddlewares(app, config) {
  logger.debug('Configuring middleware...');

  // 1. Baseline security headers (lightweight; suitable for internal services)
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  // 2. CORS — dev allows all; prod uses config.corsOrigin (string, *, or array from comma-separated env)
  app.use(cors({
    origin: function (origin, callback) {
      // Non-browser clients (curl, mobile) may omit Origin
      if (!origin) return callback(null, true);

      if (config.isDevelopment) {
        return callback(null, true);
      }

      const allowedOrigins = Array.isArray(config.corsOrigin) ? config.corsOrigin : [config.corsOrigin];
      const allowAny =
        config.corsOrigin === '*' || allowedOrigins.includes('*');
      if (allowAny || allowedOrigins.indexOf(origin) !== -1) {
        return callback(null, true);
      }
      
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'GeniSpace', 'X-Requested-With', 'Accept', 'Origin'],
    exposedHeaders: ['Content-Length', 'X-Total-Count']
  }));

  // 3. Compress responses when clients accept encoding
  app.use(compression());

  // 4. JSON / urlencoded bodies (+ raw body on req for optional signature checks)
  app.use(express.json({ 
    limit: config.maxRequestSize,
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  }));

  app.use(express.urlencoded({ 
    extended: true, 
    limit: config.maxRequestSize 
  }));

  // 5. Per-IP rate limiting under apiPrefix
  if (config.security.enableRateLimit) {
    const limiter = createRateLimiter(config.rateLimit);
    const apiPrefix = config.apiPrefix || '/api';
    app.use(`${apiPrefix}/`, limiter);
  }

  // 6. Request / response logging
  app.use(requestLogger);

  // 7. Optional GeniSpace API key validation (populates req.genispace when valid)
  const { auth } = require('./auth');
  app.use(auth());

  logger.debug('Middleware configured');
}

/**
 * express-rate-limit factory with JSON error body consistent with the rest of the API.
 * @param {object} rateLimitConfig
 */
function createRateLimiter(rateLimitConfig) {
  return rateLimit({
    windowMs: rateLimitConfig.windowMs,
    max: rateLimitConfig.max,
    message: {
      success: false,
      error: 'Too many requests, please try again later',
      code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit triggered', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path
      });
      
      res.status(429).json({
        success: false,
        error: 'Too many requests, please try again later',
        code: 'RATE_LIMIT_EXCEEDED',
        timestamp: new Date().toISOString()
      });
    }
  });
}

module.exports = { setupMiddlewares };
