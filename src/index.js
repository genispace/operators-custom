/**
 * GeniSpace Custom Operators API Server
 *
 * Lightweight custom operator component library for the GeniSpace AI platform.
 * Clear layered architecture after refactor.
 *
 * @copyright © 2025 genispace.com Dev Team
 * @license MIT
 */

const express = require('express');
const swaggerUi = require('swagger-ui-express');
const path = require('path');
const { execSync } = require('child_process');

// Load `.env` into process.env before reading config
require('dotenv').config();

const config = require('./config/env');
const ApplicationService = require('./services/app-service');
const { setupMiddlewares } = require('./middleware');
const { setupRoutes } = require('./routes');
const logger = require('./utils/logger');

const app = express();

// Chat plugin assets: mount after setupMiddlewares so CORS applies (dev playground fetches manifest/JS cross-origin).
const publicPluginsPath = path.join(__dirname, '../public/plugins');

// Coordinates discovery, registry, OpenAPI merge, and route application
const appService = new ApplicationService(config);

/** Strip ingress path prefix (e.g. /operators/internal) so /api and /health match internally. */
function mountIngressStripPrefix(expressApp, rawPrefix) {
  const trimmed = rawPrefix && String(rawPrefix).trim();
  if (!trimmed) return;
  const prefix = trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
  expressApp.use((req, res, next) => {
    const pathOnly = req.path;
    if (pathOnly === prefix || pathOnly.startsWith(`${prefix}/`)) {
      const rest = pathOnly.slice(prefix.length) || '/';
      const q = req.url.indexOf('?');
      const qs = q >= 0 ? req.url.slice(q) : '';
      req.url = rest + qs;
    }
    next();
  });
  logger.info(`Ingress strip prefix: ${prefix}`);
}

async function startApp() {
  try {
    logger.info('🚀 Starting GeniSpace Custom Operators API...');

    mountIngressStripPrefix(app, config.ingressStripPrefix);

    if (config.security.trustProxy) {
      app.set('trust proxy', true);
    }

    // CORS, JSON/body limits, logging, auth, rate limiting, etc.
    setupMiddlewares(app, config);

    // Dev: public/plugins is gitignored; nodemon restarts skip npm pre scripts — sync operators/**/plugin on boot.
    if (config.isDevelopment) {
      const repoRoot = path.join(__dirname, '..');
      try {
        execSync('node scripts/build-plugins.js', { cwd: repoRoot, stdio: 'pipe' });
        logger.debug('Dev: synced Chat plugins -> public/plugins');
      } catch (err) {
        const detail = err.stderr ? String(err.stderr) : err.message;
        logger.warn('Dev: build-plugins failed; manifests under /static/plugins may 404', { error: detail });
      }
    }

    // Static hosting for built plugin bundles (also under apiPrefix when gateway forwards full path)
    app.use('/static/plugins', express.static(publicPluginsPath, { fallthrough: true }));
    const apiPx = (config.apiPrefix && String(config.apiPrefix).replace(/\/$/, '')) || '';
    if (apiPx) {
      app.use(`${apiPx}/static/plugins`, express.static(publicPluginsPath, { fallthrough: true }));
    }

    const operatorsDir = path.join(__dirname, '../operators');
    await appService.initialize(operatorsDir);

    // System routes: home, health, operator listing, etc.
    setupRoutes(app, appService, config);

    // Per-operator Express routers under /api/{category}/{operator}
    appService.applyTo(app);

    setupApiDocs(app, appService, config);

    const { errorHandler, notFoundHandler } = require('./middleware/error');
    // Must be registered after all routes
    app.use(notFoundHandler);
    app.use(errorHandler);

    const server = app.listen(config.port, config.host, () => {
      const stats = appService.getStats();

      logger.info('✅ Server started', {
        port: config.port,
        host: config.host,
        environment: config.env,
        nodeVersion: process.version,
        operators: stats.totalOperators,
        endpoints: stats.totalEndpoints
      });

      const publicRouteBase = config.getPublicRouteBaseUrl();
      logger.info(`📚 API docs: ${publicRouteBase}/docs`);
      logger.info(`🔗 OpenAPI schema: ${publicRouteBase}/docs.json`);
      const probeHost = config.host === '0.0.0.0' ? 'localhost' : config.host;
      logger.info(`🏥 Health: http://${probeHost}:${config.port}/health`);
    });

    // SIGTERM/SIGINT and uncaught exception handlers
    setupGracefulShutdown(server);

    return { app, server, appService };
  } catch (error) {
    logger.error('❌ Server failed to start', { error: error.stack });
    process.exit(1);
  }
}

function setupApiDocs(app, appService, config) {
  const swaggerSpec = appService.getSwaggerSpec();
  const apiPrefix = config.apiPrefix || '/api';

  // Interactive OpenAPI browser
  app.use(`${apiPrefix}/docs`, swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'GeniSpace Custom Operators API',
    swaggerOptions: {
      docExpansion: 'list',
      filter: true,
      showRequestHeaders: true,
      tryItOutEnabled: true
    }
  }));

  // Raw OpenAPI document for codegen and external tools
  app.get(`${apiPrefix}/docs.json`, (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.json(swaggerSpec);
  });
}

/** Graceful HTTP shutdown and fatal process error logging. */
function setupGracefulShutdown(server) {
  let shutdownStarted = false;
  const SHUTDOWN_FORCE_MS = 8000;

  const gracefulShutdown = (signal) => {
    if (shutdownStarted) {
      logger.info(`Received ${signal} again, forcing exit`);
      process.exit(0);
      return;
    }
    shutdownStarted = true;
    logger.info(`Received ${signal}, shutting down gracefully...`);

    const t = setTimeout(() => {
      logger.warn('Shutdown timeout (open connections); forcing exit');
      process.exit(0);
    }, SHUTDOWN_FORCE_MS);
    t.unref();

    // Without this, browser keep-alive sockets keep server.close() from finishing.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections();
    } else if (typeof server.closeIdleConnections === 'function') {
      server.closeIdleConnections();
    }

    server.close(() => {
      clearTimeout(t);
      logger.info('HTTP server closed');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  process.on('uncaughtException', (error) => {
    logger.error('Uncaught exception', { error: error.stack });
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled promise rejection', {
      reason,
      promise
    });
    process.exit(1);
  });
}

// When executed directly (`node src/index.js`), boot the server
if (require.main === module) {
  startApp();
}

module.exports = { app, startApp, appService };
