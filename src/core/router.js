/**
 * Route builder: mounts operator routers on Express.
 */

const logger = require('../utils/logger');

class RouterBuilder {
  constructor(config = {}) {
    this.config = config;
    this.apiPrefix = config.apiPrefix || '/api';
    // Reuse timing/logging wrapper per operator (keyed by name + version)
    this.handlerCache = new Map();
    this.stats = {
      routesCount: 0,
      operatorsCount: 0,
      errors: 0
    };
  }

  /**
   * @param {object} app
   * @param {OperatorRegistry} registry
   */
  /** Mount every registered operator router on the Express app. */
  applyRoutes(app, registry) {
    const operators = registry.getAll();

    logger.info(`Applying routes for ${operators.length} operator(s)`);

    operators.forEach(operatorData => {
      this._registerOperatorRoutes(app, operatorData, registry);
    });

    logger.info(`Routes registered: ${this.stats.routesCount} total`);
  }

  _registerOperatorRoutes(app, operatorData, registry) {
    try {
      const { config, metadata } = operatorData;
      const routes = registry.getRoutes(metadata.id);

      if (!routes) {
        logger.warn(`Operator routes not found: ${config.info.name}`);
        return;
      }

      const basePath = `${this.apiPrefix}/${config.info.category}/${config.info.name}`;

      app.use(basePath, this._wrapRouter(routes, config));

      this.stats.routesCount++;
      this.stats.operatorsCount++;

      logger.debug(`Operator routes registered: ${config.info.name}`, {
        basePath,
        category: config.info.category
      });
    } catch (error) {
      this.stats.errors++;
      logger.error(`Operator route registration failed: ${operatorData.config?.info?.name}`, {
        error: error.message
      });
    }
  }

  _wrapRouter(router, config) {
    const cacheKey = `${config.info.name}-${config.info.version}`;
    if (this.handlerCache.has(cacheKey)) {
      return this.handlerCache.get(cacheKey);
    }

    // Per-request: attach operator info; on finish log duration when log level is debug
    router.use((req, res, next) => {
      const startTime = process.hrtime.bigint();
      req.operatorInfo = config.info;

      res.on('finish', () => {
        const duration = Number(process.hrtime.bigint() - startTime) / 1000000; // ns -> ms

        if (logger.level === 'debug') {
          logger.debug(`Operator request finished: ${config.info.name}`, {
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            duration: `${duration.toFixed(2)}ms`
          });
        }
      });

      next();
    });

    this.handlerCache.set(cacheKey, router);
    return router;
  }

  getStats() {
    return { ...this.stats };
  }

  clearCache() {
    this.handlerCache.clear();
    logger.debug('Route handler cache cleared');
  }
}

module.exports = RouterBuilder;
