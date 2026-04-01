/**
 * Operator registry: registration, lookup, and lifecycle.
 * Config and routes are separate per operator.
 */

const logger = require('../utils/logger');
const { operatorMethods } = require('../utils/operator-definition');
const { deriveOpenApiFromConfig } = require('../utils/derive-openapi-from-methods');

class OperatorRegistry {
  constructor() {
    // Primary indexes
    this.operators = new Map();
    this.endpoints = new Map();
    this.categories = new Set();
    this.routes = new Map();

    // Derived caches (invalidated on register/clear)
    this.categoryIndex = new Map();
    this.operatorList = null;

    this.stats = {
      totalOperators: 0,
      totalEndpoints: 0,
      totalCategories: 0,
      loadErrors: 0
    };
  }

  /**
   * @param {object} operatorData { config, routes, metadata }
   * @returns {string} operatorId
   */
  register(operatorData) {
    try {
      const { config, routes, metadata } = operatorData;

      if (!config.openapi?.paths && operatorMethods(config).length > 0) {
        config.openapi = deriveOpenApiFromConfig(config);
      }

      this._validateOperatorConfig(config);

      const operatorId = this._generateId(config.info.name, config.info.category);

      // Store config + Express router separately for fast lookup
      this.operators.set(operatorId, {
        config,
        metadata: {
          ...metadata,
          registeredAt: new Date().toISOString(),
          id: operatorId
        }
      });

      this.routes.set(operatorId, routes);

      if (config.info.category) {
        this.categories.add(config.info.category);
      }

      // Flatten openapi.paths into an endpoint map for metrics and introspection
      this._registerOpenAPIEndpoints(config, operatorId);

      this._updateStats();
      this._invalidateCache();

      logger.debug(`Operator registered: ${config.info.name}`, {
        id: operatorId,
        category: config.info.category,
        paths: Object.keys(config.openapi?.paths || {}).length
      });

      return operatorId;
    } catch (error) {
      this.stats.loadErrors++;
      logger.error(`Operator registration failed: ${config?.info?.name || 'unknown'}`, {
        error: error.message
      });
      throw error;
    }
  }

  get(operatorId) {
    return this.operators.get(operatorId) || null;
  }

  getRoutes(operatorId) {
    return this.routes.get(operatorId) || null;
  }

  getAll() {
    if (this.operatorList) {
      return this.operatorList;
    }

    // Snapshot cached until the registry mutates
    this.operatorList = Array.from(this.operators.values());
    return this.operatorList;
  }

  getByCategory(category) {
    if (this.categoryIndex.has(category)) {
      return this.categoryIndex.get(category);
    }

    const operators = this.getAll().filter(op => op.config.info.category === category);
    this.categoryIndex.set(category, operators);
    return operators;
  }

  getEndpoints() {
    return this.endpoints;
  }

  getStats() {
    return {
      ...this.stats,
      categories: Array.from(this.categories)
    };
  }

  clear() {
    this.operators.clear();
    this.endpoints.clear();
    this.categories.clear();
    this.routes.clear();
    this._invalidateCache();
    this._updateStats();

    logger.debug('Operator registry cleared');
  }

  _validateOperatorConfig(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('Operator config must be an object');
    }

    if (!config.info || !config.info.name) {
      throw new Error('Operator must have info.name');
    }

    if (!config.openapi || !config.openapi.paths) {
      throw new Error('Operator must define openapi.paths');
    }
  }

  _generateId(name, category = 'default') {
    return `${category}/${name}`;
  }

  _registerOpenAPIEndpoints(config, operatorId) {
    if (!config.openapi?.paths) return;

    Object.entries(config.openapi.paths).forEach(([path, methods]) => {
      Object.entries(methods).forEach(([method, spec]) => {
        const endpointKey = `${operatorId}:${path}:${method.toUpperCase()}`;
        this.endpoints.set(endpointKey, {
          operatorId,
          operatorName: config.info.name,
          path,
          method: method.toUpperCase(),
          spec,
          category: config.info.category
        });
      });
    });
  }

  _updateStats() {
    this.stats.totalOperators = this.operators.size;
    this.stats.totalEndpoints = this.endpoints.size;
    this.stats.totalCategories = this.categories.size;
  }

  _invalidateCache() {
    this.categoryIndex.clear();
    this.operatorList = null;
  }
}

module.exports = OperatorRegistry;
