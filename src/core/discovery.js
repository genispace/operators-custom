/**
 * Operator discovery
 *
 * Scans the filesystem and loads operator modules.
 */

const fs = require('fs').promises;
const path = require('path');
const logger = require('../utils/logger');
const { deriveOpenApiFromConfig } = require('../utils/derive-openapi-from-methods');
const { operatorMethods } = require('../utils/operator-definition');

class OperatorDiscovery {
  constructor(options = {}) {
    this.options = {
      operatorPattern: '*.operator.js',
      excludePatterns: ['node_modules', '.git', 'test', '__test__'],
      ...options
    };
    this.discovered = new Set();
  }

  /**
   * @param {string} directory
   * @returns {Array}
   */
  async scan(directory) {
    try {
      // Resolve to an absolute path before walking the tree
      const absoluteDir = path.isAbsolute(directory) ? directory : path.resolve(process.cwd(), directory);
      logger.info(`Scanning operators directory: ${absoluteDir}`);

      await this._checkDirectory(absoluteDir);

      const operators = [];
      await this._scanRecursive(absoluteDir, operators);

      logger.info(`Discovery complete: ${operators.length} operator(s)`);
      return operators;
    } catch (error) {
      logger.error(`Operator discovery failed: ${directory}`, { error: error.message });
      throw error;
    }
  }

  /**
   * @param {string} filePath
   * @returns {object|null}
   */
  async loadOperator(filePath) {
    try {
      if (this.discovered.has(filePath)) {
        logger.debug(`Skipping already loaded operator: ${filePath}`);
        return null;
      }

      const resolvedPath = path.isAbsolute(filePath) ? filePath : require.resolve(filePath);
      // Clear module cache so file changes are picked up on reload
      if (require.cache[resolvedPath]) {
        delete require.cache[resolvedPath];
      }

      const operatorConfig = require(filePath);
      const category = this._extractCategory(filePath);

      // Require info, routes, and a non-empty methods list (see operator-definition)
      if (!this._validateOperatorConfig(operatorConfig)) {
        logger.error(`Invalid operator config: ${filePath}`);
        return null;
      }

      try {
        operatorConfig.openapi = deriveOpenApiFromConfig(operatorConfig);
      } catch (err) {
        logger.error(`OpenAPI derivation failed: ${filePath}`, { error: err.message });
        return null;
      }

      // Default category from operators/{category}/... layout when omitted
      if (!operatorConfig.info?.category && category) {
        operatorConfig.info = { ...operatorConfig.info, category };
      }

      // routes field is a path relative to the operator module directory
      const routesPath = path.resolve(path.dirname(filePath), operatorConfig.routes);
      let routes = null;

      try {
        if (require.cache[routesPath]) {
          delete require.cache[routesPath];
        }
        routes = require(routesPath);
      } catch (error) {
        logger.error(`Failed to load routes file: ${routesPath}`, { error: error.message });
        return null;
      }

      this.discovered.add(filePath);

      logger.debug(`Operator loaded: ${operatorConfig.info?.name}`, {
        file: path.basename(filePath),
        routes: operatorConfig.routes,
        category
      });

      return {
        config: operatorConfig,
        routes,
        metadata: {
          filePath,
          routesPath,
          category,
          fileName: path.basename(filePath)
        }
      };
    } catch (error) {
      logger.error(`Operator load failed: ${filePath}`, { error: error.message });
      return null;
    }
  }

  reset() {
    this.discovered.clear();
  }

  async _checkDirectory(directory) {
    try {
      await fs.access(directory);
    } catch {
      throw new Error(`Operators directory does not exist: ${directory}`);
    }
  }

  /** Depth-first walk; only files matching *.operator.js are loaded. */
  async _scanRecursive(directory, operators, category = '') {
    const entries = await fs.readdir(directory, { withFileTypes: true });

    for (const entry of entries) {
      if (this._shouldExclude(entry.name)) {
        continue;
      }

      const fullPath = path.isAbsolute(directory)
        ? path.join(directory, entry.name)
        : path.resolve(directory, entry.name);

      if (entry.isDirectory()) {
        const subCategory = category ? `${category}/${entry.name}` : entry.name;
        await this._scanRecursive(fullPath, operators, subCategory);
      } else if (this._isOperatorFile(entry.name)) {
        const result = await this.loadOperator(fullPath);
        if (result) {
          operators.push(result);
        }
      }
    }
  }

  _shouldExclude(name) {
    return this.options.excludePatterns.some(pattern =>
      name.includes(pattern) || name.startsWith('.')
    );
  }

  _isOperatorFile(fileName) {
    return fileName.endsWith('.operator.js');
  }

  /** Derive category from operators/<category>/.../name.operator.js when possible. */
  _extractCategory(filePath) {
    const relativePath = path.relative(process.cwd(), filePath);
    const segments = relativePath.split(path.sep);

    if (segments.length >= 3 && segments[0] === 'operators') {
      return segments[1];
    }

    return '';
  }

  _validateOperatorConfig(config) {
    if (!config || typeof config !== 'object') {
      return false;
    }

    if (!config.info || !config.info.name) {
      return false;
    }

    if (!config.routes || typeof config.routes !== 'string') {
      return false;
    }

    const methods = operatorMethods(config);
    if (methods.length === 0) {
      return false;
    }

    for (const m of methods) {
      if (!m || typeof m !== 'object') {
        return false;
      }
      if (!m.identifier || typeof m.identifier !== 'string') {
        return false;
      }
      if (!m.name || typeof m.name !== 'string') {
        return false;
      }
      if (!m.path || typeof m.path !== 'string') {
        return false;
      }
    }

    return true;
  }
}

module.exports = OperatorDiscovery;
