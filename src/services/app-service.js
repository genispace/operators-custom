/**
 * Application service orchestration
 *
 * Coordinates core components for the operator platform.
 */

// const swaggerJsDoc = require('swagger-jsdoc'); // unused; custom docs generator instead
const OperatorRegistry = require('../core/registry');
const OperatorDiscovery = require('../core/discovery');
const RouterBuilder = require('../core/router');
const DocumentGenerator = require('./docs-generator');
const logger = require('../utils/logger');
const { operatorMethods, chatPluginByMethodMap } = require('../utils/operator-definition');
const { playgroundNeedsGeniSpaceKey } = require('../utils/operator-auth');

class ApplicationService {
  constructor(config = {}) {
    this.config = config;
    this.registry = new OperatorRegistry();
    this.discovery = new OperatorDiscovery();
    this.router = new RouterBuilder(config);
    this.docsGenerator = new DocumentGenerator(config);
    this.initialized = false;
  }

  /**
   * Initialize application service
   * @param {string} operatorsDir
   */
  async initialize(operatorsDir) {
    try {
      logger.info('Initializing application service...');

      await this._loadOperators(operatorsDir);

      // Merge registry into one OpenAPI document for /docs and /docs.json
      this._generateDocs();

      this.initialized = true;
      logger.info('Application service initialized');

    } catch (error) {
      logger.error('Application service initialization failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Mount on Express app
   * @param {object} app
   */
  applyTo(app) {
    if (!this.initialized) {
      throw new Error('Application service not initialized; call initialize() first');
    }

    // Each operator Express router under /api/{category}/{operatorName}
    this.router.applyRoutes(app, this.registry);
    return this;
  }

  /**
   * @returns {object} OpenAPI / Swagger spec
   */
  getSwaggerSpec() {
    return this.swaggerSpec;
  }

  /**
   * @returns {object} stats
   */
  getStats() {
    const registryStats = this.registry.getStats();
    const routerStats = this.router.getStats();
    
    return {
      ...registryStats,
      ...routerStats,
      initialized: this.initialized
    };
  }

  /**
   * @returns {Array} operators
   */
  getOperators() {
    return this.registry.getAll().map(operatorData => {
      const { config, metadata } = operatorData;
      const pathSet = new Set(
        operatorMethods(config).map((m) =>
          m.path && String(m.path).startsWith('/') ? m.path : `/${m.path || ''}`
        )
      );
      const endpoints = [...pathSet];
      
      return {
        id: metadata.id,
        name: config.info.name,
        title: config.info.title,
        description: config.info.description,
        version: config.info.version,
        category: config.info.category,
        endpoints: endpoints.map(path => `${this.config.apiPrefix || '/api'}/${config.info.category}/${config.info.name}${path}`),
        endpointCount: endpoints.length,
        registeredAt: metadata.registeredAt
      };
    });
  }

  /**
   * @param {string} category
   * @returns {Array}
   */
  getOperatorsByCategory(category) {
    return this.getOperators().filter(op => op.category === category);
  }

  /**
   * @param {string} operatorId
   * @param {object|null} req for base URL
   * @returns {object|null}
   */
  getOperatorDefinition(operatorId, req = null) {
    const operatorData = this.registry.get(operatorId);
    if (!operatorData) {
      return null;
    }

    const { config, metadata } = operatorData;
    const fileMetadata =
      config.metadata && typeof config.metadata === 'object' ? { ...config.metadata } : {};

    // Base URL from request; behind gateway without X-Forwarded-Proto, req.secure may be wrong
    let baseUrl = '';
    if (req) {
      const protocol = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
      const host = req.headers['x-forwarded-host'] || req.headers.host || `${process.env.HOST || 'localhost'}:${process.env.PORT || 8080}`;
      baseUrl = `${protocol}://${host}`;
    }

    const explicitGenispaceApiBase = process.env.GENISPACE_API_BASE_URL && String(process.env.GENISPACE_API_BASE_URL).trim();
    const serverUrlDefault = explicitGenispaceApiBase
      ? explicitGenispaceApiBase.replace(/\/$/, '')
      : baseUrl;

    const defaultSystemConfiguration = {
      schema: {
        type: 'api',
        properties: {
          serverUrl: {
            type: 'string',
            title: 'Server URL',
            required: true,
            description: 'Base URL of the API server',
            default: serverUrlDefault
          },
          timeout: {
            type: 'number',
            title: 'Global timeout',
            default: 30000,
            description: 'Request timeout in milliseconds'
          },
          headers: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                key: { type: 'string' },
                value: { type: 'string' }
              }
            },
            title: 'Global headers',
            description: 'HTTP headers applied to every request'
          },
          retryPolicy: {
            type: 'object',
            title: 'Global retry policy',
            properties: {
              intervalMs: {
                type: 'number',
                title: 'Retry interval (ms)',
                default: 1000
              },
              maxAttempts: {
                type: 'number',
                title: 'Max retry attempts',
                default: 3
              }
            }
          }
        }
      }
    };
    const customUserConfiguration =
      config.configuration && typeof config.configuration === 'object'
        ? config.configuration
        : { schema: { type: 'object', properties: {} }, values: {} };

    // GeniSpace operator definition shape
    return {
      type: 'genispace-operator',
      version: '1.0.0',
      operator: {
        identifier: config.info.name,
        name: config.info.title,
        description: config.info.description,
        version: config.info.version,
        category: config.info.category,
        tags: config.info.tags || [],
        author: config.info.author || 'genispace.com Dev Team',
        
        // User-level config from operator file root `configuration`
        configuration: {
          schema: customUserConfiguration.schema || { type: 'object', properties: {} },
          values: customUserConfiguration.values || {}
        },
        // System-level API runtime config (base URL, headers, timeout)
        systemConfiguration: defaultSystemConfiguration,

        // Methods from root `methods`; merge chatPluginByMethod → chatPluginConfig
        methods: this._mergeChatPluginConfigs(
          this._buildMethodsFromDefinition(config),
          config,
          this._resolvePublicBaseUrl(baseUrl)
        ),
        
        // Metadata: export audit fields first, then merge file metadata (e.g. locales.zh)
        metadata: {
          source: 'genispace-internal-operators',
          exportedAt: new Date().toISOString(),
          exportedBy: 'GeniSpace Custom Operators API',
          originalOperatorId: operatorId,
          registeredAt: metadata.registeredAt,
          ...fileMetadata
        }
      }
    };
  }

  /**
   * Playground: registered operators with inputSchema, endpoint, chatPluginConfig
   * @param {object|null} req for public host
   * @returns {Array<object>}
   */
  getPlaygroundRegistry(req = null) {
    if (!this.initialized) {
      throw new Error('Application service not initialized; call initialize() first');
    }

    return this.registry.getAll()
      .map(({ config, metadata }) => {
        const def = this.getOperatorDefinition(metadata.id, req);
        if (!def?.operator) {
          return null;
        }
        const op = def.operator;
        const locales = config.metadata?.locales;
        const needsGeniSpaceKey = playgroundNeedsGeniSpaceKey(config);
        return {
          id: metadata.id,
          identifier: op.identifier,
          name: op.name,
          category: op.category,
          description: op.description,
          metadata: locales ? { locales } : undefined,
          methods: (op.methods || []).map((m) => ({
            identifier: m.identifier,
            name: m.name,
            description: m.description,
            inputSchema: m.inputSchema,
            endpoint: m.configuration?.values?.endpoint,
            httpMethod: m.configuration?.values?.method,
            chatPluginConfig: m.chatPluginConfig || null,
            needsGeniSpaceKey
          }))
        };
      })
      .filter(Boolean);
  }

  /**
   * Public origin for pluginUrl (no trailing slash)
   * @param {string} reqBaseUrl
   * @returns {string}
   */
  _resolvePublicBaseUrl(reqBaseUrl) {
    const explicit = process.env.PUBLIC_BASE_URL || this.config.publicBaseUrl;
    const trim = (v) => (v && String(v).trim()) || '';
    const raw = trim(explicit) || trim(reqBaseUrl)
      || (typeof this.config.getServiceBaseUrl === 'function' ? this.config.getServiceBaseUrl() : '');
    return raw.replace(/\/$/, '');
  }

  /**
   * Build platform methods from operator methods[] (root or legacy genispace.methods)
   * @param {object} config
   * @returns {Array<object>}
   */
  _buildMethodsFromDefinition(config) {
    const apiPrefix = this.config.apiPrefix || '/api';
    const info = config.info || {};
    const operatorName = info.name;
    const category = info.category;
    const raw = operatorMethods(config);

    return raw.map((m, index) => {
      const path = m.path && String(m.path).startsWith('/') ? m.path : `/${m.path || ''}`;
      const httpMethod = String(m.httpMethod || 'POST').toUpperCase();
      const endpoint = `${apiPrefix}/${category}/${operatorName}${path}`;
      const inputSchema =
        m.inputSchema !== undefined ? m.inputSchema : { type: 'object', properties: {} };
      const outputSchema =
        m.outputSchema !== undefined ? m.outputSchema : { type: 'object', properties: {} };

      return {
        name: m.name,
        identifier: m.identifier,
        description: m.description != null ? m.description : '',
        inputSchema,
        outputSchema,
        configuration: {
          schema: {
            type: 'object',
            properties: {
              method: {
                type: 'string',
                enum: [httpMethod],
                default: httpMethod
              },
              endpoint: {
                type: 'string',
                default: endpoint
              },
              headers: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    key: { type: 'string' },
                    value: { type: 'string' }
                  }
                },
                title: 'Headers',
                default: []
              },
              caching: {
                type: 'object',
                properties: {
                  enabled: { type: 'boolean', default: false },
                  ttlSeconds: { type: 'number', default: 3600 }
                }
              }
            }
          },
          values: {
            method: httpMethod,
            endpoint,
            headers: [],
            caching: {
              enabled: false,
              ttlSeconds: 3600
            }
          }
        },
        isDefault: index === 0,
        order: index,
        status: 'ACTIVE'
      };
    });
  }

  /**
   * Merge chatPluginByMethod into exported method chatPluginConfig
   * @param {Array} methods from _buildMethodsFromDefinition
   * @param {object} operatorConfig module.exports
   * @param {string} publicBase public service root URL
   * @returns {Array}
   */
  _mergeChatPluginConfigs(methods, operatorConfig, publicBase) {
    const byMethod = chatPluginByMethodMap(operatorConfig);
    if (!methods || !Array.isArray(methods)) {
      return [];
    }

    return methods.map((m) => {
      const spec = byMethod[m.identifier];
      if (!spec || spec.enabled !== true) {
        return m;
      }

      let pluginUrl = spec.pluginUrl;
      if (!pluginUrl && spec.pluginPath) {
        const p = String(spec.pluginPath).startsWith('/') ? spec.pluginPath : `/${spec.pluginPath}`;
        pluginUrl = publicBase ? `${publicBase}${p}` : p;
      }
      if (pluginUrl && !String(pluginUrl).endsWith('/')) {
        pluginUrl = `${pluginUrl}/`;
      }

      const extra = spec.extra && typeof spec.extra === 'object' ? spec.extra : {};
      const chatPluginConfig = {
        enabled: true,
        pluginId: spec.pluginId,
        pluginUrl,
        ...extra
      };

      return { ...m, chatPluginConfig };
    });
  }

  /**
   * @param {string} operatorsDir
   */
  async reload(operatorsDir) {
    logger.info('Reloading operators...');

    this.registry.clear();
    this.discovery.reset();
    
    await this.initialize(operatorsDir);

    logger.info('Operators reloaded');
  }

  /**
   * @private
   */
  async _loadOperators(operatorsDir) {
    const discovered = await this.discovery.scan(operatorsDir);
    
    let successCount = 0;
    let errorCount = 0;
    
    for (const operatorData of discovered) {
      try {
        if (operatorData) {
          this.registry.register(operatorData);
          successCount++;
        } else {
          errorCount++;
        }
      } catch (error) {
        errorCount++;
        logger.error(`Operator registration failed: ${operatorData?.config?.info?.name || 'unknown'}`, {
          error: error.message
        });
      }
    }
    
    logger.info(`Operators loaded: ${successCount} succeeded, ${errorCount} failed`);

    if (successCount === 0) {
      logger.warn('No operators loaded successfully');
    }
  }

  /**
   * @private
   */
  _generateDocs() {
    this.swaggerSpec = this.docsGenerator.generate(this.registry);

    logger.debug('OpenAPI spec generated');
  }
}

module.exports = ApplicationService;
