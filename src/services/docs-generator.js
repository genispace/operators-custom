/**
 * OpenAPI document generator from operator registry.
 */

const logger = require('../utils/logger');

class DocumentGenerator {
  constructor(config = {}) {
    this.config = config;
    this.apiPrefix = config.apiPrefix || '/api';
    this.baseConfig = {
      openapi: '3.0.0',
      info: {
        title: 'GeniSpace Custom Operators API',
        version: '1.0.0',
        description: 'GeniSpace custom operators collection',
        contact: {
          name: 'genispace.com Dev Team',
          url: 'https://genispace.com',
          email: 'dev@genispace.com'
        },
        license: {
          name: 'MIT',
          url: 'https://opensource.org/licenses/MIT'
        }
      },
      servers: DocumentGenerator._buildOpenApiServers(config)
    };
  }

  /**
   * OpenAPI servers / try-it-out base: prefer PUBLIC_BASE_URL (e.g. K8s ConfigMap).
   * If public URL has a path prefix, server URL uses origin only; paths keep full prefix
   * so Swagger does not double the prefix.
   */
  static _openApiServerUrlFromPublicBase(url) {
    const s = url && String(url).trim();
    const t = s ? s.replace(/\/$/, '') : '';
    if (!t) return t;
    try {
      const p = new URL(t);
      const pathname = (p.pathname || '/').replace(/\/$/, '');
      if (pathname) {
        return `${p.protocol}//${p.host}`;
      }
    } catch (_) {
      /* ignore */
    }
    return t;
  }

  static _buildOpenApiServers(config = {}) {
    const trim = (v) => {
      const s = v && String(v).trim();
      return s ? s.replace(/\/$/, '') : '';
    };

    const explicit =
      trim(config.publicBaseUrl) || trim(process.env.PUBLIC_BASE_URL);
    if (explicit) {
      return [
        {
          url: DocumentGenerator._openApiServerUrlFromPublicBase(explicit),
          description: 'Public service'
        }
      ];
    }

    const operatorsBase = trim(process.env.OPERATORS_BASE_URL);
    if (operatorsBase) {
      return [
        {
          url: DocumentGenerator._openApiServerUrlFromPublicBase(operatorsBase),
          description: 'Public service'
        }
      ];
    }

    let url = '';
    if (typeof config.getBrowserBaseUrl === 'function') {
      url = trim(config.getBrowserBaseUrl());
    } else if (typeof config.getServiceBaseUrl === 'function') {
      url = trim(config.getServiceBaseUrl());
    }
    if (!url) {
      const host =
        (process.env.HOST || 'localhost') === '0.0.0.0'
          ? 'localhost'
          : process.env.HOST || 'localhost';
      const port = process.env.PORT || 8080;
      const protocol = process.env.PROTOCOL || 'http';
      url = `${protocol}://${host}:${port}`;
    }

    const description = /localhost|127\.0\.0\.1/.test(url)
      ? 'Development server'
      : 'Service URL';
    return [{ url, description }];
  }

  /** @returns {object} full OpenAPI spec */
  generate(registry) {
    try {
      const doc = {
        ...this.baseConfig,
        paths: this._generatePaths(registry),
        components: this._generateComponents(registry),
        tags: this._generateTags(registry)
      };
      
      logger.debug('OpenAPI spec generated', {
        operatorsCount: registry.getStats().totalOperators,
        pathsCount: Object.keys(doc.paths).length
      });
      
      return doc;
    } catch (error) {
      logger.error('OpenAPI spec generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Fallback OpenAPI tag name when a path spec omits `tags`.
   * @private
   * @param {string} [category]
   */
  _getTagName(category) {
    return category || 'default';
  }

  /**
   * Merge per-operator `config.openapi.paths` into the global `paths` map.
   * @private
   */
  _generatePaths(registry) {
    const paths = {};
    const operators = registry.getAll();
    
    operators.forEach(operatorData => {
      const { config } = operatorData;
      if (!config.openapi?.paths) {
        return;
      }

      // Each operator may declare OpenAPI path fragments; prefix with /api/{category}/{name}
      Object.entries(config.openapi.paths).forEach(([path, methods]) => {
        const basePath = `${this.apiPrefix}/${config.info.category}/${config.info.name}`;
        const fullPath = basePath + path;
        
        if (!paths[fullPath]) {
          paths[fullPath] = {};
        }
        
        Object.entries(methods).forEach(([method, spec]) => {
          paths[fullPath][method] = {
            ...spec,
            tags: spec.tags || [this._getTagName(config.info.category)],
            operationId: spec.operationId || `${config.info.name}_${method}_${path.replace(/[\/\{\}]/g, '_')}`
          };
        });
      });
    });
    
    return paths;
  }

  /**
   * Base `components` object plus shallow merge of operator-provided schemas/responses.
   * @private
   */
  _generateComponents(registry) {
    const components = {
      securitySchemes: {
        GeniSpaceAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'Authorization',
          description: 'GeniSpace API key. Format: GeniSpace <your-api-key>'
        }
      },
      schemas: {
        // Minimal shared envelopes; operators may add more under openapi.components
        SuccessResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: true },
            data: { type: 'object' },
            timestamp: { type: 'string', format: 'date-time' }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            success: { type: 'boolean', example: false },
            error: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' }
          }
        }
      },
      responses: {
        BadRequest: {
          description: 'Bad request',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        },
        InternalServerError: {
          description: 'Internal server error',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' }
            }
          }
        },
        Unauthorized: {
          description: 'GeniSpace API key authentication failed',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' },
              example: {
                success: false,
                error: 'Missing GeniSpace API key',
                code: 'MISSING_GENISPACE_API_KEY',
                message: 'Provide a GeniSpace API key in the Authorization header: Authorization: GeniSpace <your-api-key>',
                timestamp: '2025-01-01T12:00:00.000Z'
              }
            }
          }
        }
      }
    };

    // Layer operator-specific schemas/responses on top of the defaults above
    const operators = registry.getAll();
    operators.forEach(operatorData => {
      const { config } = operatorData;
      if (config.openapi?.components) {
        if (config.openapi.components.schemas) {
          Object.assign(components.schemas, config.openapi.components.schemas);
        }
        if (config.openapi.components.responses) {
          Object.assign(components.responses, config.openapi.components.responses);
        }
      }
    });

    return components;
  }

  /**
   * Build Swagger `tags` from operator titles/descriptions (one entry per loaded operator).
   * @private
   */
  _generateTags(registry) {
    const operators = registry.getAll();
    
    return operators.map(operatorData => {
      const { config } = operatorData;
      const info = config.info;
      
      return {
        name: info.title || info.name,
        description: info.description || `${info.title || info.name} operator`
      };
    });
  }

}

module.exports = DocumentGenerator;