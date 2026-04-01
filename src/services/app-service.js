/**
 * 应用服务编排
 * 
 * 协调各个核心组件，实现算子平台的核心功能
 */

// const swaggerJsDoc = require('swagger-jsdoc'); // 不再需要，直接使用自定义文档生成器
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
   * 初始化应用服务
   * @param {string} operatorsDir - 算子目录
   */
  async initialize(operatorsDir) {
    try {
      logger.info('开始初始化应用服务...');
      
      // 1. 发现和加载算子
      await this._loadOperators(operatorsDir);
      
      // 2. 生成API文档
      this._generateDocs();
      
      this.initialized = true;
      logger.info('应用服务初始化完成');
      
    } catch (error) {
      logger.error('应用服务初始化失败', { error: error.message });
      throw error;
    }
  }

  /**
   * 应用到Express应用
   * @param {object} app - Express应用实例
   */
  applyTo(app) {
    if (!this.initialized) {
      throw new Error('应用服务未初始化，请先调用 initialize()');
    }

    // 构建路由
    this.router.applyRoutes(app, this.registry);
    return this;
  }

  /**
   * 获取Swagger文档
   * @returns {object} Swagger规范
   */
  getSwaggerSpec() {
    return this.swaggerSpec;
  }

  /**
   * 获取统计信息
   * @returns {object} 统计数据
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
   * 获取算子列表
   * @returns {Array} 算子列表
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
   * 按分类获取算子
   * @param {string} category - 分类名称
   * @returns {Array} 算子列表
   */
  getOperatorsByCategory(category) {
    return this.getOperators().filter(op => op.category === category);
  }

  /**
   * 获取单个算子的完整定义
   * @param {string} operatorId - 算子ID
   * @param {object} req - 请求对象（用于构建完整URL）
   * @returns {object|null} 算子定义
   */
  getOperatorDefinition(operatorId, req = null) {
    const operatorData = this.registry.get(operatorId);
    if (!operatorData) {
      return null;
    }

    const { config, metadata } = operatorData;
    const fileMetadata =
      config.metadata && typeof config.metadata === 'object' ? { ...config.metadata } : {};

    // 构建基础URL（如果提供了请求对象）；网关后常见未带 X-Forwarded-Proto，req.secure 为 false 会误判为 http
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
            title: '服务器地址',
            required: true,
            description: 'API 服务器的基础地址',
            default: serverUrlDefault
          },
          timeout: {
            type: 'number',
            title: '全局超时时间',
            default: 30000,
            description: '请求超时时间（毫秒）'
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
            title: '全局请求头',
            description: '应用于所有请求的全局请求头'
          },
          retryPolicy: {
            type: 'object',
            title: '全局重试策略',
            properties: {
              intervalMs: {
                type: 'number',
                title: '重试间隔',
                default: 1000
              },
              maxAttempts: {
                type: 'number',
                title: '最大重试次数',
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

    // 构建GeniSpace算子定义格式
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
        
        // 用户级配置（由算子定义文件根级 configuration 提供）
        configuration: {
          schema: customUserConfiguration.schema || { type: 'object', properties: {} },
          values: customUserConfiguration.values || {}
        },
        // 系统级 API 运行配置（用于服务地址、全局头、超时等）
        systemConfiguration: defaultSystemConfiguration,

        // 方法定义（根级 methods；合并 chatPluginByMethod → chatPluginConfig）
        methods: this._mergeChatPluginConfigs(
          this._buildMethodsFromDefinition(config),
          config,
          this._resolvePublicBaseUrl(baseUrl)
        ),
        
        // 元数据：先写导出审计字段，再合并算子文件中的 metadata（如 locales.zh）
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
   * 调试台：返回已注册算子及方法的 inputSchema、endpoint、chatPluginConfig
   * @param {object} req - 可选，用于解析对外 Host
   * @returns {Array<object>}
   */
  getPlaygroundRegistry(req = null) {
    if (!this.initialized) {
      throw new Error('应用服务未初始化，请先调用 initialize()');
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
   * 解析用于拼接 pluginUrl 的对外 Origin（不含尾斜杠）
   * @param {string} reqBaseUrl - 来自请求的动态 baseUrl
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
   * 由算子 methods[]（根级或兼容 genispace.methods）构建平台 methods（含 configuration）
   * @param {object} config - 算子配置
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
                title: '请求头',
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
   * 将 chatPluginByMethod（根级或 genispace）合并到导出方法的 chatPluginConfig
   * @param {Array} methods - _buildMethodsFromDefinition 结果
   * @param {object} operatorConfig - 算子 module.exports
   * @param {string} publicBase - 对外服务根 URL
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
   * 重新加载算子
   * @param {string} operatorsDir - 算子目录
   */
  async reload(operatorsDir) {
    logger.info('开始重新加载算子...');
    
    // 清空状态
    this.registry.clear();
    this.discovery.reset();
    
    // 重新初始化
    await this.initialize(operatorsDir);
    
    logger.info('算子重新加载完成');
  }

  /**
   * 加载算子
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
        logger.error(`算子注册失败: ${operatorData?.config?.info?.name || 'unknown'}`, { 
          error: error.message 
        });
      }
    }
    
    logger.info(`算子加载完成: 成功 ${successCount} 个，失败 ${errorCount} 个`);
    
    if (successCount === 0) {
      logger.warn('没有成功加载任何算子');
    }
  }

  /**
   * 生成API文档
   * @private
   */
  _generateDocs() {
    // 直接使用文档生成器生成完整的OpenAPI文档
    this.swaggerSpec = this.docsGenerator.generate(this.registry);
    
    logger.debug('API文档生成完成');
  }
}

module.exports = ApplicationService;
