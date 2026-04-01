/**
 * GeniSpace Custom Operators API Server
 * 
 * GeniSpace AI 平台的轻量级自定义算子组件库
 * 重构后的清晰分层架构
 * 
 * @copyright © 2025 genispace.com Dev Team
 * @license MIT
 */

const express = require('express');
const swaggerUi = require('swagger-ui-express');
const path = require('path');
const { execSync } = require('child_process');

// 加载环境变量
require('dotenv').config();

// 导入配置和服务
const config = require('./config/env');
const ApplicationService = require('./services/app-service');
const { setupMiddlewares } = require('./middleware');
const { setupRoutes } = require('./routes');
const logger = require('./utils/logger');

// 创建Express应用
const app = express();

// 插件静态目录（须在 setupMiddlewares 之后挂载，否则先于 CORS 响应，浏览器从调试台跨域拉 manifest/JS 会缺 ACAO）
const publicPluginsPath = path.join(__dirname, '../public/plugins');

// 创建应用服务
const appService = new ApplicationService(config);

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

/**
 * 应用启动函数
 */
async function startApp() {
  try {
    logger.info('🚀 启动 GeniSpace Custom Operators API...');

    // 0. 若在网关后以子路径暴露（见 cicd Ingress），先剥掉前缀再匹配 /api、/static、/health
    mountIngressStripPrefix(app, config.ingressStripPrefix);

    if (config.security.trustProxy) {
      app.set('trust proxy', true);
    }
    
    // 1. 设置中间件
    setupMiddlewares(app, config);

    // 1a. 开发模式：public/plugins 被 gitignore，且 nodemon 重启不会跑 npm pre 脚本；启动前同步 operators/**/plugin
    if (config.isDevelopment) {
      const repoRoot = path.join(__dirname, '..');
      try {
        execSync('node scripts/build-plugins.js', { cwd: repoRoot, stdio: 'pipe' });
        logger.debug('开发模式已同步 Chat 插件 -> public/plugins');
      } catch (err) {
        const detail = err.stderr ? String(err.stderr) : err.message;
        logger.warn('开发模式 build-plugins 失败；/static/plugins 下 manifest 可能 404', { error: detail });
      }
    }

    // 1b. 托管各算子 Chat 插件静态资源（build:plugins 聚合到 public/plugins）
    app.use('/static/plugins', express.static(publicPluginsPath, { fallthrough: true }));
    // 网关对外路径含 apiPrefix（如 /operators/internal/static/plugins/...）且未剥前缀时，需同路径挂载
    const apiPx = (config.apiPrefix && String(config.apiPrefix).replace(/\/$/, '')) || '';
    if (apiPx) {
      app.use(`${apiPx}/static/plugins`, express.static(publicPluginsPath, { fallthrough: true }));
    }
    
    // 2. 初始化应用服务
    const operatorsDir = path.join(__dirname, '../operators');
    await appService.initialize(operatorsDir);
    
    // 3. 设置基础路由
    setupRoutes(app, appService, config);
    
    // 4. 应用算子路由
    appService.applyTo(app);
    
    // 5. 设置API文档
    setupApiDocs(app, appService, config);
    
    // 6. 设置错误处理（必须在所有路由之后）
    const { errorHandler, notFoundHandler } = require('./middleware/error');
    app.use(notFoundHandler);
    app.use(errorHandler);
    
    // 7. 启动服务器
    const server = app.listen(config.port, config.host, () => {
      const stats = appService.getStats();
      
      logger.info('✅ 服务器启动成功', {
        port: config.port,
        host: config.host,
        environment: config.env,
        nodeVersion: process.version,
        operators: stats.totalOperators,
        endpoints: stats.totalEndpoints
      });
      
      const publicRouteBase = config.getPublicRouteBaseUrl();
      logger.info(`📚 API 文档: ${publicRouteBase}/docs`);
      logger.info(`🔗 OpenAPI Schema: ${publicRouteBase}/docs.json`);
      const probeHost = config.host === '0.0.0.0' ? 'localhost' : config.host;
      logger.info(`🏥 健康检查: http://${probeHost}:${config.port}/health`);
    });

    // 优雅关闭处理
    setupGracefulShutdown(server);

    return { app, server, appService };
    
  } catch (error) {
    logger.error('❌ 服务器启动失败', { error: error.stack });
    process.exit(1);
  }
}

/**
 * 设置API文档
 */
function setupApiDocs(app, appService, config) {
  const swaggerSpec = appService.getSwaggerSpec();
  const apiPrefix = config.apiPrefix || '/api';
  
  // Swagger UI
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

  // Swagger JSON端点
  app.get(`${apiPrefix}/docs.json`, (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.json(swaggerSpec);
  });
}

/**
 * 设置优雅关闭
 */
function setupGracefulShutdown(server) {
  const gracefulShutdown = (signal) => {
    logger.info(`收到 ${signal} 信号，开始优雅关闭...`);
    server.close(() => {
      logger.info('HTTP 服务器已关闭');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  // 异常处理
  process.on('uncaughtException', (error) => {
    logger.error('未捕获的异常', { error: error.stack });
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('未处理的Promise拒绝', { 
      reason: reason,
      promise: promise
    });
    process.exit(1);
  });
}

// 如果直接运行此文件，启动服务器
if (require.main === module) {
  startApp();
}

module.exports = { app, startApp, appService };