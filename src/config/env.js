/**
 * 环境配置管理
 * 
 * 集中管理所有环境变量和配置项
 */

const path = require('path');

const config = {
  // 服务器配置
  port: parseInt(process.env.PORT) || 8080,
  host: process.env.HOST || '0.0.0.0',
  
  // 环境配置
  env: process.env.NODE_ENV || 'development',
  isDevelopment: (process.env.NODE_ENV || 'development') === 'development',
  isProduction: process.env.NODE_ENV === 'production',
  
  // API配置
  apiPrefix: process.env.API_PREFIX || '/api',
  
  // CORS 配置：逗号分隔多域名；仅 * 时不要 split 成 ['*']（生产合并 base 的 CORS_ORIGIN=* 会误判为白名单）
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
  
  // 请求配置
  maxRequestSize: process.env.MAX_REQUEST_SIZE || '10mb',
  requestTimeout: parseInt(process.env.REQUEST_TIMEOUT) || 30000,
  
  // 速率限制
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15分钟
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // 最大请求数
    skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESS === 'true'
  },
  
  // 日志配置
  log: {
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    console: process.env.LOG_CONSOLE !== 'false' // 默认启用控制台输出
  },
  
  // 算子配置
  operators: {
    directory: process.env.OPERATORS_DIR || path.join(process.cwd(), 'operators'),
    cacheEnabled: process.env.OPERATORS_CACHE_ENABLED !== 'false',
    cacheTTL: parseInt(process.env.OPERATORS_CACHE_TTL) || 3600, // 1小时
    autoReload: process.env.OPERATORS_AUTO_RELOAD === 'true'
  },
  
  // 监控配置
  monitoring: {
    enabled: process.env.MONITORING_ENABLED === 'true',
    metricsPath: process.env.METRICS_PATH || '/metrics',
    healthPath: process.env.HEALTH_PATH || '/health'
  },
  
  // 安全配置
  security: {
    enableCors: process.env.SECURITY_CORS !== 'false',
    enableRateLimit: process.env.SECURITY_RATE_LIMIT !== 'false',
    trustProxy: process.env.TRUST_PROXY === 'true'
  },
  
  /** 对外可访问的服务根 URL（用于拼接 chat 远程插件 pluginUrl）。未设置时回退到 getServiceBaseUrl() */
  publicBaseUrl: process.env.PUBLIC_BASE_URL || null,

  /**
   * Ingress 对外路径前缀（如 /operators/internal）。K8s/GCE 常把完整 URI 原样转发，而应用仍挂在 /api、/static、/health；
   * 设置后由 Express 剥掉此前缀，使 pluginUrl 与 Chat 侧一致且避免重复配置路由。
   */
  ingressStripPrefix: (process.env.INGRESS_STRIP_PREFIX && process.env.INGRESS_STRIP_PREFIX.trim()) || null,

  // GeniSpace API KEY 认证配置
  genispace: {
    auth: {
      baseUrl: process.env.GENISPACE_API_BASE_URL || 'https://api.genispace.com',
      timeout: parseInt(process.env.GENISPACE_AUTH_TIMEOUT) || 10000,
      cacheTTL: parseInt(process.env.GENISPACE_AUTH_CACHE_TTL) || 300 // 5分钟缓存
    }
  },
  
  // 缓存配置（如果需要Redis等）
  cache: {
    enabled: process.env.CACHE_ENABLED === 'true',
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT) || 6379,
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB) || 0
    }
  },
  
  // 外部服务配置
  services: {
    // 可以在这里配置外部API、数据库等服务
  }
};

/**
 * 获取服务的基础URL
 * 优先级：OPERATORS_BASE_URL > PROTOCOL://HOST:PORT
 * @returns {string} 服务基础URL（不包含路径）
 */
function getServiceBaseUrl() {
  // 优先使用 OPERATORS_BASE_URL，因为服务启动配置往往跟最终配置的URL不一致
  if (process.env.OPERATORS_BASE_URL) {
    return process.env.OPERATORS_BASE_URL;
  }
  
  // 降级使用服务器启动配置
  const protocol = process.env.PROTOCOL || 'http';
  const host = process.env.HOST || 'localhost';
  const port = process.env.PORT || 8080;
  return `${protocol}://${host}:${port}`;
}

/**
 * 将基础 URL 中的 0.0.0.0 / [::] 换成 localhost，便于本机浏览器打开与复制链接
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
 * 与 getServiceBaseUrl 相同来源，但主机名适合在浏览器中访问（本地监听 0.0.0.0 时显示 localhost）
 * @returns {string}
 */
function getBrowserBaseUrl() {
  return normalizeServiceUrlForBrowser(getServiceBaseUrl());
}

/**
 * 规范化路径前缀用于比较（前导 /、去尾 /）
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
 * 对外「路由根」URL：用于拼接 /docs、/operators 等（与 Express 的 apiPrefix 路由一致）。
 * OPERATORS_BASE_URL 已含 /operators/internal 且与 API_PREFIX 相同时不再重复拼接，避免出现 .../operators/internal/operators/internal/docs
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

/**
 * 获取完整的API基础URL（包含API前缀）
 * @returns {string} API基础URL（包含API前缀，不包含具体路径）
 */
function getApiBaseUrl() {
  return getPublicRouteBaseUrl();
}

// 将方法添加到config对象
config.getServiceBaseUrl = getServiceBaseUrl;
config.getBrowserBaseUrl = getBrowserBaseUrl;
config.getPublicRouteBaseUrl = getPublicRouteBaseUrl;
config.getApiBaseUrl = getApiBaseUrl;

// 验证必要的配置
function validateConfig() {
  const required = [];
  
  if (!config.port || config.port < 1 || config.port > 65535) {
    required.push('PORT must be a valid port number (1-65535)');
  }
  
  if (required.length > 0) {
    throw new Error(`配置验证失败:\n${required.join('\n')}`);
  }
}

// 导出配置前进行验证
try {
  validateConfig();
} catch (error) {
  console.error('Configuration validation failed:', error.message);
  process.exit(1);
}

module.exports = config;
