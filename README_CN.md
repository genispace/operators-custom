# GeniSpace operators-internal（平台内置算子）

**🌐 语言**: **中文** | [English](README.md)

> **平台官方内置**算子服务：HTTP/OpenAPI 执行面 + 可选 **Chat 远程插件**（`/static/plugins` 托管）。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

本仓库与面向客户随意 fork 的 **`operators-custom` 模板仓** 不同：跟随平台版本发布，对接控制面导入与插件 URL 策略。**如何创建与维护算子**（目录、`*.operator.js` 与路由、用户/系统配置、`__config` 与 `configDelivery`、Chat 插件、认证、联调与部署）见 **[docs/creating-operators.md](docs/creating-operators.md)**。

## 💡 什么是算子？

算子在 **`*.operator.js` 根级** 用 **`methods`** 声明 HTTP 方法与 JSON Schema；服务加载时 **派生 OpenAPI** 供 Swagger UI 与端点索引。可选根级 **`chatPluginByMethod`** 映射到导出定义里的 **`chatPluginConfig`**，Chat 通过 `loadRemotePlugin` 加载同仓构建的 `manifest.json` + 脚本做富展示。历史 **`genispace.methods` / `genispace.chatPluginByMethod`** 仍兼容。

## 🚀 相对 operators-custom 的增量能力

- **`PUBLIC_BASE_URL`**：导出 definition 时拼接绝对 **`pluginUrl`**。
- **`npm run build:plugins`**：聚合 `operators/**/plugin/` → `public/plugins/`，经 **`/static/plugins`** 访问。
- **`npm run dev`**：同时启动 Express（默认 `8080`）与 Vite 调试台（`18080`），表单 + 插件预览闭环。
- **示范算子** `operators/web/web-browser/`：与 Agent 内置 `web_browser` 入参/校验/输出 JSON 对齐（无 Puppeteer）。

### 核心优势

- 与 custom 相同的 **Express 路由** 模式；契约以 **methods** 为主、OpenAPI 为派生，并内置 **Chat 插件** 工程化路径。
- 边界清晰：本仓实现 HTTP/静态插件；**注册与权限在 Core API**；**MCP 列表在 mcp-server**；**渲染在 Chat**。

## 🚀 快速上手

### 1. 安装、构建插件、启动服务

```bash
git clone https://github.com/genispace/operators-internal.git
cd operators-internal
npm install
npm run build:plugins
npm start
```

访问：
- 🏠 **首页**：http://localhost:8080/api
- 📚 **API 文档**：http://localhost:8080/api/docs  
- 🔍 **健康检查**：http://localhost:8080/health
- 📦 **示例插件**：http://localhost:8080/static/plugins/web/web-browser/manifest.json

### 2. 本地调试台

```bash
npm run dev
```

浏览器打开 **http://localhost:18080**（`/api` 与 `/static` 代理到 `8080`）。

### 3. 测试算子

```bash
# 运行回归测试
npm test

# 测试字符串工具
curl -X POST http://localhost:8080/api/text-processing/string-utils/format \
  -H "Content-Type: application/json" \
  -d '{"input":"hello world","options":{"case":"title"}}'
```

### 4. 导入到 GeniSpace 平台

1. 复制算子定义链接（从首页获取）
2. 在 GeniSpace 平台选择"算子导入" → "GeniSpace算子定义"
3. 粘贴链接，一键导入

## 📝 开发新算子

### 标准流程（2个文件）

创建算子只需要两个文件：

```bash
mkdir -p operators/example
touch operators/example/demo.operator.js  # 配置文件
touch operators/example/demo.routes.js    # 业务逻辑
```

### 配置文件示例

**`demo.operator.js`** - 根级 **`methods`** 为唯一真相（加载时自动派生 OpenAPI，无需手写顶层 `openapi`）：

```javascript
module.exports = {
  info: {
    name: 'demo',
    title: '演示算子',
    description: '字符串大小写转换',
    version: '1.0.0',
    category: 'example'
  },
  routes: './demo.routes.js',
  methods: [
    {
      identifier: 'convert',
      name: '转换文本大小写',
      description: '',
      path: '/convert',
      httpMethod: 'POST',
      inputSchema: {
        type: 'object',
        required: ['text'],
        properties: {
          text: { type: 'string', example: 'hello' },
          toUpper: { type: 'boolean', default: true }
        }
      },
      outputSchema: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          data: {
            type: 'object',
            properties: {
              result: { type: 'string', example: 'HELLO' }
            }
          }
        }
      }
    }
  ]
};
```

可选字段：`tags`、`security`、`requestBodyRequired`（默认 `true`）、`additionalResponses`（仅影响派生 Swagger，如 401/400）、根级 **`openapiComponents.schemas`**（供 `$ref`，见 `genispace-info` 算子）。Chat 插件用根级 **`chatPluginByMethod`**，**key 与 `identifier` 小写一致**。仍支持旧写法 `genispace: { methods, chatPluginByMethod, openapiComponents }`。

### 业务逻辑文件

**`demo.routes.js`** - 标准 Express 路由：

```javascript
const express = require('express');
const { sendSuccessResponse, sendErrorResponse } = require('../../src/utils/response');

const router = express.Router();

router.post('/convert', async (req, res, next) => {
  try {
    const { text, toUpper = true } = req.body;
    
    if (!text) {
      return sendErrorResponse(res, '文本不能为空', 400);
    }

    const result = toUpper ? text.toUpperCase() : text.toLowerCase();
    
    sendSuccessResponse(res, { result });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
```

### 测试新算子

```bash
# 重启服务（自动发现新算子）
npm start

# 测试API
curl -X POST http://localhost:8080/api/example/demo/convert \
  -H "Content-Type: application/json" \
  -d '{"text":"hello","toUpper":true}'

# 运行完整测试
npm test
```

## 🏗️ 项目结构

```
genispace-operators-custom/
├── operators/              # 算子目录
│   ├── text-processing/    # 文本处理算子
│   │   └── string-utils/    # 字符串工具算子
│   │       ├── string-utils.operator.js  # 算子配置
│   │       └── string-utils.routes.js    # 业务逻辑
│   ├── data-transform/     # 数据转换算子
│   │   └── json-transformer/ # JSON转换器算子
│   │       ├── json-transformer.operator.js  # 算子配置
│   │       └── json-transformer.routes.js    # 业务逻辑
│   ├── notification/       # 通知服务算子
│   │   └── email-sender/   # 邮件发送器算子
│   │       ├── email-sender.operator.js  # 算子配置
│   │       └── email-sender.routes.js    # 业务逻辑
│   ├── web/               # 网页展示类（浏览器/重定向/HTML/iframe）
│   ├── search/            # 搜索类（如 tavily-search）
│   ├── weather/           # 天气类（weather-forecast）
│   └── platform/          # 仅平台集成（genispace-info）
│       └── genispace-info/
│           ├── genispace-info.operator.js
│           └── genispace-info.routes.js
├── src/                   # 核心框架（无需修改）
│   ├── config/            # 配置管理
│   ├── core/              # 核心服务（发现、注册、路由）
│   ├── middleware/        # 中间件（认证、日志、错误处理）
│   ├── routes/            # 路由管理
│   ├── services/          # 业务服务
│   └── utils/             # 工具函数
├── test.js               # 回归测试脚本
├── env.example           # 环境变量示例
├── docker-compose.yml    # Docker 编排
├── Dockerfile            # 容器化部署
└── README_CN.md         # 中文文档
```

## 🧪 内置算子示例

| 算子 | 功能 | 端点 |
|------|------|------|
| 字符串工具 | 格式化、验证 | `/api/text-processing/string-utils/*` |
| JSON转换器 | 筛选、合并 | `/api/data-transform/json-transformer/*` |
| 邮件发送器 | 邮件通知 | `/api/notification/email-sender/*` |
| **GeniSpace平台信息** | **平台集成演示** | `/api/platform/genispace-info/*` |

> **新增**: GeniSpace平台信息算子演示了如何在算子中使用SDK调用平台功能，包括用户信息、智能体列表、任务创建等。

## 🔧 配置说明

### 环境变量

#### 基础配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `8080` | 服务端口 |
| `NODE_ENV` | `development` | 运行环境 |
| `CORS_ORIGIN` | `*` | 跨域配置 |
| `LOG_LEVEL` | `info` | 日志级别 |
| `LOG_CONSOLE` | `true` | 控制台日志输出 |

#### 🔐 GeniSpace API Key 认证配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `GENISPACE_AUTH_ENABLED` | `false` | 是否启用GeniSpace平台API Key认证 |
| `GENISPACE_API_BASE_URL` | `https://api.genispace.com` | GeniSpace平台API基础URL |
| `GENISPACE_AUTH_TIMEOUT` | `10000` | 认证请求超时时间(毫秒) |
| `GENISPACE_AUTH_CACHE_TTL` | `300` | 认证结果缓存时间(秒) |

**启用认证后**：
- 所有 `/api/*` 路径将需要有效的 GeniSpace API Key
- 专用认证格式：`Authorization: GeniSpace <your-api-key>`
- 认证结果会缓存5分钟，减少对 GeniSpace 平台的请求

### 生产部署

```bash
# Docker 部署
docker build -t my-operators .
docker run -p 8080:8080 -e NODE_ENV=production my-operators

# 或直接运行
NODE_ENV=production npm start
```

## 🔐 GeniSpace 平台认证集成

### API Key 认证配置

当您部署算子服务到生产环境时，建议启用 GeniSpace 平台的 API Key 认证，确保只有授权用户才能访问您的算子。

#### 1. 启用认证

```bash
# 修改 .env 文件
GENISPACE_AUTH_ENABLED=true
GENISPACE_API_BASE_URL=https://api.genispace.com
```

#### 2. 客户端调用示例

启用认证后，客户端需要在请求头中包含有效的 GeniSpace API Key：

```bash
# 使用 GeniSpace 专用认证格式
curl -X POST http://your-operator-service:8080/api/document/pdf-generator/generate-from-html \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"htmlContent": "<h1>Hello</h1>"}'

# 字符串处理示例
curl -X POST http://your-operator-service:8080/api/text-processing/string-utils/format \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"input": "hello world", "options": {"case": "title"}}'
```

#### 3. 使用 GeniSpace JavaScript SDK

SDK 主要用于在算子内部调用 GeniSpace 平台功能：

```bash
npm install genispace  # 已发布版本 v1.0.0
```

```javascript
import GeniSpace from 'genispace';

// SDK 用于调用 GeniSpace 平台接口
const client = new GeniSpace({
  apiKey: 'your-genispace-api-key',
  baseURL: 'https://api.genispace.com' // GeniSpace 平台地址
});

// 调用 GeniSpace 平台功能
const userInfo = await client.users.getProfile();
const agents = await client.agents.list();
const teams = await client.users.getTeams();
```

#### 4. 错误处理

认证失败时，服务会返回标准错误响应：

```json
{
  "success": false,
  "error": "API Key 无效或已过期",
  "code": "INVALID_API_KEY",
  "timestamp": "2025-09-23T14:30:00.000Z"
}
```

常见错误码：
- `MISSING_API_KEY`: 缺少 API Key
- `INVALID_API_KEY`: API Key 无效或已过期
- `INSUFFICIENT_PERMISSIONS`: 权限不足
- `AUTH_SERVICE_ERROR`: 认证服务错误

#### 5. 安全最佳实践

- ✅ 在生产环境中始终启用认证
- ✅ 定期轮换 API Key
- ✅ 使用环境变量存储 API Key，不要硬编码
- ✅ 监控异常的认证失败请求
- ✅ 配置适当的缓存时间，平衡性能和安全性

## 🤝 GeniSpace 平台集成

### 导入算子到平台

1. **获取算子定义链接**
   ```bash
   # 访问首页复制链接，或直接访问：
   curl http://your-domain:8080/api/operators/category/name/definition
   ```

2. **在平台导入**
   - 进入 GeniSpace 平台算子管理
   - 选择"GeniSpace算子定义导入"
   - 粘贴定义链接
   - 一键导入

3. **开始使用**
   - 在智能体中配置算子
   - 在工作流中调用算子

## 📊 质量保证

### 自动测试

```bash
npm test  # 运行完整回归测试
```

测试覆盖：
- ✅ 服务健康检查
- ✅ 算子加载验证  
- ✅ API 文档生成
- ✅ 核心功能测试
- ✅ 错误处理验证

### 最佳实践

1. **开发规范**
   - 算子名称使用 `kebab-case`
   - 遵循 OpenAPI 3.0 规范
   - 使用统一错误处理

2. **测试流程**  
   ```bash
   npm start  # 启动服务
   npm test   # 运行测试
   ```

3. **部署前检查**
   - 所有测试通过
   - API 文档正常生成
   - 算子定义链接可访问

## 💡 常见问题

**Q: 如何添加新算子？**
A: 在 `operators/category/` 下创建 `.operator.js` 和 `.routes.js` 文件即可。

**Q: 服务启动后算子没有加载？**  
A: 运行 `npm test` 检查算子配置，查看控制台错误信息。

**Q: 如何在 GeniSpace 平台使用？**
A: 复制算子定义链接，在平台选择"GeniSpace算子定义导入"。

## 🔧 GeniSpace SDK 深度集成

本项目已集成 **GeniSpace JavaScript SDK**，实现统一认证和平台功能调用。

### 📦 集成特性

- ✅ **统一认证**: 使用 GeniSpace 平台 API Key 验证用户身份
- ✅ **智能缓存**: 认证结果自动缓存，提升性能  
- ✅ **用户信息**: 自动获取已认证用户的详细信息
- ✅ **SDK 客户端**: 在算子中直接使用 `req.genispace.client`

### 🚀 在算子中使用 SDK

```javascript
// 在算子路由中访问用户信息和 SDK 客户端
router.post('/my-endpoint', async (req, res) => {
  // 检查认证状态
  if (!req.genispace || !req.genispace.client) {
    return res.status(401).json({ error: '需要认证才能访问此功能' });
  }
  
  const { user, client } = req.genispace;
  
  // 用户信息
  console.log(`认证用户: ${user.name} (${user.email})`);
  
  // 调用 GeniSpace 平台功能
  const teams = await client.users.getTeams();
  const stats = await client.users.getStatistics();
  const agents = await client.agents.list({ page: 1, limit: 10 });
  
  res.json({ success: true, data: { user, teams, stats, agents } });
});
```

### 📋 GeniSpace 平台信息算子

项目包含 **GeniSpace 平台信息算子** (`platform/genispace-info`)，演示 SDK 集成：

#### 🔍 可用接口
- `POST /user-profile` - 获取用户资料、统计信息和团队信息
- `POST /agents` - 获取用户智能体列表（支持分页）

#### 🧪 演示特性
- ✅ **SDK 认证**: 使用 `genispace@1.0.0` npm 包
- ✅ **错误处理**: 统一的 asyncHandler 错误处理
- ✅ **灵活调用**: 支持可选参数控制返回内容

#### 🚀 快速测试
```bash
# 启动服务
GENISPACE_AUTH_ENABLED=true npm start

# 测试用户资料接口
curl -X POST http://localhost:8080/api/platform/genispace-info/user-profile \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"includeStatistics": true, "includeTeams": true}'
```

## 📞 技术支持

- **官网**: [https://genispace.com](https://genispace.com)
- **文档**: [https://docs.genispace.com](https://docs.genispace.com)  
- **问题反馈**: [GitHub Issues](https://github.com/genispace/operators-custom/issues)

## 📄 开源协议

本项目采用 [MIT 协议](LICENSE) 开源。