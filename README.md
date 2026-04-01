# GeniSpace operators-custom

**🌐 Language**: [中文](README_CN.md) | **English**

> **Open-source operator scaffold** — host your own HTTP operator service and optional **Chat remote plugins** (`/static/plugins`). Use it to build a **private operator library** (GeniSpace tools / workflow components / Chat UI extensions) that you deploy and register on the platform via **definition URL**.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

**Authoring guide** (folders, `*.operator.js` / `*.routes.js`, user vs system configuration, `__config` / `configDelivery`, `plugins/<slot>/`, auth, local dev, deploy): [docs/creating-operators.md](docs/creating-operators.md). The guide is written against the official reference layout; **this template follows the same contract** so imports and runtime behavior match GeniSpace.

## 💡 What is an Operator?

An operator declares HTTP methods and JSON Schemas in root-level **`methods`**. At load time the service **derives OpenAPI** for Swagger and endpoint indexing. Optional root **`chatPluginByMethod`** maps to exported **`chatPluginConfig`** so Chat can load a **remote plugin** (`manifest.json` + JS bundle) for rich UI. Legacy **`genispace.*`** nesting remains supported.

## 🧩 What this scaffold includes

- **`PUBLIC_BASE_URL`** (or `OPERATORS_BASE_URL`) so exported definitions contain absolute **`pluginUrl`** for browser-loaded Chat plugins.
- **`npm run build:plugins`** — copies each `operators/**/plugins/<slot>/` (with `manifest.json`) into `public/plugins/...`, served at **`/static/plugins/...`** (see [creating-operators.md](docs/creating-operators.md) §3 / §8).
- **`npm run dev`** — Express (default `:8080`) + Vite playground (`:18080`) for schema forms and plugin preview.
- **Starter examples in this repo**: `operators/weather/weather-forecast` (HTTP + optional `plugins/forecast/`), `operators/platform/genispace-info` (GeniSpace JS SDK demo).

### How it fits GeniSpace

- **Your repository**: HTTP execution surface + optional static plugin assets.
- **GeniSpace platform**: registration, ACL, merged user/system config; you **import** each operator’s **definition** URL from your running service.
- **MCP-Server / Chat**: tool exposure and rendering; Chat may **`loadRemotePlugin`** when `chatPluginConfig` is present.

**vs [operators-internal](https://github.com/genispace/operators-internal)** (official built-in operators, platform release cadence): **operators-custom** is the **customer-owned** template — fork, extend, and ship on **your** infrastructure and release cycle.

## 🚀 Quick Start

### 1. Install, build plugins, start API

```bash
git clone https://github.com/genispace/operators-custom.git
cd operators-custom
npm install
npm run build:plugins
npm start
```

Access:
- 🏠 **Homepage**: http://localhost:8080/api (HTML index)
- 📚 **API Docs**: http://localhost:8080/api/docs  
- 🔍 **Health Check**: http://localhost:8080/health
- 📦 **Example plugin manifest**: http://localhost:8080/static/plugins/weather/weather-forecast/plugins/forecast/manifest.json

### 2. Dev playground (operators + UI preview)

```bash
npm run dev
```

Open **http://localhost:18080** — API and `/static` are proxied to `8080`.

### 3. Test Operators

```bash
# Run regression tests
npm test

# Example: weather forecast (Open-Meteo)
curl -X POST http://localhost:8080/api/weather/weather-forecast/forecast \
  -H "Content-Type: application/json" \
  -d '{"location":"Berlin","days":3}'
```

### 4. Import to GeniSpace Platform

1. Copy operator definition link (from homepage)
2. In GeniSpace platform, select "Operator Import" → "GeniSpace Operator Definition"
3. Paste link and import with one click

## 📝 Developing New Operators

### Standard Process (2 Files)

Creating an operator requires only two files:

```bash
mkdir -p operators/example
touch operators/example/demo.operator.js  # Configuration file
touch operators/example/demo.routes.js    # Business logic
```

### Configuration File Example

**`demo.operator.js`** - root **`methods`** as the single source of truth (OpenAPI is derived at load time; do not hand-write a top-level `openapi` block):

```javascript
module.exports = {
  info: {
    name: 'demo',
    title: 'Demo Operator',
    description: 'String case conversion',
    version: '1.0.0',
    category: 'example'
  },
  routes: './demo.routes.js',
  methods: [
    {
      identifier: 'convert',
      name: 'Convert text case',
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

Optional: `tags`, `security`, `requestBodyRequired` (default `true`), `additionalResponses` (Swagger-only extra status codes), root **`openapiComponents.schemas`** for `$ref` (see `genispace-info`). For Chat plugins, use root **`chatPluginByMethod`** with keys matching **`identifier`** (lowercase). Legacy `genispace: { methods, chatPluginByMethod, openapiComponents }` still works.

### Business Logic File

**`demo.routes.js`** - Standard Express routes:

```javascript
const express = require('express');
const { sendSuccessResponse, sendErrorResponse } = require('../../src/utils/response');

const router = express.Router();

router.post('/convert', async (req, res, next) => {
  try {
    const { text, toUpper = true } = req.body;
    
    if (!text) {
      return sendErrorResponse(res, 'Text cannot be empty', 400);
    }

    const result = toUpper ? text.toUpperCase() : text.toLowerCase();
    
    sendSuccessResponse(res, { result });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
```

### Testing New Operators

```bash
# Restart service (automatically discovers new operators)
npm start

# Test API
curl -X POST http://localhost:8080/api/example/demo/convert \
  -H "Content-Type: application/json" \
  -d '{"text":"hello","toUpper":true}'

# Run complete tests
npm test
```

## 🏗️ Project Structure

```
operators-custom/
├── operators/              # Your operators (add categories as needed)
│   ├── weather/
│   │   └── weather-forecast/   # Example: HTTP + plugins/forecast/ Chat bundle
│   │       ├── weather-forecast.operator.js
│   │       ├── weather-forecast.routes.js
│   │       └── plugins/forecast/   # manifest.json, index.js, widget, locales/…
│   └── platform/
│       └── genispace-info/     # Example: GeniSpace JS SDK usage
│           ├── genispace-info.operator.js
│           └── genispace-info.routes.js
├── src/                   # Core framework (usually no changes)
│   ├── config/            # Configuration management
│   ├── core/              # Core services (discovery, registry, routing)
│   ├── middleware/        # Middleware (auth, logging, error handling)
│   ├── routes/            # Route management
│   ├── services/          # Business services
│   └── utils/             # Utility functions
├── test.js               # Regression test script
├── env.example           # Environment variables example
├── docker-compose.yml    # Docker orchestration
├── Dockerfile            # Containerization deployment
└── README.md            # English documentation
```

## 🧪 Example operators in this template

| Operator | Role | Endpoint (sample) |
|----------|------|-------------------|
| **Weather forecast** | Open-Meteo + optional Chat plugin | `POST /api/weather/weather-forecast/forecast` |
| **GeniSpace platform info** | SDK / platform API demo | `/api/platform/genispace-info/*` |

Add more under `operators/<category>/<name>/` following [docs/creating-operators.md](docs/creating-operators.md).

## 🔧 Configuration Instructions

### Environment Variables

#### Basic Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Service port |
| `NODE_ENV` | `development` | Runtime environment |
| `CORS_ORIGIN` | `*` | CORS configuration |
| `LOG_LEVEL` | `info` | Log level |
| `LOG_CONSOLE` | `true` | Console log output |

#### 🔐 GeniSpace API Key Authentication Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GENISPACE_AUTH_ENABLED` | `false` | Enable GeniSpace platform API Key authentication |
| `GENISPACE_API_BASE_URL` | `https://api.genispace.com` | GeniSpace platform API base URL |
| `GENISPACE_AUTH_TIMEOUT` | `10000` | Authentication request timeout (milliseconds) |
| `GENISPACE_AUTH_CACHE_TTL` | `300` | Authentication result cache time (seconds) |

**After enabling authentication**:
- All `/api/*` paths will require valid GeniSpace API Key
- Supported authentication formats: 
  - `Authorization: GeniSpace <your-api-key>`
  - `GeniSpace: <your-api-key>` (recommended)
- Does not support `Authorization: Bearer` format to avoid conflicts with custom operator authentication
- Authentication results are cached for 5 minutes, reducing requests to GeniSpace platform

### Production Deployment

```bash
# Docker deployment
docker build -t my-operators .
docker run -p 8080:8080 -e NODE_ENV=production my-operators

# Or run directly
NODE_ENV=production npm start
```

## 🔐 GeniSpace Platform Authentication Integration

### API Key Authentication Configuration

When deploying operator services to production environment, it's recommended to enable GeniSpace platform API Key authentication to ensure only authorized users can access your operators.

#### 1. Enable Authentication

```bash
# Modify .env file
GENISPACE_AUTH_ENABLED=true
GENISPACE_API_BASE_URL=https://api.genispace.com
```

#### 2. Client Call Examples

After enabling authentication, clients need to include valid GeniSpace API Key in request headers:

```bash
# GeniSpace auth header (same shape the platform uses when calling your service)
curl -X POST http://your-operator-service:8080/api/weather/weather-forecast/forecast \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"location":"Berlin","days":3}'

# Platform info (requires auth when GENISPACE_AUTH_ENABLED=true)
curl -X POST http://your-operator-service:8080/api/platform/genispace-info/user-profile \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"includeStatistics":true}'
```

#### 3. Using GeniSpace JavaScript SDK

SDK is mainly used for calling GeniSpace platform functions within operators:

```bash
npm install genispace  # Published version v1.0.0
```

```javascript
import GeniSpace from 'genispace';

// SDK used for calling GeniSpace platform interfaces
const client = new GeniSpace({
  apiKey: 'your-genispace-api-key',
  baseURL: 'https://api.genispace.com' // GeniSpace platform address
});

// Call GeniSpace platform functions
const userInfo = await client.users.getProfile();
const agents = await client.agents.list();
const teams = await client.users.getTeams();
```

#### 4. Error Handling

When authentication fails, the service returns standard error responses:

```json
{
  "success": false,
  "error": "API Key invalid or expired",
  "code": "INVALID_API_KEY",
  "timestamp": "2025-09-23T14:30:00.000Z"
}
```

Common error codes:
- `MISSING_API_KEY`: Missing API Key
- `INVALID_API_KEY`: API Key invalid or expired
- `INSUFFICIENT_PERMISSIONS`: Insufficient permissions
- `AUTH_SERVICE_ERROR`: Authentication service error

#### 5. Security Best Practices

- ✅ Always enable authentication in production environment
- ✅ Regularly rotate API Keys
- ✅ Use environment variables to store API Keys, don't hardcode
- ✅ Monitor abnormal authentication failure requests
- ✅ Configure appropriate cache time, balance performance and security

## 🤝 GeniSpace Platform Integration

### Import Operators to Platform

1. **Get Operator Definition Link**
   ```bash
   # Visit homepage to copy link, or access directly:
   curl http://your-domain:8080/api/operators/category/name/definition
   ```

2. **Import in Platform**
   - Enter GeniSpace platform operator management
   - Select "GeniSpace Operator Definition Import"
   - Paste definition link
   - Import with one click

3. **Start Using**
   - Configure operators in AI agents
   - Call operators in workflows

## 📊 Quality Assurance

### Automated Testing

```bash
npm test  # Run complete regression tests
```

Test coverage:
- ✅ Service health check
- ✅ Operator loading verification
- ✅ API documentation generation
- ✅ Core functionality testing
- ✅ Error handling verification

### Best Practices

1. **Development Standards**
   - Use `kebab-case` for operator names
   - Follow OpenAPI 3.0 specifications
   - Use unified error handling

2. **Testing Process**  
   ```bash
   npm start  # Start service
   npm test   # Run tests
   ```

3. **Pre-deployment Checks**
   - All tests pass
   - API documentation generates normally
   - Operator definition links are accessible

4. **GeniSpace auth on imported operators**
   - When “GeniSpace authentication” is enabled in the operator runtime config, the platform may attach a **System API Key** on outbound calls.
   - In routes you can validate the caller via middleware and read `req.genispace` (user, API key, etc.).
   - Header shape: `GeniSpace: <system-api-key>` (see also root `enableGeniSpaceAuth` in [creating-operators.md](docs/creating-operators.md)).

## 💡 Common Questions

**Q: How to add new operators?**
A: Create `.operator.js` and `.routes.js` files under `operators/category/`.

**Q: Operators not loading after service starts?**  
A: Run `npm test` to check operator configuration and view console error messages.

**Q: How to use in GeniSpace platform?**
A: Copy operator definition link and select "GeniSpace Operator Definition Import" in platform.

## 🔧 GeniSpace SDK Deep Integration

This project has integrated **GeniSpace JavaScript SDK** for unified authentication and platform function calls.

### 📦 Integration Features

- ✅ **Unified Authentication**: Use GeniSpace platform API Key to verify user identity
- ✅ **Smart Caching**: Authentication results are automatically cached for performance
- ✅ **User Information**: Automatically obtain detailed information of authenticated users
- ✅ **SDK Client**: Use `req.genispace.client` directly in operators

### 🚀 Using SDK in Operators

```javascript
// Access user information and SDK client in operator routes
router.post('/my-endpoint', async (req, res) => {
  // Check authentication status
  if (!req.genispace || !req.genispace.client) {
    return res.status(401).json({ error: 'Authentication required to access this feature' });
  }
  
  const { user, client } = req.genispace;
  
  // User information
  console.log(`Authenticated user: ${user.name} (${user.email})`);
  
  // Call GeniSpace platform functions
  const teams = await client.users.getTeams();
  const stats = await client.users.getStatistics();
  const agents = await client.agents.list({ page: 1, limit: 10 });
  
  res.json({ success: true, data: { user, teams, stats, agents } });
});
```

### 📋 GeniSpace Platform Info Operator

The project includes **GeniSpace Platform Info Operator** (`platform/genispace-info`) demonstrating SDK integration:

#### 🔍 Available Interfaces
- `POST /user-profile` - Get user profile, statistics, and team information
- `POST /agents` - Get user agent list (with pagination support)

#### 🧪 Demo Features
- ✅ **SDK Authentication**: Uses `genispace@1.0.0` npm package
- ✅ **Error Handling**: Unified asyncHandler error handling
- ✅ **Flexible Calls**: Supports optional parameters to control returned content

#### 🚀 Quick Test
```bash
# Start service
GENISPACE_AUTH_ENABLED=true npm start

# Test user profile interface
curl -X POST http://localhost:8080/api/platform/genispace-info/user-profile \
  -H "Authorization: GeniSpace your-genispace-api-key" \
  -H "Content-Type: application/json" \
  -d '{"includeStatistics": true, "includeTeams": true}'
```

## 📞 Technical Support

- **Official Website**: [https://genispace.com](https://genispace.com)
- **Documentation**: [https://docs.genispace.com](https://docs.genispace.com)  
- **Issue Reports**: [GitHub Issues](https://github.com/genispace/operators-custom/issues)

## 📄 Open Source License

This project is open source under the [MIT License](LICENSE).
