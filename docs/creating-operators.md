# 如何创建算子（operators-internal 指南）

本文说明在本仓库中**新增或维护内置算子**时要做什么：目录结构、`*.operator.js` / `*.routes.js` 的写法、配置与请求体约定、可选的远程插件，以及本地构建与导入。**文中路径均以本仓库根目录为基准。**

---

## 1. 算子是什么、本仓库负责什么

**算子（Operator）** 是可声明的 HTTP 能力单元：每个方法有路径、HTTP 动词、入参/出参 Schema。你在本仓库里写好**定义**与**Express 路由**后，通过 **definition URL** 在平台控制台做「算子定义导入」；导入后由平台负责鉴权、合并用户填写的配置、向你的 HTTP 服务发请求。

**本仓库职责**：

- 提供真实的 **HTTP 执行面**（OpenAPI 由 `methods` 派生）。
- 可选：提供 **Chat 远程插件**静态资源（`plugins/<methodOrShared>/`，经构建复制到 `public/plugins/.../plugins/<slot>/`）。

**与 `operators-custom` 的区别**：本仓库为**官方内置算子**，随平台版本发布；`operators-custom` 面向客户模板与 fork。

---

## 2. 新建算子：最小步骤

1. 在 `operators/<category>/<name>/` 下新增两个文件：
   - **`<name>.operator.js`**：算子元数据、`methods`、可选 `configuration` / `systemConfiguration` / `metadata` / `chatPluginByMethod` 等。
   - **`<name>.routes.js`**：Express `Router`，挂载路径需与 OpenAPI 派生规则一致（见第 7 节）。
2. 确保 `methods` 中每条包含 **`identifier`**、**`path`**、**`httpMethod`**、**`inputSchema`** / **`outputSchema`**（与现有算子对齐）。
3. 本地执行 `npm install`、`npm run build`（含插件复制）、`npm start` 或 `npm run dev`，在首页与 Swagger 中确认路由与定义无误。
4. 在调试台或首页复制该算子的 **definition** URL，到平台控制台使用「算子定义导入」导入。
5. 若含 `plugins/<slot>/`，确认 `npm run build:plugins` 后 `GET /static/plugins/<category>/<name>/plugins/<slot>/manifest.json` 可访问；生产环境配置 **`PUBLIC_BASE_URL`**（或 `OPERATORS_BASE_URL`），使 definition 中的 `pluginUrl` 为浏览器可访问的绝对地址。写插件时请看 **第 8 节**。

**参考完整示例（用户密钥经 `__config` 出站）**：

- 定义：`operators/notification/sendgrid/sendgrid.operator.js`
- 路由：`operators/notification/sendgrid/sendgrid.routes.js`（从 `req.body.__config` 读密钥，业务字段在 `req.body` 顶层）

---

## 3. 目录与文件约定

| 路径 | 作用 |
|------|------|
| `operators/<category>/<name>/*.operator.js` | 算子主配置：根级 **`methods`（必填）**；可选 `configuration`、`systemConfiguration`、`metadata`、`routes`、`chatPluginByMethod`、`openapiComponents` 等。加载时会派生 **OpenAPI**。兼容旧包裹 `genispace: { methods, ... }`。 |
| `operators/<category>/<name>/*.routes.js` | Express `Router`；挂载路径为 **`{apiPrefix}/{category}/{name}{path}`**，默认 **`apiPrefix` 为 `/api`**（见 `src/services/app-service.js` 的 `applyTo`，可用环境配置覆盖）。 |
| `operators/<category>/<name>/plugins/<slot>/` | 可选。`<slot>` 通常等于某方法的 **`identifier`**；多方法共用一套 UI 时用 **`shared`**。内含 `manifest.json`、入口脚本（默认 `index.js`，CommonJS）；可选 **`widget`**（见第 8.2 节）。 |
| `plugins/<slot>/locales/en.json`、`zh.json` | 插件文案；构建时复制到 `public/plugins/<category>/<name>/plugins/<slot>/locales/`。 |

构建：`npm run build` / `npm run build:plugins`（开发模式启动服务时也会执行 `scripts/build-plugins.js`）将各算子 **`plugins/*/`** 下含 **`manifest.json`** 的子目录中的 **`main` 入口**（若声明且文件存在）、**`manifest.widget` 指向的文件**（若有）、**`locales/`** 复制到 **`public/plugins/<category>/<name>/plugins/<slot>/`**，运行时通过 **`GET /static/plugins/...`** 提供。遗留的 **`plugin/`**（无 `plugins/`）仅会触发构建脚本的弃用告警，不再参与复制。**仅做消息内联卡片、不需要活动面板主插件时，可以不提供 `main` 或不在 manifest 中写 `main`**，只要 **`widget` 与对应脚本文件** 存在即可通过构建复制（详见第 8.3 节）。

---

## 4. `*.operator.js` 结构说明

### 4.1 `info`（必填）

`name`、`title`、`description`、`version`、`category`、`tags`、`author` 等，用于展示与索引。

### 4.2 `routes`（必填）

指向同目录下的路由文件，例如：`routes: './sendgrid.routes.js'`。

### 4.3 `methods`（必填）

每个元素描述一个 HTTP 端点，常见字段：

- **`identifier`**：方法唯一标识（小写），与 `chatPluginByMethod` 的 key 对齐。
- **`name`**、**`description`**
- **`path`**、**`httpMethod`**：如 `'/send'`、`'POST'`
- **`inputSchema`** / **`outputSchema`**：JSON Schema（**`isPort`、`title`、中文覆盖**见 **第 4.8 节**）
- **`configuration`** / **`systemConfiguration`**（可选）：方法级覆盖算子级配置（合并规则见第 5 节）

**安全提示**：**不要把用户 API Key、密码写进 `inputSchema`**；应放在用户 **`configuration`** 中，由平台通过 **`__config`** 注入（见第 6 节）。

### 4.4 用户配置 `configuration` 与系统配置 `systemConfiguration`

| | **用户配置** | **系统配置** |
|---|-------------|-------------|
| **谁填写** | 租户在控制台启用算子时填写 | 管理员在管理后台维护 |
| **定义文件** | 根级 `configuration`（`schema` + 可选 `values`） | 根级 `systemConfiguration`（`schema` + 可选 `values`） |
| **导入平台后** | 用户算子上的 `configuration` | 系统算子上的 `systemConfiguration` |
| **典型用途** | 用户 API Key、默认发件人等 | `serverUrl`、`timeout`、`headers`、`retryPolicy`、`enableGeniSpaceAuth` 等 |

两者均可包含 **`schema`**（表单/校验）与 **`values`**（默认值）。**不要在仓库中提交真实密钥**，`values` 仅用于非敏感默认。

**兼容旧定义**：若只有根级 `configuration` 且 **`schema.type === 'api'`**，平台会把整段当作**系统配置**，没有单独用户块。**新算子建议显式拆分**：用户侧用 `type: 'object'`，系统侧用 `systemConfiguration`（`type: 'api'` 及平台约定字段）。

### 4.5 `metadata`

常用子字段：

- **`configDelivery`**：控制是否在请求 JSON 体中附加 **`__config`** / **`__sysConfig`**（见第 6 节）。
- **`locales.zh`**（等）：多语言名称与描述，导入后供前端按语言展示。

示例（与 SendGrid 一致）：

```javascript
metadata: {
  configDelivery: {
    attachConfig: true,  // 在 POST/PUT/PATCH 的 JSON 体中附加 __config
  },
  locales: {
    zh: {
      name: 'SendGrid 发信',
      description: '在控制台填写密钥与默认发件人',
    },
  },
},
```

### 4.6 根级 `enableGeniSpaceAuth`（可选）

为 `true` 时，平台在调用你的 HTTP 服务时可能附加 **`GeniSpace: <systemApiKey>`** 请求头（具体以导入后的系统配置与执行上下文为准）。本地调试台（`dev-playground`）是否展示 Key 输入区：**仅当算子文件根级** `enableGeniSpaceAuth === true`；**仅方法级** OpenAPI `security: GeniSpaceAuth` 只影响文档，**不会**单独打开调试台 Key 区域。路由侧校验见第 7 节。

### 4.7 `chatPluginByMethod`（可选）

将方法与 Chat 远程插件关联。导出 **definition** 时会合并为方法上的 **`chatPluginConfig`**（含绝对 **`pluginUrl`**）。

Chat 插件静态资源放在算子目录 **`plugins/<slot>/`**（`manifest.json`、入口脚本、可选 `locales/`）：**`<slot>`** 一般与 **`methods[].identifier`** 一致；**多个方法共用同一套前端**时用固定目录名 **`shared`**。`npm run build:plugins` 会输出到 **`public/plugins/<category>/<operator>/plugins/<slot>/`**，与下面 **`pluginPath`** 对齐。

```javascript
chatPluginByMethod: {
  open: {  // key = methods[].identifier（小写）
    enabled: true,
    pluginId: 'web-browser',
    pluginPath: '/static/plugins/web/web-browser/plugins/open/',  // 或 pluginUrl: 'https://.../'
  },
},
```

**启用条件**：**`enabled === true`** 且存在可用的 **`pluginUrl`**（及可选 `pluginId`）时，Chat 会加载远程插件；否则使用默认工具结果视图。导入后以平台上的方法详情为准。  
**插件如何读数据、与 `outputSchema` 的关系**：第 **8.0** 节。  
**`main` / `widget` 分工**：第 **8.3** 节。

### 4.8 `inputSchema` / `outputSchema`、工作流端口（`isPort` / `title`）

**硬性要求**：**`outputSchema` 与路由实际返回的 JSON 形状一致**（成功路径为主；若失败也返回 JSON 体，建议在 Schema 或文档中说明），避免 OpenAPI / 导入预览与运行时脱节。

**工作流优先：扁平业务体（推荐）**  
不强制使用 **`success` / `data` / `error`** 一类信封。很多场景下**直接在顶层返回业务字段**（例如 `{ result, items, count }`）更利于画布连线。是否扁平由产品约定，**以真实 HTTP 响应为准**，`outputSchema` 描述同一套顶层 **`properties`** 即可。

每个算子在各自的 **`<name>.operator.js`** 内**独立、完整**写出 JSON Schema（避免跨文件隐式耦合）。

#### 工作流端口：`isPort` 与 `title`

对需要在工作流画布上作为**可连线端口**展示的字段，在 **`outputSchema.properties`** 里为对应属性设置：

- **`isPort: true`**
- **`title`**：端口短标签（英文，可读即可）
- **`description`**：一句话说明

**扁平响应**时：给**顶层业务字段**（如 **`result`**、**`items`**）标端口即可。

**中文文案**：在 **`metadata.locales.zh.methods[]`** 中按 **`identifier`** 对齐方法，用 **`outputSchema.properties.<字段>.title` / `description`**（及嵌套 **`properties`**）覆盖；键路径与英文 **`inputSchema` / `outputSchema`** 一致即可。导入后由平台合并到展示层。

**输入侧**：在 **`metadata.locales.zh.methods[].inputSchema.properties`**（或算子级 **`metadata.locales.zh.inputSchema`**）补 **`title` / `description`**。

---

## 5. 平台如何合并配置（你需要知道的）

写路由时通常只关心：**最终执行时，用户填的值与方法级覆盖如何叠在一起**。

**`values` 对象合并顺序**（后者覆盖同名键；有系统原型时）：

1. 系统算子 `systemConfiguration.values`
2. 系统方法 `systemConfiguration.values`
3. 用户算子 `configuration.values`
4. 用户方法 `configuration.values`

**无系统原型的自定义算子**：只合并第 3、4 步。

**关于 `headers`**：对 API 类算子，用户侧 `configuration.values.headers`（`{ key, value }[]`）会参与出站请求头的组装；不要假设「系统 headers 与用户 headers 会自动按层合成同一对象」——若你需要特定头，应在定义里写清楚并由控制台配置落到可合并的字段。

---

## 6. 请求体中的 `__config` 与 `__sysConfig`

当算子需要让**你的 HTTP 服务**读取「用户在前端保存的密钥/参数」，但又不希望这些内容出现在工具入参（`inputSchema`）时，使用 **`metadata.configDelivery`**。

### 6.1 `metadata.configDelivery` 字段

系统算子与用户算子的 `configDelivery` **浅合并**，**用户覆盖系统**。

| 字段 | 含义 |
|------|------|
| **`attachConfig`** | 为 `true` 时，在 **POST / PUT / PATCH** 的 JSON 体中加入 **`__config`**，值为用户侧算子+方法 `configuration.values` 合并后、剔除「仅 HTTP 运行时」键之后的快照。 |
| **`attachSystemConfig`** | 为 `true` 且存在非空 **`systemConfigKeys`** 数组时，体中加入 **`__sysConfig`**：从系统侧 `systemConfiguration.values` 合并结果中**按白名单**取键。若当前用户算子**未绑定系统原型**，则**不会产生** `__sysConfig`。 |

### 6.2 不会进入 `__config` 快照的键

下列键仍参与运行时合并，但**不会**复制进 `__config`：

`serverUrl`、`endpoint`、`method`、`headers`、`timeout`、`caching`、`retryPolicy`、`enableGeniSpaceAuth`、`url`。

### 6.3 安全与 HTTP 约束

- 调用方传入的顶层 **`__config`** / **`__sysConfig`** 会被**剥离**，防止伪造。
- **`__config` / `__sysConfig` 仅支持带 JSON 正文的 POST/PUT/PATCH**；若打开了上述开关但 HTTP 方法是 **GET** 等，**执行会失败**。
- **multipart/form-data**：若工作流 REST 节点使用 multipart 且同时开启 `attachConfig` / `attachSystemConfig`，平台侧可能**直接报错**；控制台/API 直连出站一般为 **`application/json`**。需要传文件时请在设计阶段与平台能力对齐。
- 生产环境日志应对敏感字段脱敏；不要在日志中完整打印 `__config`。

### 6.4 GET 请求如何带「业务参数」

未启用 `configDelivery` 出站时，平台对 **GET** 会将工具入参作为 **Query** 发出，**不会**带 `__config`。**需要把用户配置快照放进 body 的算子必须使用 POST/PUT/PATCH**。

### 6.5 路由侧如何读（示意）

与 SendGrid 一致：在 `POST` 处理函数中，**先**解析 JSON，从 **`req.body.__config`** 取用户配置，从 **`req.body`** 其余字段取业务入参：

```javascript
const body = req.body && typeof req.body === 'object' ? req.body : {};
const cfg = body.__config && typeof body.__config === 'object' ? body.__config : {};
const apiKey = cfg.SENDGRID_API_KEY;
// to, subject 等仍在 body 顶层
```

完整逻辑见：`operators/notification/sendgrid/sendgrid.routes.js`。

---

## 7. `*.routes.js`（Express）

- 导出 **`Router`**，由 `app-service.applyTo` 挂到 **`{apiPrefix}/{category}/{name}`**（默认 `apiPrefix=/api`）。
- 需要 JSON 体时使用 `express.json()` 等中间件（与全局 app 一致）。
- 若算子要求 **GeniSpace** 头：使用中间件 **`src/middleware/auth.js`**，接受 **`GeniSpace: <key>`** 或 **`Authorization: GeniSpace <key>`**，校验后 **`req.genispace`** 可用。应用 CORS 的 `allowedHeaders` 需包含 **`GeniSpace`**（本仓库已配）。

---

## 8. 可选：Chat 远程插件

- 插件静态资源由 **`/static/plugins/...`** 提供；definition 中的 **`pluginUrl`** 应对浏览器 **HTTPS** 可访问，跨域时注意 **CORS**。
- 构建产物路径：`public/plugins/<category>/<name>/`。

### 8.0 写插件：props 里有什么？怎么拿到算子输出？

#### `outputSchema` 对应你路由里的哪一段？

- **`outputSchema` 应与 HTTP 实际返回的 JSON 一致**（见 **第 4.8 节**）：可以是**扁平业务对象**。

#### 主插件 `index.js`：宿主会传哪些 props？

Chat 会把工具结果包装后传给插件，你在实现时按下面规则处理 **`props.data`** 即可（不必追踪各服务内部实现）：

1. **`props.data` 常常是「业务 JSON 对象」**：若平台已剥掉 `{ operatorId, methodId, data }` 一类外层，你直接按 `outputSchema` 画的字段读即可。
2. **有时是字符串**：若宿主传入的是 **JSON 字符串**，需 **`typeof props.data === 'string'` 时 `JSON.parse`**，与 `operators/weather/weather-forecast/plugins/forecast/index.js` 一致。
3. **失败态**：**`props.success === false`** 或存在 **`props.error`** 时按错误 UI 处理。注意：**本地调试台**可能固定传 `success: true`，业务失败请**解析 `data` 内字段**（如 `ok: false`）自行判断。

| prop | 作用 |
|------|------|
| **`data`** | 业务负载（对象或需解析的字符串，见上）。 |
| **`success`** / **`error`** | 工具是否成功、错误文案。 |
| **`config.locale`** | 界面语言，文案优先按此分支。 |
| **`config.theme`** | **`light` / `dark`**，明暗样式只读此项。 |
| **`timestamp`**、**`metadata`**、**`compact`**、**`className`**、**`platform`** | 展示与布局用（按需使用）。 |

#### 本地调试台与 Chat 的差异

- 调试台可能把 **`props.data` 固定为字符串**（`JSON.stringify` 后的结果）；插件内应兼容「字符串 / 对象」两种形态。
- 调试台执行插件时**仅注入白名单模块**（如 `react`、`react-dom`、`lucide-react`），**无**任意 npm 包；图标类 UI 优先 **`lucide-react`**。

#### 内联 `widget.js` 和 `index.js` 有什么不同？

- **`index.js`（main）**：主要看 **`props.data`**（规则见上表）。
- **`widget.js`**：主要看 **`props.event`**。天气示例里从 **`event.metadata.result`** 等路径取工具结果再 **`JSON.parse`**，见 **`operators/weather/weather-forecast/plugins/forecast/widget.js`**。

**建议**：把「从任意结构剥到与 **`outputSchema` 一致的业务体」**抽成共用函数，**`index.js`** 与 **`widget.js`** 共用，避免两处规则漂移。

#### 新建插件目录时要有什么？

1. **`plugin/manifest.json`**：至少 `name`、`version`、`minimumChatVersion`；要活动面板就写 **`main": "index.js"`**；要消息里小卡片就写 **`widget": "widget.js"`**（可同时写）。
2. **`index.js`**：CommonJS，`module.exports.default = function MyPlugin(props) { ... }`，第一行通常 `require('react')`。
3. **`widget.js`**（可选）：同样默认导出组件，从 **`props.event`** 取数（见上）。
4. **`*.operator.js`** 里 **`chatPluginByMethod`** 对应方法 **`enabled: true`** + **`pluginPath`**（或 `pluginUrl`）。
5. 跑 **`npm run build`** 或 **`node scripts/build-plugins.js`**，确认 **`public/plugins/...`** 下有对应文件。

### 8.1 与 Chat 语言、明暗主题对齐

编写插件时应**优先读 `props.config.locale` / `props.config.theme`**，再在缺省时回退到 `navigator`，这样与 Chat 顶栏切换一致。**不要只在首次挂载时读一次**：应在渲染中随 props 更新。

### 8.1.1 多语言（构建期注入）

本仓库内带 **`plugin/locales/`** 的远程插件采用**构建期合并 + 运行时解析**。

- **目录**：**`plugin/locales/{locale}.json`**（如 **`en.json`**、**`zh.json`**）。**`en.json` 必填**；缺失时 **`npm run build:plugins`** 会报错退出。
- **内容**：扁平 **`"键": "文案"`**。插件内通过 **`__gsPluginT(__PLUGIN_I18N, props, '键')`** 取文案；缺失时回退 **`en`**。
- **构建**：**`npm run build`** / **`node scripts/build-plugins.js`** 会在输出脚本头部注入 **`__PLUGIN_I18N`** 等；浏览器加载的是 **`public/plugins/...`** 下产物，改 JSON 后需重新 **`npm run build:plugins`**。

### 8.2 消息列表 Artifact 内联 widget（`manifest.widget`）

除 **`main`** 外，可再提供**独立脚本**，用于**同一条助手消息内的产物卡片**（Artifact）。是否展示由 Chat 读取 **`pluginUrl/manifest.json`** 的 **`widget`** 决定。

在 **`plugin/manifest.json`** 中设置 **`widget`**：

- **字符串**：相对 `plugin/` 的文件名（如 **`"widget.js"`**）。
- **`true`**：等价于 **`widget.js`**。
- **省略**：不声明内联脚本。

参考：`operators/weather/weather-forecast/plugin/manifest.json` 与 **`plugin/widget.js`**。

**构建**：**`scripts/build-plugins.js`** 会复制 **`manifest.json`**、存在的 **`main`**、**`widget` 指向的文件**、**`locales/``**。静态 URL：**`GET /static/plugins/<category>/<name>/<文件名>`**。

### 8.3 `main` 与 `widget` 的分工（活动面板 vs 消息内联）

| 字段 | 典型用途 |
|------|-----------|
| **`main`** | 活动面板 / 工具输出主区域：加载该脚本作为 React 根组件。 |
| **`widget`** | **同一条助手消息内**的 Artifact 内联卡片，与过程时间轴分离。 |

**组合**：

1. **`main` + `widget`**：消息里小卡片 + 侧栏详情。
2. **仅有 `widget`**（无 `main`）：**纯内联**——消息里有卡片，活动面板不加载主脚本、避免空白侧栏。
3. **仅有 `main`**：只有主输出路径，无消息内联产物卡片。

**仅内联时的 `manifest.json` 示例**：

```json
{
  "name": "my-operator-inline-only",
  "version": "1.0.0",
  "widget": "widget.js",
  "rendererType": "my-operator-renderer",
  "minimumChatVersion": "1.0.0"
}
```

**自检**：改完 manifest 后 **`npm run build`** 或 **`node scripts/build-plugins.js`**，确认 **`public/plugins/<category>/<name>/`** 下有所需 **`widget.js`** / **`main`** 文件且无 404。

---

## 9. 环境变量（摘要）

| 变量 | 说明 |
|------|------|
| **`PUBLIC_BASE_URL`** | 对外服务根 URL（无尾斜杠），用于 definition 中 **`pluginUrl`** 等绝对地址。 |
| **`OPERATORS_BASE_URL`** | 未设置 `PUBLIC_BASE_URL` 时的回退之一。 |
| **`PORT` / `HOST` / `PROTOCOL`** | 本地默认如 `http://HOST:PORT`。 |
| **`TAVILY_API_KEY`** | （可选）`tavily-search` 算子使用；未配置时部分行为为演示占位。 |

---

## 10. 本地联调

1. **`npm install && npm run build && npm start`**（默认 **8080**）；`build` 会执行插件复制。
2. **`npm run dev`**：同时起算子服务与 Vite 调试台（常见 **http://localhost:18080**），将 **`/api`**、**`/static`** 代理到 **8080**。
3. 在调试台按方法与 Schema 试跑；需要 GeniSpace 认证的算子在调试台填入 **API Key**（见第 4.6 节）。
4. 从首页复制 **definition** URL，到平台控制面导入；带插件的方法检查 **`chatPluginConfig.pluginUrl`** 是否可在浏览器访问。

**手测 GeniSpace 认证（调试台）**：

1. 打开 `npm run dev` 后的调试台。
2. 选择根级 **`enableGeniSpaceAuth === true`** 的算子：应对**该算子下所有方法**显示 Key 输入区；填错 Key 时路由应返回 **401**。
3. 未声明根级认证的算子：调试台不展示 Key 区；**不应**因仅方法级 `security: GeniSpaceAuth` 而出现 Key 区。

---

## 11. 生产部署（摘要）

- **`PUBLIC_BASE_URL` / `OPERATORS_BASE_URL`** 设为浏览器实际访问的对外根，使 **`pluginUrl`** 与 Chat 页面 **协议、主机、路径前缀** 一致或正确配置 **CORS**。
- 网关以子路径转发（如 `/operators/internal`）时，可设置环境变量 **`INGRESS_STRIP_PREFIX`**（映射为 `src/config/env.js` 的 `ingressStripPrefix`），由 `src/index.js` 在路由匹配前剥掉前缀，应用内仍按 **`/api`**、**`/static`**、**`/health`** 处理。
- 镜像与 CI：见本仓库 **`Dockerfile`**、**`.github/workflows`**。

---

## 12. 仓库内可参考的完整示例

下列目录在本仓库提供 **HTTP 算子 + 可选远程插件**，适合对照实现：

| 场景 | 算子目录 |
|------|----------|
| 浏览器打开网页 | `operators/web/web-browser` |
| 搜索 | `operators/search/tavily-search` |
| 天气 | `operators/weather/weather-forecast` |
| URL 跳转 / iframe / HTML 图表等 | `operators/web/url-redirect`、`operators/web/iframe-embed`、`operators/web/html-renderer` |
| 平台信息示例 | `operators/platform/genispace-info` |

---

## 13. 自检清单（发布前）

- [ ] `methods` 中 `path`、`httpMethod`、`identifier` 唯一且与路由实现一致。
- [ ] 密钥仅出现在 **`configuration`** +（如需）**`attachConfig`**，**未**出现在 `inputSchema`。
- [ ] 若使用 **`attachConfig`**：HTTP 方法为 **POST/PUT/PATCH**，且与设计上的 multipart 限制一致。
- [ ] **`outputSchema` 与路由实际返回的 JSON 一致**；需要连线的字段已标 **`isPort: true`** 并配有 **`title`**（英）及 **`metadata.locales.zh.methods[]` 中对应文案**（中）。含 Chat 插件时按第 **8.0** 节验证剥壳与渲染。
- [ ] 需要平台系统 Key 时：根级 **`enableGeniSpaceAuth`** 与说明一致。
- [ ] 含插件时：**`pluginUrl`** 在生产可访问，CORS 正确。
- [ ] 需要**消息列表 Artifact 内联**时：`plugin/manifest.json` 含 **`widget`** 且构建产物中存在对应脚本；本地可 **`GET /static/plugins/<category>/<name>/widget.js`**（或 manifest 中声明的文件名）确认非 404。
- [ ] 若**只需要内联卡片、不需要活动面板**：可省略 **`main`**，并确认第 **8.3** 节行为符合预期；若**需要侧栏详情**，则 **`main` 非空**且产物中存在该入口文件。
- [ ] 含插件且有多语言或明暗主题时：插件已按 **`props.config.locale` / `props.config.theme`** 渲染，并在 Chat 内切换后验证同步。
- [ ] 本地 **`npm test`** / 手工调用关键路径通过。

---

**图示说明**：若仓库内其他文档含 **Mermaid** 图，在支持 Mermaid 的阅读器中可渲染；本指南以文字步骤为主，便于单独跟随完成算子开发。
