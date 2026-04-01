module.exports = {
  info: {
    name: 'weather-forecast',
    title: 'Weather forecast (Open-Meteo)',
    description: 'Weather forecast from Open-Meteo (geocoding + forecast API).',
    version: '1.1.0',
    category: 'weather',
    tags: ['weather', 'builtin-parity']
  },
  metadata: {
    locales: {
      zh: {
        name: '天气预报（Open-Meteo）',
        description: '基于 Open-Meteo 的地理位置与天气预报数据。',
        methods: [
          {
            identifier: 'forecast',
            name: '查询天气预报',
            description:
              '根据地点名称查询当前天气与多日预报（Open-Meteo 地理编码 + 预报接口）。业务失败时 HTTP 仍为 200，响应体在 `data` 内且 `ok` 为 false，请根据 `error_code` / `error_message` 分支处理。',
            inputSchema: {
              description: '必填 `location`；可选 `days` 指定预报天数（1–7，默认 3）。',
              properties: {
                location: {
                  title: '地点',
                  description: '城市或地名（将用于地理编码解析经纬度）'
                },
                days: {
                  title: '预报天数',
                  description: '返回的每日预报条数，范围 1–7，默认 3'
                }
              }
            },
            outputSchema: {
              description:
                '位于 HTTP 响应 `data` 内（外层另有 `success`、`data`、`timestamp` 等）。必含布尔字段 `ok`：`ok` 为 true 时含位置、当前天气、`daily` 等；为 false 时依赖 `error_code`、`error_message` 及可选 `error_details`。',
              properties: {
                ok: {
                  title: '是否成功',
                  description: 'true：已返回预报；false：输入无效、未找到地点或上游错误，见 error_* 字段'
                },
                error_code: {
                  title: '错误码',
                  description: '机器可读错误码（如 INVALID_INPUT、NOT_FOUND、UPSTREAM_ERROR），仅在 ok 为 false 时有意义'
                },
                error_message: {
                  title: '错误说明',
                  description: '英文错误文案，供模型推理与界面展示（可与插件内 i18n 配合）'
                },
                error_details: {
                  title: '错误详情',
                  description: '可选结构化上下文（如 location_query、field、phase、status）'
                },
                location: {
                  title: '解析后的地点',
                  description: 'ok 为 true 时已解析的地点信息',
                  properties: {
                    name: { title: '名称', description: '地点名称' },
                    country: { title: '国家', description: '国家' },
                    admin: { title: '行政区', description: '一级行政区' },
                    latitude: { title: '纬度', description: '纬度' },
                    longitude: { title: '经度', description: '经度' }
                  }
                },
                current: {
                  title: '当前天气',
                  description: 'ok 为 true 时的当前气象',
                  properties: {
                    temperature: { title: '气温', description: '气温' },
                    temperature_unit: { title: '气温单位', description: '气温单位' },
                    apparent_temperature: { title: '体感温度', description: '体感温度' },
                    humidity: { title: '相对湿度', description: '相对湿度' },
                    wind_speed: { title: '风速', description: '风速' },
                    wind_speed_unit: { title: '风速单位', description: '风速单位' },
                    weather_code: { title: '天气代码', description: 'WMO 天气代码' },
                    weather_description: { title: '天气描述', description: '天气现象文字说明' }
                  }
                },
                daily: {
                  title: '每日预报',
                  description: 'ok 为 true 时的逐日预报列表',
                  items: {
                    properties: {
                      date: { title: '日期', description: '日期' },
                      temp_max: { title: '最高温', description: '最高温度' },
                      temp_min: { title: '最低温', description: '最低温度' },
                      temp_unit: { title: '温度单位', description: '温度单位' },
                      precipitation: { title: '降水量', description: '降水量' },
                      precipitation_unit: { title: '降水单位', description: '降水单位' },
                      wind_speed_max: { title: '最大风速', description: '最大风速' },
                      wind_speed_unit: { title: '风速单位', description: '风速单位' },
                      weather_code: { title: '天气代码', description: 'WMO 天气代码' },
                      weather_description: { title: '天气描述', description: '天气现象文字说明' }
                    }
                  }
                },
                timezone: {
                  title: '时区',
                  description: 'IANA 时区标识（ok 为 true 时）'
                }
              }
            }
          }
        ]
      }
    }
  },
  routes: './weather-forecast.routes.js',
  chatPluginByMethod: {
    forecast: {
      enabled: true,
      pluginId: 'weather-forecast',
      pluginPath: '/static/plugins/weather/weather-forecast/plugins/forecast/'
    }
  },
  methods: [
    {
      identifier: 'forecast',
      name: 'Query weather forecast',
      description:
        'Geocode a place name and return current conditions plus daily rows from Open-Meteo. On business failure the HTTP status stays 200 and the payload in `data` has `ok: false`; use `error_code` / `error_message` to branch.',
      path: '/forecast',
      httpMethod: 'POST',
      tags: ['Weather'],
      inputSchema: {
        type: 'object',
        title: 'Weather forecast request',
        description: 'Requires `location`; optional `days` (1–7, default 3).',
        required: ['location'],
        properties: {
          location: {
            type: 'string',
            title: 'Location',
            description: 'City or place name (used for geocoding)'
          },
          days: {
            type: 'integer',
            minimum: 1,
            maximum: 7,
            default: 3,
            title: 'Forecast days',
            description: 'Number of daily forecast rows to return'
          }
        }
      },
      outputSchema: {
        type: 'object',
        title: 'Weather forecast result',
        description:
          'Payload inside the HTTP `data` field (envelope is `{ success, data, timestamp }`). Always includes boolean `ok`. When `ok` is true, weather fields are populated. When `ok` is false, use `error_code`, `error_message`, and optional `error_details` so callers and models can branch without relying on HTTP status or oneOf schemas.',
        required: ['ok'],
        properties: {
          ok: {
            type: 'boolean',
            title: 'OK',
            description: 'true: forecast returned; false: business or upstream failure described by error_* fields.'
          },
          error_code: {
            type: 'string',
            title: 'Error code',
            description: 'Stable machine-readable code when ok is false.',
            enum: ['INVALID_INPUT', 'NOT_FOUND', 'UPSTREAM_ERROR']
          },
          error_message: {
            type: 'string',
            title: 'Error message',
            description: 'English message suitable for model reasoning and user-facing UI.'
          },
          error_details: {
            type: 'object',
            title: 'Error details',
            description: 'Optional structured context (e.g. location_query, field, phase, status).',
            additionalProperties: true
          },
          location: {
            type: 'object',
            title: 'Resolved location',
            description: 'Resolved place when ok is true.',
            properties: {
              name: { type: 'string', title: 'Name', description: 'Place name' },
              country: { type: 'string', title: 'Country', description: 'Country' },
              admin: {
                type: 'string',
                title: 'Admin area',
                description: 'First-level administrative division'
              },
              latitude: { type: 'number', title: 'Latitude', description: 'Latitude' },
              longitude: { type: 'number', title: 'Longitude', description: 'Longitude' }
            }
          },
          current: {
            type: 'object',
            title: 'Current conditions',
            description: 'Current conditions when ok is true.',
            properties: {
              temperature: { type: 'number', title: 'Temperature', description: 'Air temperature' },
              temperature_unit: { type: 'string', title: 'Temperature unit', description: 'Unit for temperature' },
              apparent_temperature: {
                type: 'number',
                title: 'Apparent temperature',
                description: 'Feels-like temperature'
              },
              humidity: { type: 'number', title: 'Humidity', description: 'Relative humidity' },
              wind_speed: { type: 'number', title: 'Wind speed', description: 'Wind speed' },
              wind_speed_unit: { type: 'string', title: 'Wind speed unit', description: 'Unit for wind speed' },
              weather_code: { type: 'integer', title: 'Weather code', description: 'WMO weather code' },
              weather_description: {
                type: 'string',
                title: 'Weather description',
                description: 'Human-readable weather label'
              }
            }
          },
          daily: {
            type: 'array',
            title: 'Daily forecast',
            description: 'Daily rows when ok is true.',
            items: {
              type: 'object',
              properties: {
                date: { type: 'string', title: 'Date', description: 'Forecast date' },
                temp_max: { type: 'number', title: 'Max temperature', description: 'Daily maximum temperature' },
                temp_min: { type: 'number', title: 'Min temperature', description: 'Daily minimum temperature' },
                temp_unit: { type: 'string', title: 'Temperature unit', description: 'Unit for temperatures' },
                precipitation: { type: 'number', title: 'Precipitation', description: 'Precipitation amount' },
                precipitation_unit: {
                  type: 'string',
                  title: 'Precipitation unit',
                  description: 'Unit for precipitation'
                },
                wind_speed_max: { type: 'number', title: 'Max wind speed', description: 'Daily maximum wind speed' },
                wind_speed_unit: { type: 'string', title: 'Wind speed unit', description: 'Unit for wind speed' },
                weather_code: { type: 'integer', title: 'Weather code', description: 'WMO weather code' },
                weather_description: {
                  type: 'string',
                  title: 'Weather description',
                  description: 'Human-readable weather label'
                }
              }
            }
          },
          timezone: {
            type: 'string',
            title: 'Timezone',
            description: 'IANA timezone when ok is true'
          }
        }
      }
    }
  ]
};
