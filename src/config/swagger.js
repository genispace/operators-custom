/**
 * Swagger / OpenAPI 3.0 base document: info, servers, security schemes, reusable schemas,
 * common responses, and tag grouping for the operators service.
 */

const config = require('./env');

const swaggerConfig = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'GeniSpace Custom Operators API',
      version: '1.0.0',
      description: `
Lightweight GeniSpace custom operators API.

## Features

- **Auto-discovery**: scan and load operator modules
- **OpenAPI 3.0**: standard API documentation
- **Pluggable**: hot-pluggable operator development
- **Container-ready**: Docker-friendly deployment
- **Platform integration**: importable into GeniSpace

## Operator categories

- **text-processing**, **data-transform**, **notification**, **file-processing**
- **api-integration**, **validation**, **utility**

## Authentication

### GeniSpace

Protected operators require a valid GeniSpace API key:

\`\`\`
Authorization: GeniSpace <your-api-key>
\`\`\`

### Public endpoints

- \`${config.apiPrefix}\` — home
- \`/health\` — health check
- \`${config.apiPrefix}/docs\` — Swagger UI
- \`${config.apiPrefix}/docs.json\` — OpenAPI JSON
- \`${config.apiPrefix}/operators\` — operator list
- \`${config.apiPrefix}/operators/:category/:operator/definition\` — operator definition

## Errors

Responses use a consistent shape: code, message, and timestamp.

## Rate limiting

Default: 15-minute window, 100 requests per IP. Exceeded limits return HTTP 429.
      `,
      termsOfService: 'https://genispace.com/terms',
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
    servers: [
      {
        url: process.env.API_BASE_URL || `http://localhost:${config.port}`,
        description: 'Development server'
      }
    ],
    components: {
      securitySchemes: {
        GeniSpaceAuth: {
          type: 'apiKey',
          in: 'header',
          name: 'Authorization',
          description: 'GeniSpace API key. Format: GeniSpace <your-api-key>'
        }
      },
      
      schemas: {
        // Standard success envelope (success + data + timestamp)
        SuccessResponse: {
          type: 'object',
          required: ['success', 'data', 'timestamp'],
          properties: {
            success: {
              type: 'boolean',
              example: true,
              description: 'Whether the request succeeded'
            },
            data: {
              type: 'object',
              description: 'Response payload'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'Response timestamp',
              example: '2025-01-01T12:00:00.000Z'
            }
          }
        },

        // Standard error envelope
        ErrorResponse: {
          type: 'object',
          required: ['success', 'error', 'timestamp'],
          properties: {
            success: {
              type: 'boolean',
              example: false,
              description: 'Whether the request succeeded'
            },
            error: {
              type: 'string',
              description: 'Error message',
              example: 'Parameter validation failed'
            },
            code: {
              type: 'string',
              description: 'Error code',
              example: 'VALIDATION_ERROR'
            },
            details: {
              type: 'object',
              description: 'Error details'
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'Error timestamp',
              example: '2025-01-01T12:00:00.000Z'
            }
          }
        },

        // GET /health payload shape
        HealthResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: true
            },
            data: {
              type: 'object',
              properties: {
                status: {
                  type: 'string',
                  example: 'healthy',
                  description: 'Service status'
                },
                uptime: {
                  type: 'number',
                  description: 'Uptime in seconds',
                  example: 3600
                },
                timestamp: {
                  type: 'string',
                  format: 'date-time',
                  description: 'Check timestamp'
                },
                version: {
                  type: 'string',
                  description: 'Service version',
                  example: '1.0.0'
                },
                environment: {
                  type: 'string',
                  description: 'Runtime environment',
                  example: 'production'
                },
                memory: {
                  type: 'object',
                  description: 'Memory usage',
                  properties: {
                    rss: { type: 'number' },
                    heapTotal: { type: 'number' },
                    heapUsed: { type: 'number' },
                    external: { type: 'number' }
                  }
                },
                operators: {
                  type: 'object',
                  description: 'Operator statistics',
                  properties: {
                    loaded: {
                      type: 'integer',
                      description: 'Number of loaded operators'
                    },
                    categories: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Operator categories'
                    },
                    endpoints: {
                      type: 'integer',
                      description: 'Number of API endpoints'
                    }
                  }
                }
              }
            }
          }
        },

        // Single operator summary for catalog responses
        OperatorInfo: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Operator name',
              example: 'string-utils'
            },
            title: {
              type: 'string',
              description: 'Operator title',
              example: 'String utilities'
            },
            description: {
              type: 'string',
              description: 'Operator description',
              example: 'Provides string utilities'
            },
            version: {
              type: 'string',
              description: 'Operator version',
              example: '1.0.0'
            },
            category: {
              type: 'string',
              description: 'Operator category',
              example: 'text-processing'
            },
            tags: {
              type: 'array',
              items: { type: 'string' },
              description: 'Operator tags',
              example: ['string', 'text', 'utility']
            },
            author: {
              type: 'string',
              description: 'Operator author',
              example: 'genispace.com Dev Team'
            },
            endpoints: {
              type: 'array',
              items: { type: 'string' },
              description: 'API endpoint list',
              example: [`${config.apiPrefix}/text-processing/string-utils/format`]
            }
          }
        },

        // Operator registry list wrapper
        OperatorListResponse: {
          type: 'object',
          properties: {
            success: {
              type: 'boolean',
              example: true
            },
            data: {
              type: 'object',
              properties: {
                operators: {
                  type: 'array',
                  items: { $ref: '#/components/schemas/OperatorInfo' },
                  description: 'Operator list'
                },
                total: {
                  type: 'integer',
                  description: 'Total operators',
                  example: 8
                },
                categories: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Category list',
                  example: ['text-processing', 'data-transform', 'notification']
                },
                endpoints: {
                  type: 'integer',
                  description: 'Total API endpoints',
                  example: 15
                }
              }
            }
          }
        }
      },

      // Reusable HTTP problem responses (referenced by route specs)
      responses: {
        BadRequest: {
          description: 'Bad request',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' },
              example: {
                success: false,
                error: 'Request parameters are missing or invalid',
                code: 'BAD_REQUEST',
                timestamp: '2025-01-01T12:00:00.000Z'
              }
            }
          }
        },
        
        NotFound: {
          description: 'Resource not found',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' },
              example: {
                success: false,
                error: 'The requested resource does not exist',
                code: 'NOT_FOUND',
                timestamp: '2025-01-01T12:00:00.000Z'
              }
            }
          }
        },
        
        InternalServerError: {
          description: 'Internal server error',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' },
              example: {
                success: false,
                error: 'Internal server error; try again later',
                code: 'INTERNAL_ERROR',
                timestamp: '2025-01-01T12:00:00.000Z'
              }
            }
          }
        },
        
        RateLimitExceeded: {
          description: 'Rate limit exceeded',
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ErrorResponse' },
              example: {
                success: false,
                error: 'Too many requests; try again later',
                code: 'RATE_LIMIT_EXCEEDED',
                timestamp: '2025-01-01T12:00:00.000Z'
              }
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
      },
      
      parameters: {
        // Path param shared by operator-scoped routes
        CategoryParam: {
          name: 'category',
          in: 'path',
          required: true,
          description: 'Operator category',
          schema: {
            type: 'string',
            enum: ['text-processing', 'data-transform', 'notification', 'file-processing', 'api-integration', 'validation', 'utility']
          },
          example: 'text-processing'
        }
      }
    },
    
    tags: [
      {
        name: 'System',
        description: 'System APIs'
      },
      {
        name: 'Operators',
        description: 'Operator management APIs'
      },
      {
        name: 'Text Processing',
        description: 'Text processing operators'
      },
      {
        name: 'Data Transform',
        description: 'Data transform operators'
      },
      {
        name: 'Notification',
        description: 'Notification operators'
      },
      {
        name: 'File Processing',
        description: 'File processing operators'
      },
      {
        name: 'API Integration',
        description: 'API integration operators'
      },
      {
        name: 'Validation',
        description: 'Validation operators'
      },
      {
        name: 'Utility',
        description: 'Utility operators'
      }
    ]
  },
  
  apis: [
    './src/index.js',
    './operators/**/*.js'
  ]
};

module.exports = swaggerConfig;
