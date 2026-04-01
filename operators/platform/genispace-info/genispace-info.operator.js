/**
 * GeniSpace platform info operator — demonstrates GeniSpace SDK usage.
 */

module.exports = {
  info: {
    name: 'genispace-info',
    title: 'GeniSpace platform information',
    description:
      'Returns the authenticated user’s GeniSpace profile, statistics, teams, and agents.',
    version: '1.0.0',
    category: 'platform',
    tags: ['genispace', 'user', 'platform', 'info']
  },

  /** 与平台 Admin systemConfiguration.enableGeniSpaceAuth 同名；Worker 在启用时发送 GeniSpace 头 */
  enableGeniSpaceAuth: true,

  metadata: {
    locales: {
      zh: {
        name: 'GeniSpace平台信息',
        description: '获取当前用户的GeniSpace平台信息，包括用户资料、团队、智能体等',
        methods: [
          {
            identifier: 'postuserprofile',
            name: '获取用户资料',
            description: '获取当前认证用户的详细资料信息'
          },
          {
            identifier: 'postagents',
            name: '获取用户智能体列表',
            description: '获取当前用户可访问的智能体列表'
          }
        ]
      }
    }
  },

  routes: './genispace-info.routes.js',

  openapiComponents: {
    schemas: {
      ErrorResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: false },
          error: { type: 'string' },
          code: { type: 'string' },
          message: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' }
        }
      }
    }
  },
  methods: [
    {
      identifier: 'postuserprofile',
      name: 'Get user profile',
      description: 'Returns the current authenticated user’s profile details.',
      path: '/user-profile',
      httpMethod: 'POST',
      tags: ['GeniSpaceInfo'],
      security: [{ GeniSpaceAuth: [] }],
      requestBodyRequired: false,
      inputSchema: {
        type: 'object',
        properties: {
          includeStatistics: {
            type: 'boolean',
            description: 'Include usage statistics',
            default: true
          },
          includeTeams: {
            type: 'boolean',
            description: 'Include team list',
            default: true
          }
        }
      },
      outputSchema: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          data: {
            type: 'object',
            properties: {
              user: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  email: { type: 'string' },
                  name: { type: 'string' },
                  company: { type: 'string' },
                  createdAt: { type: 'string' }
                }
              },
              statistics: {
                type: 'object',
                properties: {
                  tasksCreated: { type: 'number' },
                  tasksCompleted: { type: 'number' },
                  agentsCount: { type: 'number' },
                  teamsCount: { type: 'number' }
                }
              },
              teams: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    role: { type: 'string' },
                    isActive: { type: 'boolean' }
                  }
                }
              }
            }
          }
        }
      },
      additionalResponses: {
        '401': {
          description: 'Authentication failed',
          schema: { $ref: '#/components/schemas/ErrorResponse' }
        }
      }
    },
    {
      identifier: 'postagents',
      name: 'List user agents',
      description: 'Returns agents accessible to the current user.',
      path: '/agents',
      httpMethod: 'POST',
      tags: ['GeniSpaceInfo'],
      security: [{ GeniSpaceAuth: [] }],
      requestBodyRequired: false,
      inputSchema: {
        type: 'object',
        properties: {
          page: {
            type: 'number',
            description: 'Page number',
            default: 1,
            minimum: 1
          },
          limit: {
            type: 'number',
            description: 'Page size',
            default: 10,
            minimum: 1,
            maximum: 100
          },
          agentType: {
            type: 'string',
            description: 'Agent type filter',
            enum: ['CHAT', 'TASK'],
            nullable: true
          }
        }
      },
      outputSchema: {
        type: 'object',
        properties: {
          success: { type: 'boolean', example: true },
          data: {
            type: 'object',
            properties: {
              agents: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    name: { type: 'string' },
                    description: { type: 'string' },
                    agentType: { type: 'string' },
                    model: { type: 'string' },
                    createdAt: { type: 'string' }
                  }
                }
              },
              pagination: {
                type: 'object',
                properties: {
                  currentPage: { type: 'number' },
                  totalPages: { type: 'number' },
                  totalItems: { type: 'number' },
                  itemsPerPage: { type: 'number' }
                }
              }
            }
          }
        }
      }
    }
  ]
};
