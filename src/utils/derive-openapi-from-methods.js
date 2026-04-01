'use strict';

const { operatorMethods, openapiComponentsForDerive } = require('./operator-definition');

/**
 * Derive OpenAPI paths (and optional components.schemas) from methods[].
 * Discovery injects `config.openapi` when loading the operator module.
 *
 * @param {object} config operator module.exports (root `methods` or legacy `genispace.methods`)
 * @returns {{ paths: object, components?: { schemas: object } }}
 */
function deriveOpenApiFromConfig(config) {
  const info = config.info || {};
  const methods = operatorMethods(config);
  if (methods.length === 0) {
    throw new Error(`Operator ${info.name || '?'} has no methods (root or genispace.methods)`);
  }

  const paths = {};
  const schemas = {};
  const openapiComponents = openapiComponentsForDerive(config);
  if (openapiComponents?.schemas) {
    Object.assign(schemas, openapiComponents.schemas);
  }

  const defaultTag = info.title || info.name || 'operator';

  for (const m of methods) {
    const pathKey = m.path && String(m.path).startsWith('/') ? m.path : `/${m.path || ''}`;
    const httpLower = String(m.httpMethod || 'POST').toLowerCase();
    if (!paths[pathKey]) {
      paths[pathKey] = {};
    }

    const inputSchema =
      m.inputSchema !== undefined ? m.inputSchema : { type: 'object', properties: {} };
    const bodyRequired = m.requestBodyRequired === false ? false : true;

    const op = {
      operationId: m.identifier,
      summary: m.name,
      description: m.description != null ? m.description : '',
      tags: Array.isArray(m.tags) && m.tags.length > 0 ? m.tags : [defaultTag]
    };
    if (m.security) {
      op.security = m.security;
    }

    op.requestBody = {
      required: bodyRequired,
      content: {
        'application/json': {
          schema: inputSchema
        }
      }
    };

    const outputSchema =
      m.outputSchema !== undefined ? m.outputSchema : { type: 'object', properties: {} };
    op.responses = {
      '200': {
        description: 'OK',
        content: {
          'application/json': {
            schema: outputSchema
          }
        }
      }
    };

    if (m.additionalResponses && typeof m.additionalResponses === 'object') {
      for (const [code, resp] of Object.entries(m.additionalResponses)) {
        if (!resp || typeof resp !== 'object') {
          continue;
        }
        const entry = { description: resp.description || '' };
        if (resp.schema) {
          entry.content = {
            'application/json': {
              schema: resp.schema
            }
          };
        }
        op.responses[String(code)] = entry;
      }
    }

    paths[pathKey][httpLower] = op;
  }

  const result = { paths };
  if (Object.keys(schemas).length > 0) {
    result.components = { schemas };
  }
  return result;
}

module.exports = { deriveOpenApiFromConfig };
