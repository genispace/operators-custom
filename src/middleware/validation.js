/** Joi-based request validation middleware */

const Joi = require('joi');
const logger = require('../utils/logger');
const { ValidationError } = require('./error');
const { sendValidationErrorResponse } = require('../utils/response');

/** @param {string} target 'body' | 'query' | 'params' | 'headers' */
function createValidator(schema, target = 'body') {
  return (req, res, next) => {
    const dataToValidate = req[target];
    
    const { error, value } = schema.validate(dataToValidate, {
      abortEarly: false, // return all field errors, not just the first
      allowUnknown: true,
      stripUnknown: true
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));
      
      logger.warn('Request validation failed', {
        requestId: req.requestId,
        target,
        errors,
        originalData: dataToValidate
      });
      
      return sendValidationErrorResponse(res, errors);
    }

    // Normalized + coerced values (unknown keys stripped when stripUnknown)
    req[target] = value;
    
    next();
  };
}

const commonSchemas = {
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().optional(),
    order: Joi.string().valid('asc', 'desc').default('asc')
  }),
  id: Joi.object({
    id: Joi.string().required()
  }),
  category: Joi.object({
    category: Joi.string().required()
  })
};

const validators = {
  validatePagination: createValidator(commonSchemas.pagination, 'query'),
  validateId: createValidator(commonSchemas.id, 'params'),
  validateCategory: createValidator(commonSchemas.category, 'params'),
  validateNotEmpty: (req, res, next) => {
    if (!req.body || Object.keys(req.body).length === 0) {
      return sendValidationErrorResponse(res, [{
        field: 'body',
        message: 'Request body cannot be empty',
        value: req.body
      }]);
    }
    next();
  }
};

const customJoi = Joi.extend((joi) => ({
  type: 'string',
  base: joi.string(),
  messages: {
    'string.alphanum': '{{#label}} must contain only letters and numbers',
    'string.identifier': '{{#label}} must be a valid identifier (letters, digits, hyphen, underscore)'
  },
  rules: {
    identifier: {
      validate(value, helpers) {
        if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
          return helpers.error('string.identifier');
        }
        return value;
      }
    }
  }
}));

const operatorSchemas = {
  operatorInfo: Joi.object({
    name: customJoi.string().identifier().required()
      .messages({
        'any.required': 'Operator name is required',
        'string.empty': 'Operator name cannot be empty'
      }),
    title: Joi.string().min(1).max(100).required()
      .messages({
        'any.required': 'Operator title is required',
        'string.min': 'Operator title cannot be empty',
        'string.max': 'Operator title cannot exceed 100 characters'
      }),
    description: Joi.string().min(1).max(500).required()
      .messages({
        'any.required': 'Operator description is required',
        'string.min': 'Operator description cannot be empty',
        'string.max': 'Operator description cannot exceed 500 characters'
      }),
    version: Joi.string().pattern(/^\d+\.\d+\.\d+$/).required()
      .messages({
        'any.required': 'Operator version is required',
        'string.pattern.base': 'Version must be in x.y.z format'
      }),
    category: Joi.string().optional(),
    tags: Joi.array().items(Joi.string()).optional(),
    author: Joi.string().optional()
  }),
  endpoint: Joi.object({
    path: Joi.string().required()
      .messages({
        'any.required': 'Endpoint path is required'
      }),
    method: Joi.string().valid('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD').required()
      .messages({
        'any.required': 'HTTP method is required',
        'any.only': 'HTTP method must be a valid verb'
      }),
    summary: Joi.string().min(1).max(200).required()
      .messages({
        'any.required': 'Endpoint summary is required',
        'string.min': 'Endpoint summary cannot be empty',
        'string.max': 'Endpoint summary cannot exceed 200 characters'
      }),
    description: Joi.string().optional(),
    operationId: Joi.string().optional(),
    requestBody: Joi.object().optional(),
    responses: Joi.object().optional(),
    parameters: Joi.array().optional()
  })
};

function validateRequest(req, schema, target = 'body') {
  const { error, value } = schema.validate(req[target], {
    abortEarly: false,
    allowUnknown: true,
    stripUnknown: true
  });
  
  if (error) {
    const errors = error.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message,
      value: detail.context?.value
    }));
    
    return { valid: false, errors };
  }
  
  return { valid: true, value };
}

function createDynamicValidator(getSchema, target = 'body') {
  return (req, res, next) => {
    try {
      const schema = getSchema(req);
      if (!schema) {
        return next();
      }
      
      const result = validateRequest(req, schema, target);
      
      if (!result.valid) {
        logger.warn('Dynamic validation failed', {
          requestId: req.requestId,
          target,
          errors: result.errors
        });
        
        return sendValidationErrorResponse(res, result.errors);
      }
      
      req[target] = result.value;
      next();
    } catch (error) {
      logger.error('Dynamic validation error', {
        requestId: req.requestId,
        error: error.message
      });
      
      next(error);
    }
  };
}

function createConditionalValidator(condition, schema, target = 'body') {
  return (req, res, next) => {
    if (condition(req)) {
      return createValidator(schema, target)(req, res, next);
    }
    next();
  };
}

module.exports = {
  createValidator,
  createDynamicValidator,
  createConditionalValidator,
  validators,
  commonSchemas,
  operatorSchemas,
  customJoi,
  validateRequest
};
