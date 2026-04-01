/**
 * Error handling middleware
 *
 * Centralized application error handling
 */

const logger = require('../utils/logger');
const { createErrorResponse, HttpStatus, ErrorCodes } = require('../utils/response');

/**
 * Global error handler
 * @param {Error} error
 * @param {object} req
 * @param {object} res
 * @param {function} next
 */
function errorHandler(error, req, res, next) {
  // Avoid double-send; delegate to Express default handler
  if (res.headersSent) {
    return next(error);
  }

  logger.error('Application Error', {
    message: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
  let errorCode = ErrorCodes.INTERNAL_ERROR;
  let errorMessage = 'Internal server error';
  let details = null;

  // Classify by error shape (Joi, Mongoose-style, custom codes, body-parser, etc.)
  if (error.name === 'ValidationError') {
    statusCode = HttpStatus.BAD_REQUEST;
    errorCode = ErrorCodes.VALIDATION_ERROR;
    errorMessage = 'Request validation failed';
    details = error.details || error.message;
  } else if (error.name === 'CastError') {
    statusCode = HttpStatus.BAD_REQUEST;
    errorCode = ErrorCodes.INVALID_PARAMETER;
    errorMessage = 'Invalid parameter format';
  } else if (error.name === 'UnauthorizedError') {
    statusCode = HttpStatus.UNAUTHORIZED;
    errorCode = ErrorCodes.UNAUTHORIZED;
    errorMessage = 'Unauthorized';
  } else if (error.code === 'OPERATOR_NOT_FOUND') {
    statusCode = HttpStatus.NOT_FOUND;
    errorCode = ErrorCodes.OPERATOR_NOT_FOUND;
    errorMessage = error.message || 'Operator not found';
  } else if (error.code === 'OPERATOR_EXECUTION_ERROR') {
    statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    errorCode = ErrorCodes.OPERATOR_EXECUTION_ERROR;
    errorMessage = error.message || 'Operator execution failed';
    details = error.details;
  } else if (error.statusCode || error.status) {
    // AppError and similar attach statusCode / code
    statusCode = error.statusCode || error.status;
    errorMessage = error.message;
    errorCode = error.code || ErrorCodes.INTERNAL_ERROR;
    details = error.details;
  } else if (error.type === 'entity.parse.failed') {
    statusCode = HttpStatus.BAD_REQUEST;
    errorCode = ErrorCodes.BAD_REQUEST;
    errorMessage = 'Invalid JSON body';
  } else if (error.type === 'entity.too.large') {
    statusCode = HttpStatus.BAD_REQUEST;
    errorCode = ErrorCodes.BAD_REQUEST;
    errorMessage = 'Request body too large';
  }

  // Surface stack trace when nothing else was attached (local debugging only)
  if (process.env.NODE_ENV === 'development') {
    details = details || {
      stack: error.stack,
      originalError: error.message
    };
  }

  res.status(statusCode).json(createErrorResponse(errorMessage, errorCode, details));
}

/**
 * 404 handler
 */
function notFoundHandler(req, res, next) {
  logger.warn('404 Not Found', {
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(HttpStatus.NOT_FOUND).json(createErrorResponse(
    'Resource not found',
    ErrorCodes.NOT_FOUND,
    {
      path: req.originalUrl,
      method: req.method
    }
  ));
}

class AppError extends Error {
  constructor(message, statusCode = HttpStatus.INTERNAL_SERVER_ERROR, code = ErrorCodes.INTERNAL_ERROR, details = null) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends Error {
  constructor(message, errors = []) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = HttpStatus.BAD_REQUEST;
    this.code = ErrorCodes.VALIDATION_ERROR;
    this.details = errors;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

class OperatorError extends Error {
  constructor(message, operatorName, details = null) {
    super(message);
    this.name = 'OperatorError';
    this.statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    this.code = ErrorCodes.OPERATOR_EXECUTION_ERROR;
    this.operatorName = operatorName;
    this.details = details;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

class NotFoundError extends Error {
  constructor(message, resource = null) {
    super(message);
    this.name = 'NotFoundError';
    this.statusCode = HttpStatus.NOT_FOUND;
    this.code = ErrorCodes.NOT_FOUND;
    this.resource = resource;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

function catchAsync(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function createOperatorErrorHandler(operatorName) {
  return (error, req, res, next) => {
    // Re-throw through global errorHandler with operator context
    const operatorError = new OperatorError(
      `Operator "${operatorName}" failed: ${error.message}`,
      operatorName,
      {
        originalError: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      }
    );

    next(operatorError);
  };
}

module.exports = {
  errorHandler,
  notFoundHandler,
  catchAsync,
  createOperatorErrorHandler,

  AppError,
  ValidationError,
  OperatorError,
  NotFoundError
};
