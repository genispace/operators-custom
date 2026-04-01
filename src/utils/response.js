/**
 * Shared JSON response shape helpers (`success`, `timestamp`, optional `code` / `details`).
 */

/**
 * @param {unknown} data
 * @param {string|null} [message]
 * @returns {{ success: true, data: unknown, timestamp: string, message?: string }}
 */
function createSuccessResponse(data, message = null) {
  const response = {
    success: true,
    data,
    timestamp: new Date().toISOString()
  };

  if (message) {
    response.message = message;
  }

  return response;
}

/**
 * @param {string} error Human-readable message
 * @param {string|null} [code]
 * @param {unknown} [details]
 */
function createErrorResponse(error, code = null, details = null) {
  const response = {
    success: false,
    error,
    timestamp: new Date().toISOString()
  };

  if (code) {
    response.code = code;
  }

  if (details) {
    response.details = details;
  }

  return response;
}

/**
 * @param {unknown[]} items
 * @param {number} page
 * @param {number} limit
 * @param {number} total
 */
function createPaginatedResponse(items, page, limit, total) {
  const totalPages = Math.ceil(total / limit);

  return createSuccessResponse({
    items,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  });
}

/** @param {unknown[]} errors Joi-style or custom field errors */
function createValidationErrorResponse(errors) {
  return createErrorResponse(
    'Request validation failed',
    'VALIDATION_ERROR',
    { errors }
  );
}

/** @param {import('express').Response} res */
function sendSuccessResponse(res, data, message = null, statusCode = 200) {
  res.status(statusCode).json(createSuccessResponse(data, message));
}

/** @param {import('express').Response} res */
function sendErrorResponse(res, error, code = null, details = null, statusCode = 400) {
  res.status(statusCode).json(createErrorResponse(error, code, details));
}

/** @param {import('express').Response} res */
function sendPaginatedResponse(res, items, page, limit, total, statusCode = 200) {
  res.status(statusCode).json(createPaginatedResponse(items, page, limit, total));
}

/** @param {import('express').Response} res */
function sendValidationErrorResponse(res, errors, statusCode = 400) {
  res.status(statusCode).json(createValidationErrorResponse(errors));
}

/** Express route wrapper: forwards rejected promises to `next(err)`. */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/** Same as {@link asyncHandler} for middleware functions. */
function asyncMiddleware(middleware) {
  return (req, res, next) => {
    Promise.resolve(middleware(req, res, next)).catch(next);
  };
}

/** Common HTTP status codes for handlers */
const HttpStatus = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  VALIDATION_ERROR: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

/** Stable machine-readable `code` values for clients */
const ErrorCodes = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  BAD_REQUEST: 'BAD_REQUEST',
  OPERATOR_NOT_FOUND: 'OPERATOR_NOT_FOUND',
  OPERATOR_EXECUTION_ERROR: 'OPERATOR_EXECUTION_ERROR',
  INVALID_PARAMETER: 'INVALID_PARAMETER',
  MISSING_PARAMETER: 'MISSING_PARAMETER'
};

module.exports = {
  // Build plain objects (for tests or manual res.json)
  createSuccessResponse,
  createErrorResponse,
  createPaginatedResponse,
  createValidationErrorResponse,

  // Set status + json in one call
  sendSuccessResponse,
  sendErrorResponse,
  sendPaginatedResponse,
  sendValidationErrorResponse,

  asyncHandler,
  asyncMiddleware,

  HttpStatus,
  ErrorCodes
};
