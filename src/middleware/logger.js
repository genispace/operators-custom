/** Minimal request logging to stdout */

function generateRequestId() {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function requestLogger(req, res, next) {
  const startTime = process.hrtime.bigint();
  const requestId = generateRequestId();
  
  req.requestId = requestId;
  
  console.log(`${new Date().toISOString()} [INFO] Request started`, JSON.stringify({
    requestId,
    method: req.method,
    url: req.originalUrl || req.url,
    ip: req.ip || req.connection?.remoteAddress,
    userAgent: req.get('User-Agent'),
    contentType: req.get('Content-Type'),
    contentLength: req.get('Content-Length') || 0
  }));

  res.on('finish', () => {
    const duration = Number(process.hrtime.bigint() - startTime) / 1000000; // ns → ms
    const level = res.statusCode >= 400 ? 'WARN' : 'INFO';
    
    console.log(`${new Date().toISOString()} [${level}] Request completed`, JSON.stringify({
      requestId,
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      responseTime: `${duration.toFixed(2)}ms`,
      contentLength: res.get('Content-Length') || 0
    }));
  });

  next();
}

module.exports = { requestLogger };