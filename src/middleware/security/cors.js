const { logger } = require('../../utils/logger');

module.exports = function corsMiddleware(opts = {}) {
  const cors = Object.assign({
    enabled: false,
    allowOrigins: [],
    allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowHeaders: ['Content-Type','Authorization'],
    allowCredentials: false,
    maxAge: 86400
  }, opts.cors || {});

  return function (req, res, next) {
    if (!cors.enabled) return next();

    const origin = req.headers.origin;
    let allowed = false;

    if (typeof cors.allowOrigins === 'function') {
      allowed = cors.allowOrigins(origin, req);
    } else if (Array.isArray(cors.allowOrigins)) {
      allowed = cors.allowOrigins.includes('*') || (origin && cors.allowOrigins.includes(origin));
    }

    if (!allowed) {
      logger.warn('CORS blocked origin', { origin });
      return next();
    }

    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', cors.allowMethods.join(','));
    res.setHeader('Access-Control-Allow-Headers', cors.allowHeaders.join(','));
    if (cors.allowCredentials) res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', cors.maxAge);

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    next();
  };
};
