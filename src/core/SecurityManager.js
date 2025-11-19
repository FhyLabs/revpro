const basicAuth = require('basic-auth');
const RateLimiter = require('../middleware/security/rateLimiter');
const IPFilter = require('../middleware/security/ipFilter');
const corsMiddlewareFactory = require('../middleware/security/cors');
const bodyLimitFactory = require('../middleware/security/bodyLimit');
const WAF = require('../security/waf');
const HeaderSanitizer = require('../security/headerSanitizer');
const SignatureBlocker = require('../security/signatureBlocker');
const { logger } = require('../utils/logger');

class SecurityManager {
  constructor(opts = {}) {
    this.opts = opts || {};

    this.rateLimiter = new RateLimiter({ maxRequestsPerMinute: opts.maxRequestsPerMinute || 1200 });
    this.ipFilter = new IPFilter({ whitelist: opts.ipWhitelist || [], blacklist: opts.ipBlacklist || [] });
    this.corsMiddlewareInstance = corsMiddlewareFactory(opts);
    this.bodyLimitMiddlewareInstance = bodyLimitFactory(opts);
  }

  rateLimiterMiddleware(req, res, next) {
    try {
      this.rateLimiter.middleware(req, res, next);
    } catch (err) {
      logger.error('RateLimiter error', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
      next();
    }
  }

  ipFilterMiddleware(req, res, next) {
    try {
      this.ipFilter.middleware(req, res, next);
    } catch (err) {
      logger.error('IPFilter error', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
      next();
    }
  }

  basicAuthMiddleware(req, res, next) {
    try {
      if (!this.opts.auth) return next();
      const user = basicAuth(req) || {};
      if (user.name === this.opts.auth.username && user.pass === this.opts.auth.password) return next();

      logger.warn('Unauthorized access attempt', { ip: req.ip || req.socket.remoteAddress, url: req.url, username: user.name });
      res.setHeader('WWW-Authenticate', `Basic realm="${this.opts.auth.realm || 'Protected'}"`); // ganti juga
      res.statusCode = 401;
      res.end('Unauthorized');
    } catch (err) {
      logger.error('Auth middleware error', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
      next(err);
    }
  }

  corsMiddleware(req, res, next) {
    try {
      this.corsMiddlewareInstance(req, res, next);
    } catch (err) {
      logger.error('CORS middleware error', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
      next();
    }
  }

  bodyLimitMiddleware(req, res, next) {
    const max = this.opts.maxBodyBytes || 2 * 1024 * 1024;

    const skipPaths = this.opts.bodyLimitSkipPaths || ['/healthz', '/__proxy__/status'];
    if (skipPaths.includes(req.path) || !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      return next();
    }

    const contentLength = req.headers['content-length'] || 0;
    if (Number(contentLength) > max) {
      logger.warn('Payload Too Large', { ip: req.ip || req.socket.remoteAddress, url: req.url, contentLength });
      res.statusCode = 413;
      res.end('Payload Too Large');
      return;
    }

    if (Number(contentLength) === 0) return next();

    try {
      const result = this.bodyLimitMiddlewareInstance(req, res, next);
      if (result && typeof result.then === 'function') {
        result.catch(err => {
          logger.warn('Invalid Body', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
          res.statusCode = 400;
          res.end('Invalid Body');
        });
      }
    } catch (err) {
      logger.warn('Body limit middleware error', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
      res.statusCode = 400;
      res.end('Invalid Body');
    }
  }

  wafMiddleware(req, res, next) {
    try {
      HeaderSanitizer.sanitize(req);

      if (SignatureBlocker.blocked(req)) {
        logger.warn('Blocked malicious signature', { ip: req.ip || req.socket.remoteAddress, url: req.url, headers: req.headers });
        res.statusCode = 403;
        res.end('Forbidden');
        return;
      }

      if (WAF.inspect(req)) {
        logger.warn('Blocked request by WAF', { ip: req.ip || req.socket.remoteAddress, url: req.url });
        res.statusCode = 403;
        res.end('Forbidden');
        return;
      }

    } catch (err) {
      logger.error('WAF inspection failed', { err: err.message, ip: req.ip || req.socket.remoteAddress, url: req.url });
    }

    next();
  }
}

module.exports = SecurityManager;
