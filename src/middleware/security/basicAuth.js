const basicAuth = require('basic-auth');
const { logger } = require('../../utils/logger');

module.exports = function basicAuthMiddleware(opts = {}) {
  const realm = (opts.basicAuth && opts.basicAuth.realm) || 'Restricted';

  return function (req, res, next) {
    try {
      if (!opts.basicAuth) return next();

      const user = basicAuth(req) || {};
      const ip = req.ip || req.socket.remoteAddress;

      if (user.name === opts.basicAuth.username && user.pass === opts.basicAuth.password) {
        return next();
      }

      logger.warn('Unauthorized access attempt', {
        ip,
        url: req.url,
        username: user.name || null,
      });

      res.setHeader('WWW-Authenticate', `Basic realm="${realm}"`);
      res.statusCode = 401;
      res.end('Unauthorized');
    } catch (err) {
      logger.error('BasicAuth middleware error', {
        err: err.message,
        ip: req.ip || req.socket.remoteAddress,
        url: req.url,
      }
