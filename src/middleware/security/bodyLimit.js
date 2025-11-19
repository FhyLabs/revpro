const getRawBody = require('raw-body');

module.exports = function bodyLimit(opts = {}) {
  const max = opts.maxBodyBytes || 2 * 1024 * 1024;
  return async function (req, res, next) {
    try {
      const len = req.headers['content-length'];
      if (len && Number(len) > max) {
        res.statusCode = 413;
        res.end('Payload Too Large');
        return;
      }

      req.rawBody = await getRawBody(req, { length: len || max, limit: max });
      next();
    } catch (err) {
      if (err.type === 'entity.too.large') {
        res.statusCode = 413;
        res.end('Payload Too Large');
      } else {
        res.statusCode = 400;
        res.end('Invalid Body');
      }
    }
  };
};
