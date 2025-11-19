const { logger } = require('../../utils/logger');

module.exports = function trustProxy(app, opts = {}) {
  if (!app || typeof app.set !== 'function') {
    logger.warn('trustProxy: invalid app instance');
    return;
  }

  try {
    app.set('trust proxy', opts.trustProxy === undefined ? true : !!opts.trustProxy);
    if (opts.debug) logger.info(`trustProxy applied: ${app.get('trust proxy')}`);
  } catch (err) {
    logger.error('trustProxy failed', { err: err.message });
  }
};
