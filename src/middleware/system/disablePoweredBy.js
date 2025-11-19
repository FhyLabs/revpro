const { logger } = require('../../utils/logger');

module.exports = function disablePoweredBy(app, opts = {}) {
  if (!app || typeof app.disable !== 'function') {
    logger.warn('disablePoweredBy: invalid app instance');
    return;
  }

  try {
    app.disable('x-powered-by');
    if (opts.debug) logger.info('x-powered-by header disabled');
  } catch (err) {
    logger.error('disablePoweredBy failed', { err: err.message });
  }
};
