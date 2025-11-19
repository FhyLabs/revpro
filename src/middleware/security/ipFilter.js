const ipaddr = require('ipaddr.js');
const { logger } = require('../../utils/logger');

class IPFilter {
  constructor(opts = {}) {
    this.whitelist = Array.isArray(opts.whitelist) ? opts.whitelist : [];
    this.blacklist = Array.isArray(opts.blacklist) ? opts.blacklist : [];
    this.cidrCache = new Map();
    this.blockStatus = opts.blockStatus || 403;
    this.blockMessage = opts.blockMessage || 'Forbidden';
  }

  _parseCIDR(item) {
    if (this.cidrCache.has(item)) return this.cidrCache.get(item);
    const parsed = ipaddr.parseCIDR(item);
    this.cidrCache.set(item, parsed);
    return parsed;
  }

  _checkIP(ip, list) {
    try {
      if (!ip) return false;
      if (list.includes('*')) return true;
      const addr = ipaddr.parse(ip);
      for (const item of list) {
        if (item === ip) return true;
        if (item.includes('/')) {
          const range = this._parseCIDR(item);
          if (addr.match(range)) return true;
        }
      }
    } catch (e) {
      logger.error('IPFilter error', { ip, err: e.message });
    }
    return false;
  }

  middleware(req, res, next) {
    const ips = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
      .split(',')
      .map(i => i.trim())
      .filter(Boolean);

    for (const ip of ips) {
      if (this._checkIP(ip, this.blacklist)) {
        logger.warn(`Blocked IP (blacklist): ${ip}`);
        res.statusCode = this.blockStatus;
        res.end(this.blockMessage);
        return;
      }
    }

    if (this.whitelist.length && !ips.some(ip => this._checkIP(ip, this.whitelist))) {
      logger.warn(`Blocked IP (not in whitelist): ${ips.join(', ')}`);
      res.statusCode = this.blockStatus;
      res.end(this.blockMessage);
      return;
    }

    next();
  }
}

module.exports = IPFilter;
