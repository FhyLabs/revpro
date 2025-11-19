const { logger } = require('../../utils/logger');

class RateLimiter {
  constructor(opts = {}) {
    this.max = opts.maxRequestsPerMinute || 1200;
    this.windowMs = opts.windowMs || 60_000;
    this.counters = new Map();
    this.resetTimers = new Map();
  }

  middleware(req, res, next) {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (!ip) return next();

    const now = Date.now();
    const record = this.counters.get(ip) || { count: 0, start: now };

    if (now - record.start > this.windowMs) {
      record.count = 0;
      record.start = now;
    }

    record.count += 1;
    this.counters.set(ip, record);

    const remaining = this.max - record.count;

    res.setHeader('X-RateLimit-Limit', this.max);
    res.setHeader('X-RateLimit-Remaining', Math.max(remaining, 0));
    res.setHeader('X-RateLimit-Reset', Math.ceil((record.start + this.windowMs - now)/1000));

    if (record.count > this.max) {
      logger.warn(`Rate limit exceeded for IP ${ip}`);
      res.statusCode = 429;
      res.setHeader('Retry-After', Math.ceil((record.start + this.windowMs - now)/1000));
      res.end('Too Many Requests');
      return;
    }

    next();
  }
}

module.exports = RateLimiter;
