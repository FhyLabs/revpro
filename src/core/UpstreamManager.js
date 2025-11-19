const http = require('http');
const https = require('https');
const { URL } = require('url');
const EventEmitter = require('events');
const { logger } = require('../utils/logger');

class UpstreamManager extends EventEmitter {
  constructor(upstreams = [], opts = {}) {
    super();
    this.opts = opts;
    this.nodes = (Array.isArray(upstreams) ? upstreams : []).map(u => ({
      url: u.url,
      priority: u.priority || 1,
      healthy: true
    }));
    this.hcTimer = null;
  }

  start() {
    this.runHealthChecks();
    this.hcTimer = setInterval(() => this.runHealthChecks(), this.opts.healthCheckInterval || 15000);
    logger.info('UpstreamManager started', { nodes: this.nodes.map(n => n.url) });
  }

  stop() {
    if (this.hcTimer) {
      clearInterval(this.hcTimer);
      this.hcTimer = null;
      logger.info('UpstreamManager stopped');
    }
  }

  list() {
    return this.nodes.map(n => ({
      url: n.url,
      priority: n.priority,
      healthy: n.healthy
    }));
  }

  pick() {
    const healthyNodes = this.nodes.filter(n => n.healthy);
    if (!healthyNodes.length) {
      logger.warn('No upstream healthy available');
      return null;
    }
    healthyNodes.sort((a, b) => a.priority - b.priority);
    return healthyNodes[0];
  }

  markUnhealthy(url, reason = 'unknown') {
    const node = this.nodes.find(n => n.url === url);
    if (node && node.healthy) {
      node.healthy = false;
      logger.warn('Upstream marked unhealthy', { url, reason });
      this.emit('upstream:down', url, reason);
    }
  }

  markHealthy(url) {
    const node = this.nodes.find(n => n.url === url);
    if (node && !node.healthy) {
      node.healthy = true;
      logger.info('Upstream back healthy', { url });
      this.emit('upstream:back', url);
    }
  }

  runHealthChecks() {
    this.nodes.forEach((n) => {
      const u = new URL(n.url);
      const httpx = u.protocol === 'https:' ? https : http;

      const req = httpx.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: this.opts.healthCheckPath || '/',
        method: 'GET',
        timeout: this.opts.healthCheckTimeout || 3000
      }, (res) => {
        const wasHealthy = n.healthy;
        const nowHealthy = res.statusCode >= 200 && res.statusCode < 500;
        n.healthy = nowHealthy;
        res.resume();

        if (!wasHealthy && nowHealthy) {
          logger.info('Upstream recovered from unhealthy', { url: n.url, statusCode: res.statusCode });
          this.emit('upstream:back', n.url);
        } else if (!nowHealthy && wasHealthy) {
          this.markUnhealthy(n.url, `statusCode ${res.statusCode}`);
        }
      });

      req.on('error', (err) => this.markUnhealthy(n.url, `error: ${err.message}`));
      req.on('timeout', () => {
        req.destroy();
        this.markUnhealthy(n.url, 'timeout');
      });

      req.end();
    });
  }
}

module.exports = UpstreamManager;
