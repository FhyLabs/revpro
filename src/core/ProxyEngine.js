const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const httpProxy = require('http-proxy');
const helmet = require('helmet');
const morgan = require('morgan');

const UpstreamManager = require('./UpstreamManager');
const SecurityManager = require('./SecurityManager');
const ErrorHandler = require('./ErrorHandler');
const PluginSystem = require('./PluginSystem');
const { logger } = require('../utils/logger');

const trustProxy = require('../middleware/system/trustProxy');
const disablePoweredBy = require('../middleware/system/disablePoweredBy');
const { probe } = require('../network/upstreamProbe');
const { resolve: dnsResolve } = require('../network/dnsResolver');

function createProxy(userOptions = {}) {
  const opts = Object.assign({}, userOptions);
  const app = express();
  let server = null;
  const proxyServer = httpProxy.createProxyServer({});

  const upstreamManager = new UpstreamManager(opts.upstreams || [], opts);
  const securityManager = new SecurityManager(opts);
  const pluginSystem = new PluginSystem(opts.plugins || []);

  disablePoweredBy(app);
  if (opts.trustProxy) trustProxy(app);
  app.use(helmet());
  app.use((req, res, next) => res.setHeader('X-Content-Type-Options', 'nosniff') && next());
  app.use(morgan(opts.logFormat || 'combined', { stream: logger.stream }));

  app.use((req, res, next) => securityManager.rateLimiterMiddleware(req, res, next));
  app.use((req, res, next) => securityManager.ipFilterMiddleware(req, res, next));
  app.use((req, res, next) => securityManager.basicAuthMiddleware(req, res, next));
  app.use((req, res, next) => securityManager.corsMiddleware(req, res, next));
  app.use((req, res, next) => securityManager.bodyLimitMiddleware(req, res, next));
  app.use((req, res, next) => securityManager.wafMiddleware(req, res, next));

  try { pluginSystem.applyMiddlewares(app); } 
  catch (err) { logger.error('PluginSystem applyMiddlewares error', { message: err.message, stack: err.stack }); }

  const healthPath = opts.healthCheckPath || '/healthz';
  app.get('/__proxy__/status', (req, res) => res.json({ ok: true, upstreams: upstreamManager.list() }));
  app.get(healthPath, async (req, res) => {
    const upstreams = upstreamManager.list();
    await Promise.all(upstreams.map(async (u) => {
      const healthy = await probe(u.url, '/', opts.healthCheckTimeout);
      u.healthy = healthy;
    }));
    const allHealthy = upstreams.every(u => u.healthy);
    res.status(allHealthy ? 200 : 503).json({
      ok: allHealthy,
      upstreams: upstreams.map(u => ({ url: u.url, healthy: u.healthy })),
    });
  });

  app.use((req, res) => {
    let upstream = upstreamManager.pick();
    if (!upstream?.url) {
      logger.warn('No upstream available', { url: req.url });
      res.statusCode = 502; return res.end('Bad Gateway - No upstream available');
    }

    let target = upstream.url;
    proxyServer.web(req, res, { target, changeOrigin: true, preserveHeaderKeyCase: true }, (err) => {
      logger.error('Proxy error', { message: err?.message, stack: err?.stack, request: { method: req.method, url: req.url }, target });
      upstreamManager.markUnhealthy(upstream.url);

      const fallback = upstreamManager.list().find(u => u.healthy && u.url !== upstream.url);
      if (!fallback) { res.statusCode = 502; return res.end('Bad Gateway - No healthy upstream'); }

      target = fallback.url;
      proxyServer.web(req, res, { target, changeOrigin: true }, (err2) => {
        logger.error('Fallback proxy error', { message: err2?.message, stack: err2?.stack, request: { method: req.method, url: req.url }, target });
        res.statusCode = 502; res.end('Bad Gateway - Fallback failed');
      });
    });
  });

  app.use((err, req, res, next) => ErrorHandler.handle(err, req, res, next));

  function start() {
    if (server) return server;
    if (opts.https?.enabled && opts.https.key && opts.https.cert) {
      const key = fs.readFileSync(path.resolve(opts.https.key));
      const cert = fs.readFileSync(path.resolve(opts.https.cert));
      server = https.createServer({ key, cert }, app).listen(opts.port, opts.bind, () => {
        logger.info(`Proxy listening HTTPS on ${opts.bind}:${opts.port}`);
      });
    } else {
      server = http.createServer(app).listen(opts.port, opts.bind, () => {
        logger.info(`Proxy listening HTTP on ${opts.bind}:${opts.port}`);
      });
    }
    upstreamManager.start();
    return server;
  }

  function stop() {
    if (!server) return;
    server.close(); upstreamManager.stop(); server = null;
  }

  return { start, stop, _internal: { app, upstreamManager, securityManager, pluginSystem } };
}

module.exports = { createProxy };
