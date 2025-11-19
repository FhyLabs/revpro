const { createProxy } = require("../index");

// proxy configuration
const proxy = createProxy({
  port: 8080,
  bind: '127.0.0.1',

  // upstream servers
  upstreams: [
    { url: "http://localhost:9000", priority: 1 },
    { url: "http://localhost:3002", priority: 2 }
  ],

  // log request
  logFormat: 'dev',
  logging: { enabled: true },

  // health check
  healthCheck: {
    interval: 3000,  // every 3 seconds check upstream
    timeout: 2000,   // timeout request health-check
    retry: 2         // retry if failed
  },

  // security suite
  security: {
    rateLimit: { windowMs: 60000, max: 100 },  // max 100 req per menit
    ipFilter: { allow: ['127.0.0.1'], block: [] }, // whitelist IP
    bodyLimit: '5mb',  // maximum body size
    basicAuth: { username: 'admin', password: '12345' }, // basic auth
    cors: { allowedOrigins: ['http://localhost:8080'] }, // whitelist CORS
    waf: true  // enable mini WAF (signature blocker + header sanitizer)
  },

  // plugins
  plugins: [
    './plugins/logger.js',  // logging plugin example
  ],

  // HTTPS support (optional, activate if you already have a cert & key)
  https: {
    enabled: false,
    key: null,
    cert: null
  }
});

// helper: wait for upstream to be healthy before logging ready
async function waitForHealthy() {
  const start = Date.now();
  while (Date.now() - start < 5000) { // wait max 5 seconds
    const upstreams = proxy._internal.upstreamManager.list();
    if (upstreams.some(u => u.healthy)) return;
    await new Promise(r => setTimeout(r, 500));
  }
  console.warn("Warning: no upstream healthy after wait period");
}

// run proxy
(async () => {
  proxy.start();
  await waitForHealthy();
  console.log("Reverse Proxy running on port 8080");
})();