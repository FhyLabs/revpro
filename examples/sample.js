const { createProxy } = require("../index");

// Create a proxy instance with configuration
const proxy = createProxy({
  port: 8080,                // Proxy server port
  bind: '127.0.0.1',         // Bind address

  // Upstream backend servers
  upstreams: [
    { url: "http://localhost:9000", priority: 1 },
    { url: "http://localhost:3002", priority: 2 }
  ],

  // Logging configuration
  logFormat: 'dev',           // morgan log format
  logging: { enabled: true }, // Enable logging

  // Health check configuration
  healthCheckPath: '/healthz',
  healthCheckInterval: 3000,  // Check interval in ms
  healthCheckTimeout: 2000,   // Timeout for probe requests

  // Security options
  maxRequestsPerMinute: 100,  // Rate limit
  ipWhitelist: ['127.0.0.1'], // Allowed IPs ('*' for all)
  ipBlacklist: [],            // Blocked IPs
  auth: { username: 'admin', password: '12345' }, // Basic auth
  cors: { enabled: true, allowOrigins: ['*'] },        // CORS settings
  maxBodyBytes: 5 * 1024 * 1024, // Maximum body size (5 MB)
  waf: true,                    // Enable mini WAF

  // Plugins to enhance functionality
  plugins: ['./plugins/logger.js'],

  // HTTPS options (optional)
  https: { enabled: false, key: null, cert: null },

  // Enable trust proxy
  trustProxy: true
});

// Helper function to wait until at least one upstream is healthy
async function waitForHealthy() {
  const start = Date.now();
  while (Date.now() - start < 5000) { // Maximum wait: 5 seconds
    const upstreams = proxy._internal.upstreamManager.list();
    if (upstreams.some(u => u.healthy)) return; // Exit if any upstream is healthy
    await new Promise(r => setTimeout(r, 500));
  }
  console.warn("Warning: no upstream healthy after wait period");
}

// Start the proxy and wait for upstream readiness
(async () => {
  proxy.start();           // Start HTTP/HTTPS proxy server
  await waitForHealthy();  // Wait until at least one upstream is healthy
})();
