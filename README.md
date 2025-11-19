# RevPro

RevPro is a reverse-proxy to efficiently route and manage application traffic.
It supports multiple upstreams, health checks, failover, rate limiting, IP filtering, Basic Auth, CORS, body limits, WAF, plugins, and HTTPS.

---

## Installation

```bash
npm install @fhylabs/revpro
```

---

## Global CLI

```bash
revpro start
revpro start ./config/production.js
```

---

## PM2

```bash
pm2 start examples.js --name revpro
```

---

## API Reference

### Proxy Configuration Parameters

| Parameter             | Type                      | Default             | Description                                                         |
| --------------------- | ------------------------- | ------------------- | ------------------------------------------------------------------- |
| `port`                | `number`                  | `8080`              | Proxy server port                                                   |
| `bind`                | `string`                  | `'0.0.0.0'`         | Bind address/interface                                              |
| `upstreams`           | `Array<string \| object>` | `[]`                | List of upstreams, can be URL string or `{ url, priority, weight }` |
| `logFormat`           | `string`                  | `'combined'`        | Logging format for requests                                         |
| `logging`             | `{ enabled: boolean }`    | `{ enabled: true }` | Enable/disable request logging                                      |
| `healthCheckPath`     | `string`                  | `/healthz`          | Endpoint path to check upstream health                              |
| `healthCheckInterval` | `number`                  | `5000`              | Interval in ms to perform health checks                             |
| `healthCheckTimeout`  | `number`                  | `2000`              | Timeout for health check probe requests                             |
| `trustProxy`          | `boolean`                 | false               | Enable trust proxy headers                                          |

**Example: Proxy Config**

```js
const { createProxy } = require("@fhylabs/revpro");

const proxy = createProxy({
  port: 8080,
  bind: '127.0.0.1',
  logFormat: 'dev',
  logging: { enabled: true },
  healthCheckPath: '/healthz',
  healthCheckInterval: 3000,
  healthCheckTimeout: 2000,
  trustProxy: true
});
```

---

### Upstream Configuration

| Property   | Type     | Default  | Description                    |
| ---------- | -------- | -------- | ------------------------------ |
| `url`      | `string` | required | URL of upstream server         |
| `priority` | `number` | 1        | Lower number = higher priority |
| `weight`   | `number` | 1        | Weight for load balancing      |

**Example: Upstreams**

```js
upstreams: [
  { url: 'http://localhost:9000', priority: 1, weight: 3 },
  { url: 'http://localhost:3002', priority: 2, weight: 1 }
]
```

---

### Security Options

| Option                 | Type                                           | Default                                | Description               |
| ---------------------- | ---------------------------------------------- | -------------------------------------- | ------------------------- |
| `maxRequestsPerMinute` | `number`                                       | undefined                              | Limit requests per minute |
| `ipWhitelist`          | `Array<string>`                                | `[]`                                   | Allowed IPs               |
| `ipBlacklist`          | `Array<string>`                                | `[]`                                   | Blocked IPs               |
| `auth`                 | `{ username: string, password: string }`       | undefined                              | Basic Auth credentials    |
| `cors`                 | `{ enabled: boolean, allowOrigins: string[] }` | `{ enabled: false, allowOrigins: [] }` | CORS configuration        |
| `maxBodyBytes`         | `number`                                       | 2 * 1024 * 1024                        | Max request body size     |
| `waf`                  | `boolean`                                      | true                                   | Enable WAF                |

**Example: Security Options**

```js
maxRequestsPerMinute: 100,
ipWhitelist: ['127.0.0.1'],
ipBlacklist: [],
auth: { username: 'admin', password: '12345' },
cors: { enabled: true, allowOrigins: ['*'] },
maxBodyBytes: 5 * 1024 * 1024,
waf: true
```

---

### Logging

| Option            | Type      | Default    | Description            |
| ----------------- | --------- | ---------- | ---------------------- |
| `logFormat`       | `string`  | 'combined' | Logging format         |
| `logging.enabled` | `boolean` | true       | Enable request logging |

**Example: Logging**

```js
logFormat: 'dev',
logging: { enabled: true }
```

---

### Health Check

| Option                | Type     | Default    | Description                                       |
| --------------------- | -------- | ---------- | ------------------------------------------------- |
| `healthCheckPath`     | `string` | `/healthz` | Endpoint path to check upstream health            |
| `healthCheckInterval` | `number` | 5000       | Interval in milliseconds to perform health checks |
| `healthCheckTimeout`  | `number` | 2000       | Timeout for probe requests                        |

**Example: Health Check**

```js
healthCheckPath: '/healthz',
healthCheckInterval: 3000,
healthCheckTimeout: 2000
```

**Manual Probe Example**

```js
const upstreams = proxy._internal.upstreamManager.list();

async function checkUpstreams() {
  for (const u of upstreams) {
    const healthy = await probe(u.url, '/', 2000);
    console.log(`${u.url} is ${healthy ? 'healthy' : 'unhealthy'}`);
  }
}

checkUpstreams();
```

---

### Plugin System Events

| Event                | Data                                     | Description                 |
| -------------------- | ---------------------------------------- | --------------------------- |
| `plugin:request`     | `{ path, method }`                       | Fired on incoming request   |
| `plugin:response`    | `{ path, method, statusCode, duration }` | Fired on response completed |
| `upstream:healthy`   | `{ url }`                                | Upstream became healthy     |
| `upstream:unhealthy` | `{ url }`                                | Upstream became unhealthy   |

**Example: Plugin Usage**

```js
module.exports = function loggerPlugin({ app, logger, events }) {
  app.use((req, res, next) => {
    logger.info(`Incoming request: ${req.method} ${req.url}`);
    events.emit('plugin:request', { path: req.url, method: req.method });
    next();
  });

  app.use((req, res, next) => {
    res.on('finish', () => {
      events.emit('plugin:response', {
        path: req.url,
        method: req.method,
        statusCode: res.statusCode,
        duration: Date.now() - req.startTime
      });
    });
    next();
  });
};
```

---

### HTTPS Options

| Option    | Type      | Default | Description         |
| --------- | --------- | ------- | ------------------- |
| `enabled` | `boolean` | false   | Enable HTTPS server |
| `key`     | `string`  | null    | Path to private key |
| `cert`    | `string`  | null    | Path to certificate |

**Example: HTTPS Options**

```js
https: {
  enabled: true,
  key: './ssl/key.pem',
  cert: './ssl/cert.pem'
}
```

## Full Example

```
const { createProxy } = require("@fhylabs/revpro");

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
```