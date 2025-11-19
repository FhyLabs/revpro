# RevPro

RevPro is a reverse-proxy built to efficiently manage the flow of application traffic. It routes requests to multiple upstream servers, monitors their health, handles failovers, and applies security measures like rate limiting, IP filtering, and request body limits.

----

## Features

- Run HTTP & HTTPS proxies
- Automatic load balancing between upstream servers
- Automatic failover when one server goes down
- Periodic health checks to ensure all servers are healthy
- Limit traffic with a rate limiter
- IP filtering, Basic Auth, and CORS whitelisting
- Limit request body size
- Enable WAF
- Add custom plugins for logging, monitoring, or other needs
- Prioritize specific servers with priority configuration
- Set up weighted load balancing between servers

---

## Installation

```
npm install @fhylabs/revpro
```

## Global
```
revpro start
revpro start ./config/production.js
```

## PM2

```
pm2 start examples.js --name revpro
```

---

## API Reference

### Parameters

| Parameters | Type | Default | Description |
| ------------- | ------------------------- | --------------------------------------------- | ------------------------------------------------------------------------------- |
| `port` | `number` | `8080` | Port for listening proxy |
| `bind` | `string` | `'0.0.0.0'` | Bind server IP/interface |
| `upstreams` | `Array<string \| object>` | `[]` | List of upstream servers. Can be a URL string or an object `{ url, priority, weight }` |
| `logFormat` | `string` | `'combined'` | Request log format (apache-like / dev / custom) |
| `logging` | `object` | `{ enabled: true }` | Logging configuration |
| `healthCheck` | `object` | `{ interval: 5000, timeout: 2000, retry: 2 }` | Health-check configuration |
| `security` | `object` | `{}` | Security suite (rateLimit, IP filter, basicAuth, CORS, bodyLimit, WAF) |
| `plugins` | `Array<string>` | `[]` | List of plugins, JS paths or modules |
| `https` | `object` | `{ enabled: false, key: null, cert: null }` | HTTPS Configuration |

**Example of use:**

```js
const { createProxy } = require('@fhylabs/revpro');

const proxy = createProxy({
  port: 8080,
  bind: '127.0.0.1',
  upstreams: [
    { url: 'http://localhost:3001', priority: 1 },
    { url: 'http://localhost:3002', priority: 2 }
  ],
  logFormat: 'dev',
  logging: { enabled: true },
  plugins: ['./plugins/logger.js']
});

proxy.start();
```

---

### Methods

| Method | Returns | Description |
| ----------- | -------- | ------------------------------------------------------------------------------------------------- |
| `start()` | `Server` | Running a proxy server (HTTP/HTTPS) |
| `stop()` | `void` | Stop server and health-check |
| `_internal` | `object` | Internal objects for debugging/testing: `{ app, upstreamManager, securityManager, pluginSystem }` |

**Example of use:**

```js
proxy.start(); // run server
proxy.stop();  // stop server
console.log(proxy._internal.upstreamManager.list()); // upstream status access
```

---

### Upstream

| Property | Type | Default | Description |
| ---------- | -------- | -------- | ------------------------------------------------ |
| `url` | `string` | required | Upstream URL |
| `priority` | `number` | `1` | Priority, lower → higher priority |
| `weight` | `number` | `1` | Weight for weighted load-balancing |

**Example usage:**

```js
upstreams: [
  { url: 'http://localhost:3001', priority: 1, weight: 3 },
  { url: 'http://localhost:3002', priority: 2, weight: 1 }
]
```

---

### Health Check

| Options | Type | Default | Description |
| ---------- | -------- | ------- | ---------------------------- |
| `interval` | `number` | `5000` | Upstream checking interval |
| `timeout` | `number` | `2000` | Timeout request health-check |
| `retry` | `number` | `2` | Retry if upstream fails |

> Endpoint: http://127.0.0.1:8080/healthz

**Example of use:**

```js
healthCheck: {
  interval: 3000,
  timeout: 2000,
  retry: 2
}
```

---

###Security

| Options | Type | Default | Description |
| ----------- | ---------------------------------------- | ---------- | -------------------------------------------------------- |
| `rateLimit` | `{ windowMs: number, max: number }` | undefined | Limit requests per window Ms |
| `ipFilter` | `{ allow: string[], block: string[] }` | `{[], []}` | IP whitelist/blacklist |
| `basicAuth` | `{ username: string, password: string }` | undefined | Basic Auth |
| `cors` | `{ allowedOrigins: string[] }` | `[]` | CORS Whitelist |
| `bodyLimit` | `string` | `'2mb'` | Maximum size request body |
| `waf` | `boolean` | `true` | Enable WAF |

**Example of use:**

```js
security: {
  rateLimit: { windowMs: 60000, max: 100 },
  ipFilter: { allow: ['127.0.0.1'], block: [] },
  basicAuth: { username: 'admin', password: '12345' },
  cors: { allowedOrigins: ['http://localhost:8080'] },
  bodyLimit: '5mb',
  waf: true
}
```

---

### Logging

| Options | Type | Default | Description |
| ----------------- | --------- | ------------ | ------------------------ |
| `logFormat` | `string` | `'combined'` | Logging request format |
| `logging.enabled` | `boolean` | `true` | Enable request logging |

**Example of use:**

```js
logFormat: 'dev',
logging: { enabled: true }
```

---

### Plugin System

| Parameters | Type | Description |
| -------------------- | ---------------------------------------- | ------------------------------- |
| `app` | `Express app` | Express instances |
| `logger` | `winston logger` | Logger instances |
| `events` | `EventEmitter` | Events plugin |
| `proxy` | `object` | Proxy instance (internal access) |
| `plugin:request` | `{ path, method }` | Incoming request |
| `plugin:response` | `{ path, method, statusCode, duration }` | Response completed |
| `upstream:healthy` | `{ url }` | Upstream healthy |
| `upstream:unhealthy` | `{ url }` | Upstream is unhealthy |

**Example of use:**

```js
module.exports = function loggerPlugin({ app, logger, events }) {
  app.use((req, res, next) => {
    logger.info(`Plugin Logger: ${req.method} ${req.url}`);
    events.emit('plugin:request', { path: req.url, method: req.method });
    next();
  });
};
```

---

### HTTPS Options

| Options | Type | Default | Description |
| --------- | --------- | ------- | --------------------- |
| `enabled` | `boolean` | `false` | Run the HTTPS server |
| `key` | `string` | null | Path to private key |
| `cert` | `string` | null | Path to certificate |

**Example of use:**

```js
https: {
  enabled: true,
  key: './ssl/key.pem',
  cert: './ssl/cert.pem'
}
```

---

## Test Example

```js
const { createProxy } = require("revpro");

// proxy configuration
const proxy = createProxy({
  port: 8080,
  bind: '127.0.0.1',

  // upstream servers
  upstreams: [
    { url: "http://localhost:3001", priority: 1 },
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
    waf: true  // enable WAF
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
const { createProxy } = require('../index');
const cfg = require('../config/development');
const proxy = createProxy(cfg);
proxy.start();
console.log('Proxy started on', cfg.bind + ':' + cfg.port);
```