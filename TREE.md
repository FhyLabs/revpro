## Folder Structure

```
RevPro/
│
├── package.json
├── README.md
├── index.js
├── cli.js
├── config/
│   ├── default.js
│   ├── production.js
│   └── development.js
│
├── src/
│   ├── core/
│   │   ├── ProxyEngine.js
│   │   ├── UpstreamManager.js
│   │   ├── SecurityManager.js
│   │   ├── MiddlewareLoader.js
│   │   ├── ErrorHandler.js
│   │   └── PluginSystem.js
│   │
│   ├── middleware/
│   │   ├── security/
│   │   │   ├── rateLimiter.js
│   │   │   ├── ipFilter.js
│   │   │   ├── basicAuth.js
│   │   │   ├── cors.js
│   │   │   └── bodyLimit.js
│   │   └── system/
│   │       ├── trustProxy.js
│   │       └── disablePoweredBy.js
│   │
│   ├── utils/
│   │   └── logger.js
│   │
│   ├── network/
│   │   ├── healthChecker.js
│   │   ├── upstreamProbe.js
│   │   └── dnsResolver.js
│   │
│   ├── security/
│   │   ├── waf.js
│   │   ├── signatureBlocker.js
│   │   └── headerSanitizer.js
│   │
│   └── index.js
│
└── examples/
    └── simple.js
```