const http = require('http');
const https = require('https');
const { URL } = require('url');

async function probe(url, path = '/', timeout = 3000) {
  return new Promise((resolve) => {
    try {
      const u = new URL(url);
      const httpx = u.protocol === 'https:' ? https : http;
      const req = httpx.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path,
        method: 'GET',
        timeout
      }, (res) => {
        resolve(res.statusCode >= 200 && res.statusCode < 500);
        res.resume();
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    } catch (e) {
      resolve(false);
    }
  });
}

module.exports = { probe };
