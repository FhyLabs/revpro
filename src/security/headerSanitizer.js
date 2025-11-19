function sanitize(req) {
  if (!req || !req.headers) return;

  const dangerousHeaders = [
    'proxy-authorization',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-real-ip',
    'x-aws-ec2-metadata-token',
    'x-amzn-trace-id', 
    'cf-connecting-ip',
    'true-client-ip',
    'forwarded',
    'x-client-ip',
    'x-originating-ip'
  ];

  const headers = req.headers;

  for (const key of dangerousHeaders) {
    for (const h in headers) {
      if (h.toLowerCase() === key) {
        delete headers[h];
      }
    }
  }

  for (const h in headers) {
    if (headers[h] === undefined || headers[h] === null) {
      delete headers[h];
    }
  }
}

module.exports = { sanitize };
