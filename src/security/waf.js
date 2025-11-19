function deepDecode(str) {
  try {
    let last = str;
    let decoded = str;

    for (let i = 0; i < 3; i++) {
      decoded = decodeURIComponent(decoded);
      if (decoded === last) break;
      last = decoded;
    }
    return decoded;
  } catch {
    return str;
  }
}

function normalize(str) {
  return str
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) // \x41
    .replace(/&#x([0-9A-Fa-f]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))  // &#x41;
    .replace(/&#([0-9]+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)))         // &#65;
    .replace(/\s+/g, " ")                                                            // remove excessive space
    .trim()
    .toLowerCase();
}

const patterns = [
  // SQLi
  /\b(select|union(\s+all)?|insert|delete|update|drop|alter|create|truncate|rename)\b/,
  /\b(or|and)\s+[0-9]+\s*=\s*[0-9]+\b/,
  /(--|#|\/\*)/,
  /\b(sleep|benchmark)\s*\(/,

  // Blind SQLi time-based
  /\bwaitfor\s+delay\b/,

  // NoSQL Injection
  /\$\w+=|\$ne|\$where|ObjectId\(/,

  // XSS
  /<script[\s>]/,
  /\bon\w+=/,
  /(javascript|data):/,

  // XSS modern (Vue, React)
  /\{\{.*\}\}/,
  /\b(v-html|v-on)\b/,

  // RCE PHP / Node / Shell
  /\b(eval|system|exec|passthru|shell_exec|pcntl_exec|spawn)\(/,
  /\b(require|include)(_once)?\s*\(/,
  /\bchild_process\b/,

  // LFI / RFI
  /\.\.\//,
  /%2e%2e%2f/,
  /\b(file|php|data|zip|http|https):\/\//,

  // Windows path traversal
  /[A-Za-z]:\\(windows|system32)/,

  // Code Injection
  /\$(\{.*\})/,
  /\bimport\(/,

  // Null byte
  /\x00/,
];

function inspect(req) {
  const ua = req.headers["user-agent"] || "";
  const raw = (req.rawBody && req.rawBody.toString("utf8")) || "";

  if (/nikto|sqlmap|acunetix|nessus|owasp|burpsuite/i.test(ua)) return true;

  let target = req.url + " " + raw + " " + ua;

  target = deepDecode(target);
  target = normalize(target);

  for (const p of patterns) {
    if (p.test(target)) return true;
  }

  return false;
}

module.exports = { inspect };
