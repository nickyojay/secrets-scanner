// src/patterns/advanced.ts

import { RuleContext } from '../types';
import { MultiLineRule } from '../scanner/multiLineScanner';

export const advancedRules: MultiLineRule[] = [

  // ── Path Traversal ────────────────────────────────────────────────────

  {
    id: 'VULN_PATH_TRAVERSAL',
    name: 'Path Traversal via User Input',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'high',
    description:
      'Constructing file paths directly from user input allows attackers to read arbitrary files using ../../ sequences.',
    remediation:
      'Use path.resolve() and verify the result starts with your intended base directory. Never concatenate user input directly into file paths.',
    pattern: /(path\.(join|resolve)|fs\.(readFile|readFileSync|createReadStream))\s*\([^)]*req\.(params|query|body)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
  },

  // ── Prototype Pollution ───────────────────────────────────────────────

  {
    id: 'VULN_PROTOTYPE_POLLUTION',
    name: 'Potential Prototype Pollution',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'Setting object properties using bracket notation with user-controlled keys can allow attackers to set __proto__ or constructor, polluting the Object prototype.',
    remediation:
      'Validate that user-supplied keys are not __proto__, constructor, or prototype before using them. Use Map instead of plain objects for user-controlled data.',
    pattern: /\w+\[req\.(body|query|params)\.\w+\]\s*=/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
    contextCheck: (ctx: RuleContext) => {
      const nearbyLines = ctx.allLines
        .slice(Math.max(0, ctx.lineIndex - 3), ctx.lineIndex + 3)
        .join('\n');
      if (nearbyLines.includes('hasOwnProperty') || nearbyLines.includes('allowedKeys')) {
        return false;
      }
      return true;
    },
  },

  // ── Open Redirect ─────────────────────────────────────────────────────

  {
    id: 'VULN_OPEN_REDIRECT',
    name: 'Open Redirect via User Input',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    description:
      'Redirecting to a URL taken directly from user input allows attackers to send users to malicious sites.',
    remediation:
      'Only redirect to URLs from a hardcoded allowlist, or strip the host and only use the path portion of user-supplied URLs.',
    pattern: /res\.redirect\s*\(\s*req\.(query|body|params)\.\w+/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
  },

  // ── Mass Assignment ───────────────────────────────────────────────────

  {
    id: 'VULN_MASS_ASSIGNMENT',
    name: 'Mass Assignment from Request Body',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'Spreading req.body directly into a database call allows attackers to set fields they should not control (e.g. isAdmin: true).',
    remediation:
      'Explicitly list accepted fields: const { name, email } = req.body. Never spread the entire body into a database call.',
    pattern: /(\.create|\.update|\.insert)\s*\(\s*\{?\s*\.\.\.req\.body/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 2,
  },

  // ── Timing Attack ─────────────────────────────────────────────────────

  {
    id: 'VULN_TIMING_ATTACK',
    name: 'Insecure Secret Comparison',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'Using == or === to compare secrets or tokens is vulnerable to timing attacks. An attacker can determine the correct value by measuring comparison time.',
    remediation:
      'Use crypto.timingSafeEqual() for all secret comparisons. This runs in constant time regardless of where strings differ.',
    pattern: /\b(token|secret|password|apiKey|api_key|hash)\s*(===|==)\s*(req\.|user\.|input)/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
  },

  // ── ReDoS ─────────────────────────────────────────────────────────────

  {
    id: 'VULN_REDOS',
    name: 'Potential ReDoS Vulnerability',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'low',
    description:
      'Regular expressions with nested quantifiers can be made to run in exponential time with crafted input, causing Denial of Service.',
    remediation:
      'Avoid nested quantifiers like (a+)+ or (.*)* . Use a tool like safe-regex to audit your patterns.',
    pattern: /\(([^()]*[+*][^()]*)\)[+*]/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
    highFalsePositiveRate: true,
  },

  // ── Deserialization ───────────────────────────────────────────────────

  {
    id: 'VULN_UNSAFE_DESERIALIZATION',
    name: 'Unsafe Deserialization of User Input',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Deserializing untrusted data with unsafe libraries can lead to Remote Code Execution.',
    remediation:
      'Never deserialize data from untrusted sources using unsafe methods. Use JSON.parse() for JSON and validate all input first.',
    pattern: /unserialize\s*\(\s*req\.(body|query|params)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
  },

  // ── Insecure Random Token ─────────────────────────────────────────────

  {
    id: 'VULN_INSECURE_RANDOM_TOKEN',
    name: 'Math.random() Used for Security Token',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    description:
      'Math.random() is used near security-sensitive variable names. Math.random() is not cryptographically secure.',
    remediation:
      'Use crypto.randomBytes(32).toString("hex") for tokens and session IDs.',
    pattern: /Math\.random\s*\(\s*\)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 3,
    contextCheck: (ctx: RuleContext) => {
      const window = ctx.allLines
        .slice(Math.max(0, ctx.lineIndex - 2), ctx.lineIndex + 3)
        .join('\n')
        .toLowerCase();
      const securityKeywords = ['token', 'session', 'secret', 'password', 'key', 'nonce', 'csrf', 'salt'];
      return securityKeywords.some(kw => window.includes(kw));
    },
  },

  // ── JWT Without Expiry ────────────────────────────────────────────────

  {
    id: 'VULN_JWT_NO_EXPIRY',
    name: 'JWT Issued Without Expiry',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'medium',
    description:
      'JWTs without an expiry are valid forever. A stolen token can be used indefinitely.',
    remediation:
      'Always set expiresIn: e.g. "15m" for access tokens, "7d" for refresh tokens.',
    pattern: /jwt\.sign\s*\(\s*\{[^}]*\}\s*,\s*[^,)]+\s*\)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 5,
    contextCheck: (ctx: RuleContext) => {
      const window = ctx.allLines
        .slice(ctx.lineIndex, ctx.lineIndex + 5)
        .join('\n');
      if (window.includes('expiresIn')) return false;
      return true;
    },
  },

  // ── Insecure Cookie ───────────────────────────────────────────────────

  {
    id: 'VULN_INSECURE_COOKIE',
    name: 'Cookie Missing Security Flags',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'medium',
    description:
      'Authentication cookies should have httpOnly (prevents JS access) and secure (HTTPS only) flags.',
    remediation:
      'Set both flags: res.cookie("session", value, { httpOnly: true, secure: true, sameSite: "strict" })',
    pattern: /res\.cookie\s*\([^)]+\)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 3,
    contextCheck: (ctx: RuleContext) => {
      const window = ctx.allLines
        .slice(ctx.lineIndex, ctx.lineIndex + 3)
        .join('\n');
      const hasHttpOnly = window.includes('httpOnly');
      const hasSecure = window.includes('secure');
      return !(hasHttpOnly && hasSecure);
    },
  },

  // ── Secret in URL ─────────────────────────────────────────────────────

  {
    id: 'VULN_SECRET_IN_URL',
    name: 'Secret Passed as URL Query Parameter',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'Passing tokens or keys as URL query parameters exposes them in browser history, server logs, and Referer headers.',
    remediation:
      'Pass sensitive values in request headers (Authorization: Bearer <token>) or the request body, never in the URL.',
    pattern: /[?&](token|api_key|apikey|password|secret|key)=/i,
    windowSize: 1,
  },

  // ── Hardcoded Crypto Key ──────────────────────────────────────────────

  {
    id: 'VULN_HARDCODED_CRYPTO_KEY',
    name: 'Hardcoded Cryptographic Key',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'high',
    description:
      'A hardcoded string is being used directly as a cryptographic key. Hardcoded keys cannot be rotated.',
    remediation:
      'Load the key from an environment variable: process.env.ENCRYPTION_KEY. Generate with crypto.randomBytes(32).',
    pattern: /createCipheriv\s*\(\s*["'][^"']+["']\s*,\s*["'][A-Za-z0-9+/=]{16,}["']/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 1,
  },

  // ── Missing Helmet ────────────────────────────────────────────────────

  {
    id: 'VULN_MISSING_HELMET',
    name: 'Express App Without Helmet',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'medium',
    description:
      'Express apps without Helmet.js are missing important HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).',
    remediation:
      'Add Helmet.js: npm install helmet, then app.use(helmet()) near the top of your middleware stack.',
    pattern: /express\s*\(\s*\)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
    windowSize: 15,
    contextCheck: (ctx: RuleContext) => {
      const following = ctx.allLines
        .slice(ctx.lineIndex, ctx.lineIndex + 20)
        .join('\n');
      if (following.includes('helmet()') || following.includes('helmet(')) {
        return false;
      }
      return true;
    },
  },
];