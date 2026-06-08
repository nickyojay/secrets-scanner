import { ScanRule } from '../types';

export const vulnerabilityRules: ScanRule[] = [

  // ── Dangerous Functions ───────────────────────────────────────────────

  {
    id: 'VULN_EVAL_USAGE',
    name: 'eval() Usage',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'eval() executes arbitrary JavaScript from a string. If user input ever reaches it, that is Remote Code Execution.',
    remediation:
      'Remove eval() entirely. Use JSON.parse() for JSON data. There is almost never a legitimate reason to use eval() in production code.',
    pattern: /\beval\s*\(/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_FUNCTION_CONSTRUCTOR',
    name: 'Function Constructor Usage',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'new Function(string) is equivalent to eval() — it executes arbitrary code from a string and is often missed in code reviews.',
    remediation: 'Avoid constructing functions from strings. Refactor to static code.',
    pattern: /new\s+Function\s*\(/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_CHILD_PROCESS_EXEC',
    name: 'child_process exec with Variable Input',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'exec() passes the command to the shell. If any part is user-controlled, this is Command Injection.',
    remediation:
      'Use execFile() or spawn() instead — they do not invoke a shell and take arguments as an array.',
    pattern: /\bexec\s*\(\s*[`'"].*?\+|\.exec\s*\(\s*`/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },

  // ── Weak Cryptography ─────────────────────────────────────────────────

  {
    id: 'VULN_WEAK_HASH_MD5',
    name: 'MD5 Hash Usage',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    description:
      'MD5 is cryptographically broken. Collisions can be computed in seconds on consumer hardware.',
    remediation:
      'Replace with SHA-256 or SHA-3 for integrity checks. For passwords, use bcrypt, scrypt, or Argon2.',
    pattern: /createHash\s*\(\s*["']md5["']\)/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_WEAK_HASH_SHA1',
    name: 'SHA-1 Hash Usage',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'high',
    description:
      'SHA-1 is deprecated for security use. Practical collision attacks have been demonstrated (SHAttered, 2017).',
    remediation: 'Replace with SHA-256 or SHA-3 for any security-sensitive hashing.',
    pattern: /createHash\s*\(\s*["']sha1["']\)/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_WEAK_CIPHER_DES',
    name: 'DES/3DES Cipher Usage',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'high',
    description:
      'DES uses a 56-bit key and is trivially brute-forceable. 3DES is deprecated by NIST.',
    remediation: 'Replace with AES-256-GCM.',
    pattern: /createCipher(iv)?\s*\(\s*["'](des|des-ede|des-ede3)[^"']*["']/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_MATH_RANDOM',
    name: 'Math.random() for Security',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'low',
    description:
      'Math.random() is NOT cryptographically secure. Do not use it for tokens, passwords, or session IDs.',
    remediation:
      'Use crypto.randomBytes() in Node.js or crypto.getRandomValues() in the browser.',
    pattern: /\bMath\.random\s*\(\s*\)/,
    highFalsePositiveRate: true,
  },

  // ── Injection ─────────────────────────────────────────────────────────

  {
    id: 'VULN_SQL_CONCAT',
    name: 'SQL Query String Concatenation',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'medium',
    description:
      'Building SQL queries by concatenating strings with variables is the classic SQL Injection vulnerability.',
    remediation:
      'Use parameterized queries. With raw drivers: db.query("SELECT * FROM users WHERE id = ?", [id]). With Prisma or TypeORM, use the query builder — never raw string interpolation.',
    pattern: /["'`]\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\s[^"'`]*["'`]\s*\+|`\s*(SELECT|INSERT|UPDATE|DELETE)\s[^`]*\$\{/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_NOSQL_INJECTION',
    name: 'Potential NoSQL Injection',
    category: 'vulnerability',
    severity: 'high',
    confidence: 'medium',
    description:
      'Passing unvalidated req.body or req.query directly into MongoDB queries can lead to NoSQL injection.',
    remediation:
      'Validate all query inputs with Zod or Joi. Never pass req.body directly to find() or findOne().',
    pattern: /\.(find|findOne|findOneAndUpdate|deleteMany)\s*\(\s*req\.(body|query|params)/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },

  // ── Security Misconfiguration ─────────────────────────────────────────

  {
    id: 'VULN_CORS_WILDCARD',
    name: 'CORS Wildcard Origin',
    category: 'vulnerability',
    severity: 'medium',
    confidence: 'high',
    description:
      'Setting CORS origin to "*" allows any website to make requests to your API.',
    remediation:
      'Specify explicit allowed origins: cors({ origin: ["https://yourdomain.com"] }).',
    pattern: /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'VULN_SSL_VERIFY_DISABLED',
    name: 'SSL Certificate Verification Disabled',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'high',
    description:
      'Disabling SSL certificate verification makes the app vulnerable to man-in-the-middle attacks.',
    remediation:
      'Never set rejectUnauthorized: false in production. Add the CA certificate instead if using self-signed certs.',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.env'],
  },

  // ── Auth & Sessions ───────────────────────────────────────────────────

  {
    id: 'VULN_WEAK_JWT_ALGORITHM',
    name: 'JWT Using "none" Algorithm',
    category: 'vulnerability',
    severity: 'critical',
    confidence: 'high',
    description:
      'JWT signed with algorithm "none" is completely unsigned and trivially forgeable.',
    remediation:
      'Use RS256 or ES256. Never accept "none" as an algorithm. Verify the alg header matches what your server expects.',
    pattern: /algorithm\s*:\s*["']none["']|algorithms?\s*:\s*\[\s*["']none["']/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
];