import { ScanRule } from '../types';

export const hygieneRules: ScanRule[] = [
  {
    id: 'HYGIENE_HARDCODED_IP',
    name: 'Hardcoded IP Address',
    category: 'hygiene',
    severity: 'low',
    confidence: 'high',
    description:
      'Hardcoded IPs make infrastructure changes painful and can expose internal network topology.',
    remediation: 'Use environment variables or service discovery for hostnames and IPs.',
    pattern: /\b(?!127\.0\.0\.1|0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}\b/,
    highFalsePositiveRate: true,
  },
  {
    id: 'HYGIENE_TODO_SECURITY',
    name: 'Security-Related TODO Comment',
    category: 'hygiene',
    severity: 'info',
    confidence: 'medium',
    description: 'A TODO or FIXME comment referencing security, auth, or validation.',
    remediation: 'Address this before shipping to production.',
    pattern: /\/\/\s*(TODO|FIXME|HACK|XXX)[^:]*:?\s*.*(auth|security|secret|token|password|cred|vuln|sanitize|validate)/i,
  },
  {
    id: 'HYGIENE_CONSOLE_LOG_SENSITIVE',
    name: 'console.log of Sensitive Data',
    category: 'hygiene',
    severity: 'low',
    confidence: 'medium',
    description: 'Logging potentially sensitive values (tokens, passwords) to the console.',
    remediation:
      'Remove debug logging of sensitive values. Use a structured logger with redaction.',
    pattern: /console\.(log|debug|info|warn|error)\s*\([^)]*\b(password|token|secret|key|auth|credential)[^)]*\)/i,
    fileExtensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'],
  },
  {
    id: 'HYGIENE_COMMENTED_CREDENTIALS',
    name: 'Commented-Out Credentials',
    category: 'hygiene',
    severity: 'medium',
    confidence: 'low',
    description: 'What appears to be a credential or secret in a comment.',
    remediation:
      'Remove it entirely. Comments are stored in git history and visible to anyone with repo access.',
    pattern: /\/\/.*\b(password|secret|api_key|token|credential)\s*[=:]\s*\S+/i,
    highFalsePositiveRate: true,
  },
  {
    id: 'HYGIENE_DOTENV_COMMITTED',
    name: '.env File Committed',
    category: 'hygiene',
    severity: 'high',
    confidence: 'high',
    description: '.env files often contain real secrets and should never be in version control.',
    remediation:
      'Add .env to .gitignore immediately. Rotate all secrets it contained. Commit a .env.example with placeholder values instead.',
    // /.* matches any content — the finding triggers just from the file existing
    // The engine has special handling for this pattern
    pattern: /.*/,
    fileExtensions: ['.env'],
  },
  {
    id: 'HYGIENE_PRIVATE_KEY_FILE',
    name: 'Private Key File',
    category: 'hygiene',
    severity: 'critical',
    confidence: 'high',
    description: 'A file with a .pem, .key, .p12, or .pfx extension was found.',
    remediation:
      'Add *.pem, *.key, *.p12, *.pfx to .gitignore and remove from git history.',
    pattern: /.*/,
    fileExtensions: ['.pem', '.key', '.p12', '.pfx', '.p8'],
  },
];