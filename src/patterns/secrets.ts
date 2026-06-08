import { ScanRule } from '../types';

export const secretRules: ScanRule[] = [

  // ── Cloud Providers ──────────────────────────────────────────────────

  {
    id: 'SECRET_AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'AWS Access Key IDs always start with AKIA or ASIA',
    remediation:
      'Rotate this key immediately in AWS IAM. Audit CloudTrail for unauthorized usage. Use IAM roles or environment variables instead of hardcoded credentials.',
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: 'SECRET_AWS_SECRET_KEY',
    name: 'AWS Secret Access Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'medium',
    description: 'AWS Secret Access Keys are 40-char strings near the aws_secret keyword',
    remediation:
      'Rotate this key immediately in AWS IAM. Use environment variables or AWS Secrets Manager.',
    pattern: /aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
  },
  {
    id: 'SECRET_GCP_API_KEY',
    name: 'Google Cloud API Key',
    category: 'secret',
    severity: 'high',
    confidence: 'high',
    description: 'GCP API keys start with AIza followed by 35 characters',
    remediation:
      'Restrict or rotate this key in the Google Cloud Console. Apply API restrictions to limit what the key can access.',
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
  },
  {
    id: 'SECRET_GCP_SERVICE_ACCOUNT',
    name: 'Google Service Account Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'Service account JSON files contain private keys',
    remediation:
      'Delete this key in GCP IAM, generate a new one, and store it using Secret Manager.',
    pattern: /"type"\s*:\s*"service_account"/,
    fileExtensions: ['.json'],
  },

  // ── AI Provider Keys ─────────────────────────────────────────────────

  {
    id: 'SECRET_ANTHROPIC_API_KEY',
    name: 'Anthropic API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'Anthropic API keys start with sk-ant-',
    remediation:
      'Revoke this key at console.anthropic.com. Use the ANTHROPIC_API_KEY environment variable.',
    pattern: /sk-ant-[A-Za-z0-9\-_]{32,}/,
  },
  {
    id: 'SECRET_OPENAI_API_KEY',
    name: 'OpenAI API Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'medium',
    description: 'OpenAI API keys start with sk-',
    remediation:
      'Revoke this key at platform.openai.com. Use the OPENAI_API_KEY environment variable.',
    pattern: /sk-[A-Za-z0-9]{20,}/,
  },

  // ── Version Control ──────────────────────────────────────────────────

  {
    id: 'SECRET_GITHUB_TOKEN',
    name: 'GitHub Personal Access Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'GitHub PATs use ghp_, gho_, ghu_, ghs_, or ghr_ prefixes',
    remediation:
      'Revoke this token at github.com/settings/tokens. GitHub auto-revokes tokens found in public repos.',
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/,
  },
  {
    id: 'SECRET_GITLAB_TOKEN',
    name: 'GitLab Personal Access Token',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'GitLab PATs start with glpat-',
    remediation: 'Revoke this token in your GitLab user settings under Access Tokens.',
    pattern: /glpat-[A-Za-z0-9\-_]{20}/,
  },

  // ── Payment ──────────────────────────────────────────────────────────

  {
    id: 'SECRET_STRIPE_SECRET_KEY',
    name: 'Stripe Secret Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'Stripe secret keys start with sk_live_ or sk_test_',
    remediation:
      'Roll this key in the Stripe dashboard immediately. Live keys (sk_live_) are a security incident — audit your Stripe logs.',
    pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/,
  },
  {
    id: 'SECRET_STRIPE_PUBLISHABLE_KEY',
    name: 'Stripe Publishable Key',
    category: 'secret',
    severity: 'low',
    confidence: 'high',
    description: 'Stripe publishable keys (pk_) are lower risk but should not be in server-side code',
    remediation:
      'Publishable keys are for client-side use only. Avoid committing them to version control.',
    pattern: /pk_(live|test)_[A-Za-z0-9]{24,}/,
  },

  // ── Communication ────────────────────────────────────────────────────

  {
    id: 'SECRET_TWILIO_SID',
    name: 'Twilio Account SID',
    category: 'secret',
    severity: 'high',
    confidence: 'medium',
    description: 'Twilio Account SIDs start with AC followed by 32 hex characters',
    remediation: 'Rotate credentials in the Twilio console. Use environment variables.',
    pattern: /AC[a-f0-9]{32}/,
  },
  {
    id: 'SECRET_SENDGRID_KEY',
    name: 'SendGrid API Key',
    category: 'secret',
    severity: 'high',
    confidence: 'high',
    description: 'SendGrid API keys start with SG.',
    remediation:
      'Revoke this key and generate a new restricted key with minimum required permissions.',
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/,
  },
  {
    id: 'SECRET_SLACK_TOKEN',
    name: 'Slack Token',
    category: 'secret',
    severity: 'high',
    confidence: 'high',
    description: 'Slack tokens use xox prefixes (xoxb-, xoxp-, xoxa-, xoxr-)',
    remediation:
      'Revoke this token at api.slack.com/apps. Audit Slack logs for unauthorized access.',
    pattern: /xox[bpars]-[A-Za-z0-9\-]{10,}/,
  },
  {
    id: 'SECRET_DISCORD_TOKEN',
    name: 'Discord Bot Token',
    category: 'secret',
    severity: 'high',
    confidence: 'medium',
    description: 'Discord bot tokens follow a specific base64 pattern',
    remediation:
      'Regenerate the bot token in the Discord Developer Portal.',
    pattern: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}/,
  },

  // ── Databases ────────────────────────────────────────────────────────

  {
    id: 'SECRET_MONGODB_URI',
    name: 'MongoDB Connection String with Credentials',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'MongoDB URIs containing username:password',
    remediation:
      'Rotate the database user password immediately. Use a DATABASE_URL environment variable.',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/i,
  },
  {
    id: 'SECRET_POSTGRES_URI',
    name: 'PostgreSQL Connection String with Credentials',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'PostgreSQL URIs containing username:password',
    remediation:
      'Rotate the database user password immediately. Use a DATABASE_URL environment variable.',
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s"']+/i,
  },
  {
    id: 'SECRET_MYSQL_URI',
    name: 'MySQL Connection String with Credentials',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'MySQL URIs containing username:password',
    remediation: 'Rotate the database user password. Use environment variables for connection strings.',
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/i,
  },

  // ── Private Keys ─────────────────────────────────────────────────────

  {
    id: 'SECRET_RSA_PRIVATE_KEY',
    name: 'RSA Private Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'PEM-encoded RSA private key block',
    remediation:
      'Revoke and regenerate this key pair immediately. Use a secrets manager like HashiCorp Vault. Never commit private keys.',
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: 'SECRET_SSH_PRIVATE_KEY',
    name: 'SSH Private Key',
    category: 'secret',
    severity: 'critical',
    confidence: 'high',
    description: 'OpenSSH private key block',
    remediation:
      'Remove from git history using BFG Repo Cleaner, revoke access on all servers, generate a new key pair.',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/,
  },

  // ── Generic (higher false positive rate) ─────────────────────────────

  {
    id: 'SECRET_GENERIC_API_KEY',
    name: 'Generic API Key Assignment',
    category: 'secret',
    severity: 'medium',
    confidence: 'low',
    description: 'A variable named api_key or apiKey assigned a value',
    remediation: 'Move this value to an environment variable.',
    pattern: /\bapi[_-]?key\s*[=:]\s*["']([A-Za-z0-9\-_./+=]{8,})["']/i,
    highFalsePositiveRate: true,
  },
  {
    id: 'SECRET_GENERIC_PASSWORD',
    name: 'Hardcoded Password',
    category: 'secret',
    severity: 'high',
    confidence: 'low',
    description: 'A variable named password assigned a non-placeholder string',
    remediation: 'Never hardcode passwords. Use environment variables.',
    pattern: /\bpass(word|wd|phrase)?\s*[=:]\s*["']([A-Za-z0-9!@#$%^&*\-_]{6,})["']/i,
    highFalsePositiveRate: true,
  },
  {
    id: 'SECRET_JWT_SECRET',
    name: 'Hardcoded JWT Secret',
    category: 'secret',
    severity: 'high',
    confidence: 'medium',
    description: 'JWT secret key hardcoded in source',
    remediation:
      'Move to a JWT_SECRET environment variable. Use a cryptographically random value of at least 256 bits.',
    pattern: /jwt[_-]?secret\s*[=:]\s*["']([A-Za-z0-9!@#$%^&*\-_./+=]{8,})["']/i,
  },
];