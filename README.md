# Secrets Scanner

A developer tool for scanning codebases for leaked secrets and security vulnerabilities. Built with Node.js and TypeScript.

**[Live Dashboard](https://secrets-scanner-production-cb30.up.railway.app)** — upload a zip of any project and see findings in your browser.

---

## What it detects

**Secrets** — API keys, tokens, and credentials that should never be in source code:
- AWS, GCP, and cloud provider credentials
- AI provider keys (OpenAI, Anthropic)
- GitHub, GitLab tokens
- Stripe, Twilio, SendGrid, Slack, Discord keys
- Database connection strings with credentials (PostgreSQL, MongoDB, MySQL)
- Private keys and certificates (.pem, .key, SSH, PGP)
- Hardcoded JWT secrets and passwords

**Vulnerabilities** — dangerous code patterns that can be exploited:
- `eval()` and `new Function()` — Remote Code Execution risk
- SQL string concatenation — SQL Injection
- Path traversal via user input
- Mass assignment from `req.body`
- Open redirect via user input
- Weak cryptography (MD5, SHA-1, DES, RC4)
- `Math.random()` used for security tokens
- SSL certificate verification disabled
- JWT issued without expiry
- Insecure cookie flags
- Timing attacks on secret comparison
- CORS wildcard origin

**Hygiene** — code habits that create security risk over time:
- Committed `.env` files
- `console.log` of sensitive data
- Security-related TODO comments
- Commented-out credentials
- Hardcoded IP addresses

---

## CLI

### Install

```bash
npm install -g secrets-scanner
```

### Usage

```bash
# Scan a directory
secrets-scan ./my-project

# Only critical and high findings
secrets-scan ./my-project --severity critical,high

# Secrets only
secrets-scan ./my-project --category secret

# JSON output
secrets-scan ./my-project --format json

# CI/CD mode — exits with code 1 if critical findings exist
secrets-scan ./my-project --fail-on critical

# Include findings suppressed by scanner-disable comments
secrets-scan ./my-project --show-suppressed

# Help
secrets-scan --help
```

### CI/CD integration

Add this to your GitHub Actions workflow to block PRs with critical findings:

```yaml
- name: Scan for secrets
  run: |
    npm install -g secrets-scanner
    secrets-scan ./src --fail-on critical --format json > findings.json
```

### Suppressing false positives

If a finding is intentional, add a comment on the line above to suppress it:

```typescript
// scanner-disable: using eval intentionally in sandbox environment
const result = eval(sandboxedCode);
```

---

## Web Dashboard

Upload a `.zip` of any project at [secrets-scanner-production-cb30.up.railway.app](https://secrets-scanner-production-cb30.up.railway.app) to scan it through the browser.

Features:
- Drag and drop zip upload
- Filter findings by severity and category
- Click any finding to expand the code snippet and remediation advice
- Severity summary chips to quickly toggle severity levels on and off
- Search across rule names, file paths, and keywords

---

## How it works

The scanner is built in three layers:

**Pattern library** — 40+ regex rules across secrets, vulnerabilities, and hygiene categories. Each rule has a severity level, confidence rating, and specific remediation advice.

**Scanning engine** — walks the directory tree respecting `.gitignore`, skips binary files and files over 1MB, then applies rules against each file. Supports single-line and multi-line pattern matching. Context-aware rules inspect surrounding lines before firing to reduce false positives.

**Output layer** — the CLI and web dashboard are separate consumers of the same engine. The CLI formats results for the terminal. The web API accepts zip uploads, runs the engine, and returns JSON for the dashboard to render.

---

## Running locally

```bash
git clone https://github.com/nickyojay/secrets-scanner
cd secrets-scanner
npm install

# Run the test suite against the intentionally vulnerable fixtures
npm test

# Start the web dashboard
npm run web

# Use the CLI directly
npm run cli -- ./my-project
```

---

## Stack

- **Runtime** — Node.js + TypeScript
- **Web server** — Express
- **File uploads** — Multer + Unzipper
- **CLI output** — Chalk
- **Deployment** — Railway
- **Published** — [npmjs.com/package/secrets-scanner](https://www.npmjs.com/package/secrets-scanner)

---

## Author

Built by Nick — [github.com/nickyojay](https://github.com/nickyojay)
