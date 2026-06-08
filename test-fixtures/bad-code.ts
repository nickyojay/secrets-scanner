// test-fixtures/bad-code.ts
// Intentionally vulnerable code for scanner testing.
// This file should produce findings — it is not real application code.

import crypto from 'crypto';
import path from 'path';
import jwt from 'jsonwebtoken';
import { exec } from 'child_process';

// ── Phase 1 patterns ──────────────────────────────────────────────────────

// Should trigger VULN_EVAL_USAGE
function processInput(input: string) {
  return eval(input);
}

// Should trigger VULN_WEAK_HASH_MD5
function hashPassword(password: string) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Should trigger VULN_SQL_CONCAT
function getUser(userId: string) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return query;
}

// Should trigger VULN_SSL_VERIFY_DISABLED
const options = { rejectUnauthorized: false };

// Should trigger VULN_CORS_WILDCARD
const corsConfig = { origin: '*' };

// Should trigger HYGIENE_TODO_SECURITY
// TODO: add auth validation here before deploying

// Should trigger HYGIENE_CONSOLE_LOG_SENSITIVE
function login(password: string) {
  console.log("Login attempt with password:", password);
}

// ── Phase 2 patterns ──────────────────────────────────────────────────────

// Should trigger VULN_PATH_TRAVERSAL
app.get('/file', (req: any, res: any) => {
  const filePath = path.join(__dirname, req.query.name as string);
  res.sendFile(filePath);
});

// Should trigger VULN_OPEN_REDIRECT
app.get('/login', (req: any, res: any) => {
  res.redirect(req.query.returnUrl as string);
});

// Should trigger VULN_MASS_ASSIGNMENT
app.post('/user', async (req: any, res: any) => {
  const user = await prisma.user.create({ ...req.body });
  res.json(user);
});

// Should trigger VULN_JWT_NO_EXPIRY
const token = jwt.sign({ userId: 123 }, process.env.JWT_SECRET!);

// Should trigger VULN_INSECURE_RANDOM_TOKEN
const sessionToken = Math.random().toString(36);

// Should trigger VULN_TIMING_ATTACK
if (token === req.query.token) {
  grantAccess();
}

// Should trigger VULN_INSECURE_COOKIE (missing httpOnly and secure)
res.cookie('session', token);

// This should NOT trigger VULN_INSECURE_COOKIE (both flags present)
// scanner-disable: intentionally testing cookie behavior in this test
res.cookie('test', 'value', { httpOnly: true, secure: true });