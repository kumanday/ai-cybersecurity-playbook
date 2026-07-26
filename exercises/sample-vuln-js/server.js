// INTENTIONALLY VULNERABLE TRAINING APPLICATION. DO NOT DEPLOY.
// Companion to sample-vuln-app (Python/Flask): same idea, JS/Express flavor,
// so the Tree-sitter indexer and path audit have a second language to chew on.
// Five planted vulnerability classes, mirroring the OWASP Top 10:
//   A03 SQL injection (string-concatenated query in db.js)
//   A03 OS command injection (execSync with user input)
//   A01 path traversal (unsanitized join)
//   A05 hardcoded secrets (module-level constants)
//   A05 unsafe deserialization-ish eval (config expression evaluator)
// The app is designed for STATIC analysis (Lab 8). You never need to run it.

const express = require('express');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const db = require('./db');

// VULN (A05): hardcoded secrets committed to source.
const API_KEY = 'sk-live-4f3c9e2a1b7d8c6e5f4a3b2c1d0e9f8a';
const SESSION_SECRET = 'password123';

const app = express();
app.use(express.json());

app.get('/', (req, res) => {
  res.send('vuln-js training target; see /users, /ping, /download, /config');
});

app.get('/users', async (req, res) => {
  const name = req.query.name || '';
  const rows = await db.findUsers(name);
  res.json(rows);
});

// VULN (A03): OS command injection. req.query.host reaches execSync
// through string concatenation with no validation.
app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  const out = execSync('ping -c 1 ' + host).toString();
  res.type('text').send(out);
});

// VULN (A01): path traversal. req.query.file is joined without any check,
// so /download?file=../../../../etc/passwd escapes FILES_DIR.
app.get('/download', (req, res) => {
  const target = path.join(__dirname, 'files', req.query.file || 'readme.txt');
  res.type('text').send(fs.readFileSync(target, 'utf8'));
});

// VULN (A03): code evaluation. A "templating" helper that evals user input
// inside a config expression. eval is eval, whatever the comment says.
app.post('/config', (req, res) => {
  const expr = (req.body && req.body.expr) || '1 + 1';
  const value = eval('(' + expr + ')');
  res.json({ value });
});

app.listen(3000, () => console.log('vuln-js listening on :3000'));
