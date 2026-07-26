# Path-Centric Audit Report: sample-vuln-js

- Date: 2026-07-26 03:59:33
- Mode: Kimi K3 path-centric audit
- Elapsed: 42.0s
- Entry-point coverage: 5/5 entry points bundled; 7/7 functions analyzed
- Findings: critical: 3, high: 3
- Root-cause clusters: 6

## Root-cause clusters

| Cluster | Findings | Worst severity |
|---|---|---|
| A01 Broken Access Control @ server.js:47 | 1 | HIGH |
| A02 Cryptographic Failures @ server.js:17 | 1 | HIGH |
| A02 Cryptographic Failures @ server.js:18 | 1 | HIGH |
| A03 Injection @ server.js:12 | 1 | CRITICAL |
| A03 Injection @ server.js:38 | 1 | CRITICAL |
| A03 Injection @ server.js:55 | 1 | CRITICAL |

## Findings

### 1. [CRITICAL] OS command injection via execSync

- **Entry point:** GET /ping
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `server.handler_get_ping (server.js:36-39)`
- **Sink line:** 38
- **Evidence:** `const out = execSync('ping -c 1 ' + host).toString();`
- **Attack path:** Unauthenticated req.query.host is concatenated into a shell command. /ping?host=127.0.0.1;id runs arbitrary commands as the node process user and reflects output.
- **Fix:** Use execFileSync('ping', ['-c','1', host]) (no shell), and validate host against a strict IP/hostname pattern first.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 2. [CRITICAL] SQL injection via string concatenation across files

- **Entry point:** GET /users
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `server.handler_get_users (server.js:28-31)` → `db.findUsers (db.js:10-13)`
- **Sink line:** 12
- **Evidence:** `const sql = "SELECT * FROM users WHERE name = '" + name + "'"; return conn.query(sql);`
- **Attack path:** Unauthenticated req.query.name crosses the module boundary into db.findUsers and lands in the SQL string unescaped. /users?name=' OR '1'='1 dumps the users table.
- **Fix:** Parameterized query in db.js (conn.query('SELECT ... WHERE name = ?', [name]) or the driver's equivalent); never concatenate request data into SQL.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 3. [CRITICAL] Remote code execution via eval on request body

- **Entry point:** POST /config
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `server.handler_post_config (server.js:53-56)`
- **Sink line:** 55
- **Evidence:** `const value = eval('(' + expr + ')');`
- **Attack path:** Unauthenticated req.body.expr is evaluated as JavaScript by eval. Any expression, including require('child_process').execSync(...), executes; this is unauthenticated RCE.
- **Fix:** Remove eval entirely. If expression evaluation is a real requirement, use a sandboxed expression parser with an allowlist of operators and no scope access.
- **Validate:** POST {"expr": "1+1"} and observe 2; then with a harmless marker like globalThis.__poc = true.
- **Verifier notes:** req.body.expr flows directly into eval with no indirection; JSON body parsing is already enabled, so no content-type trickery is needed.

### 4. [HIGH] Path traversal in file download

- **Entry point:** GET /download
- **Category:** A01 Broken Access Control (verdict: confirmed)
- **Path:** `server.handler_get_download (server.js:45-48)`
- **Sink line:** 47
- **Evidence:** `const target = path.join(__dirname, 'files', req.query.file || 'readme.txt'); fs.readFileSync(target)`
- **Attack path:** Unauthenticated req.query.file is joined into a filesystem path without validation. /download?file=../../../../etc/passwd escapes the files directory; path.join does not protect against .. segments.
- **Fix:** Resolve with path.resolve and require the result to start with the files directory, or serve from an allowlist of known filenames.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 5. [HIGH] Hardcoded API key in source

- **Entry point:** module import / startup (server.js)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Path:** `server.js module level (server.js:17)`
- **Sink line:** 17
- **Evidence:** `const API_KEY = 'sk-live-4f3c9e2a1b7d8c6e5f4a3b2c1d0e9f8a';`
- **Attack path:** A live-format API key committed to source is compromised on commit; repo readers and git history both hold it.
- **Fix:** Move to environment variables or a secrets manager; rotate the key now.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 6. [HIGH] Hardcoded session secret

- **Entry point:** module import / startup (server.js)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Path:** `server.js module level (server.js:18)`
- **Sink line:** 18
- **Evidence:** `const SESSION_SECRET = 'password123';`
- **Attack path:** A guessable committed session secret lets attackers forge or tamper with session data in any middleware that uses it.
- **Fix:** Load from the environment with a strong random value per environment.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.
