# Security Audit Report: sample-vuln-app

- Date: 2026-07-26 04:11:30
- Mode: Kimi K3 divide-and-conquer audit
- Elapsed: 0.0s
- Findings: critical: 3, high: 5, medium: 1

## Findings

### 1. [CRITICAL] SQL injection via string-formatted query

- **File:** `app.py` (line 51)
- **Category:** A03 Injection (verdict: confirmed)
- **Evidence:** `query = "SELECT id, username, role FROM users WHERE username = '%s'" % username`
- **Attack path:** GET /user takes request.args['username'] into raw SQL; ' OR '1'='1 dumps the table.
- **Fix:** Parameterize: conn.execute('... WHERE username = ?', (username,)).
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 2. [CRITICAL] OS command injection with shell=True

- **File:** `app.py` (line 60)
- **Category:** A03 Injection (verdict: confirmed)
- **Evidence:** `subprocess.check_output("ping -c 1 " + host, shell=True)`
- **Attack path:** GET /ping concatenates request.args['host'] into a shell command; ?host=127.0.0.1;id executes anything.
- **Fix:** argument list without shell, plus strict host validation.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 3. [CRITICAL] Insecure pickle deserialization in /import

- **File:** `app.py` (line 84)
- **Category:** A08 Software and Data Integrity Failures (verdict: confirmed)
- **Evidence:** `blob = request.get_data(); obj = pickle.loads(blob)`
- **Attack path:** Unauthenticated POST body to pickle.loads is unauthenticated RCE.
- **Fix:** JSON + schema validation; never unpickle network input.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 4. [HIGH] Hardcoded API key

- **File:** `app.py` (line 26)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Evidence:** `API_KEY = "sk-live-9f8e7d6c5b4a3210HARDCODED"`
- **Attack path:** Committed live-format key is compromised on commit; rotate.
- **Fix:** Env vars / secrets manager; rotate now.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 5. [HIGH] Hardcoded session secret

- **File:** `app.py` (line 27)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Evidence:** `app.secret_key = "password123"`
- **Attack path:** Guessable session secret enables session forgery.
- **Fix:** Strong random value from env.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 6. [HIGH] Path traversal in /download

- **File:** `app.py` (line 68)
- **Category:** A01 Broken Access Control (verdict: confirmed)
- **Evidence:** `return send_file(os.path.join("/tmp/uploads", name))`
- **Attack path:** ?name=../../../../etc/passwd escapes the uploads dir.
- **Fix:** realpath + commonpath containment check, or an allowlist.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 7. [HIGH] Server-side template injection in /greet

- **File:** `app.py` (line 76)
- **Category:** A03 Injection (verdict: confirmed)
- **Evidence:** `template = "<h1>Hello " + name + "!</h1>"; render_template_string(template)`
- **Attack path:** name becomes template source; {{config}} leaks secrets, Jinja chains reach RCE.
- **Fix:** render_template_string('...{{ name }}...', name=name).
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 8. [HIGH] Debug mode enabled

- **File:** `app.py` (line 99)
- **Category:** A05 Security Misconfiguration (verdict: confirmed)
- **Evidence:** `app.run(host="127.0.0.1", port=5050, debug=True)`
- **Attack path:** Werkzeug debugger = code execution for whoever reaches the port; loopback narrows, does not remove.
- **Fix:** Env-gated debug defaulting to off.
- **Validate:** Fire the benign probe for the class (quote, metachar, traversal) and observe.
- **Verifier notes:** The flagged line does what the finding claims and input reaches it unvalidated.

### 9. [MEDIUM] Error response leaks internals

- **File:** `app.py` (line 94)
- **Category:** A05 Security Misconfiguration
- **Evidence:** `return f"debug trace: {exc!r} db={DB_PATH} key={API_KEY[:12]}...", 500`
- **Attack path:** Exception detail, DB path, and 12 chars of the API key leak to any unauthenticated caller.
- **Fix:** Generic client error; log detail server-side.
