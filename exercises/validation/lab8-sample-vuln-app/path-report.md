# Path-Centric Audit Report: sample-vuln-app

- Date: 2026-07-26 04:11:45
- Mode: Kimi K3 path-centric audit
- Elapsed: 42.0s
- Entry-point coverage: 8/8 entry points bundled; 9/9 functions analyzed
- Findings: critical: 3, high: 4, medium: 2
- Root-cause clusters: 9

## Root-cause clusters

| Cluster | Findings | Worst severity |
|---|---|---|
| A01 Broken Access Control @ app.py:68 | 1 | HIGH |
| A02 Cryptographic Failures @ app.py:26 | 1 | HIGH |
| A02 Cryptographic Failures @ app.py:27 | 1 | HIGH |
| A03 Injection @ app.py:51 | 1 | CRITICAL |
| A03 Injection @ app.py:60 | 1 | CRITICAL |
| A03 Injection @ app.py:76 | 1 | HIGH |
| A05 Security Misconfiguration @ app.py:94 | 1 | MEDIUM |
| A05 Security Misconfiguration @ app.py:99 | 1 | MEDIUM |
| A08 Software and Data Integrity Failures @ app.py:84 | 1 | CRITICAL |

## Findings

### 1. [CRITICAL] Insecure deserialization of request body with pickle

- **Entry point:** POST /import
- **Category:** A08 Software and Data Integrity Failures (verdict: confirmed)
- **Path:** `app.import_data (app.py:81-85)`
- **Sink line:** 84
- **Evidence:** `blob = request.get_data(); obj = pickle.loads(blob)`
- **Attack path:** Unauthenticated POST body is passed raw to pickle.loads. A crafted pickle stream executes arbitrary code during deserialization; this is unauthenticated remote code execution.
- **Fix:** Never unpickle network input. Accept JSON instead, validate it against a schema, and if binary payloads are unavoidable, sign them and verify the signature before loading.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 2. [CRITICAL] OS command injection in ping endpoint

- **Entry point:** GET /ping
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `app.ping (app.py:57-61)`
- **Sink line:** 60
- **Evidence:** `subprocess.check_output("ping -c 1 " + host, shell=True)`
- **Attack path:** Unauthenticated GET parameter 'host' is concatenated into a shell command. /ping?host=127.0.0.1;id executes arbitrary commands as the app user, and output is reflected back in the response.
- **Fix:** Drop shell=True and pass an argument list (subprocess.check_output(['ping','-c','1',host])), plus strict input validation (IP/hostname allowlist pattern).
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 3. [CRITICAL] SQL injection via string-formatted query

- **Entry point:** GET /user
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `app.user_lookup (app.py:47-53)` → `app.get_db (app.py:32-33)`
- **Sink line:** 51
- **Evidence:** `query = "SELECT id, username, role FROM users WHERE username = '%s'" % username; rows = conn.execute(query).fetchall()`
- **Attack path:** Unauthenticated GET parameter 'username' is formatted into a SQL string and executed by the get_db() connection. /user?username=' OR '1'='1 dumps the users table, and the response even echoes the raw query back to the attacker.
- **Fix:** Use parameterized queries (conn.execute('... WHERE username = ?', (username,))) and never echo the query string in responses.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 4. [MEDIUM] Flask debug mode enabled at startup

- **Entry point:** cli-main (app.py:97)
- **Category:** A05 Security Misconfiguration (verdict: confirmed)
- **Path:** `app.__main__ (app.py:97-99)`
- **Sink line:** 99
- **Evidence:** `app.run(host="127.0.0.1", port=5050, debug=True)`
- **Attack path:** Anyone able to reach port 5050 and trigger an exception gets the Werkzeug interactive debugger, which executes arbitrary Python in the app process. The loopback binding narrows exposure to local actors and SSRF-style pivots but does not remove it.
- **Fix:** Never run debug=True outside local development; drive it from an env var defaulting to off, and put a startup assertion in front of it.
- **Validate:** Start the app, curl http://127.0.0.1:5050/report to trigger an exception, and observe the Werkzeug debugger console PIN prompt.
- **Verifier notes:** Path is real (app.run with debug=True at line 99), but the loopback binding means remote exploitation requires a local foothold or an SSRF pivot; impact stays severe once reachable, likelihood is reduced.

### 5. [HIGH] Path traversal in file download

- **Entry point:** GET /download
- **Category:** A01 Broken Access Control (verdict: confirmed)
- **Path:** `app.download (app.py:65-68)`
- **Sink line:** 68
- **Evidence:** `name = request.args.get("name", "notes.txt"); send_file(os.path.join("/tmp/uploads", name))`
- **Attack path:** Unauthenticated GET parameter 'name' is joined into a filesystem path with no validation. /download?name=../../../../etc/passwd escapes /tmp/uploads and reads arbitrary files the process can open.
- **Fix:** Resolve with os.path.realpath and require the result to stay under the uploads directory (os.path.commonpath), or map names to an allowlist of known files.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 6. [HIGH] Server-side template injection in greeting

- **Entry point:** GET /greet
- **Category:** A03 Injection (verdict: confirmed)
- **Path:** `app.greet (app.py:72-77)`
- **Sink line:** 76
- **Evidence:** `template = "<h1>Hello " + name + "!</h1>"; render_template_string(template)`
- **Attack path:** Unauthenticated GET parameter 'name' is concatenated into the Jinja2 template source itself, so payload {{7*7}} evaluates, and Jinja globals (e.g. {{config}} or {{''.__class__.__mro__}} chains) expose secrets or code execution.
- **Fix:** Pass user input as template data, not template source: render_template_string('<h1>Hello {{ name }}!</h1>', name=name).
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 7. [HIGH] Hardcoded API key in source

- **Entry point:** module import / startup (app.py)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Path:** `app.py module level (app.py:26)`
- **Sink line:** 26
- **Evidence:** `API_KEY = "sk-live-9f8e7d6c5b4a3210HARDCODED"`
- **Attack path:** A live-format API key committed to source is compromised the moment it is committed; anyone with repo read access holds it, and git history keeps it after deletion.
- **Fix:** Move secrets to environment variables or a secrets manager, and rotate this key now.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 8. [HIGH] Hardcoded Flask session secret

- **Entry point:** module import / startup (app.py)
- **Category:** A02 Cryptographic Failures (verdict: confirmed)
- **Path:** `app.py module level (app.py:27)`
- **Sink line:** 27
- **Evidence:** `app.secret_key = "password123"`
- **Attack path:** A guessable, committed session secret lets anyone forge Flask session cookies, impersonating any user and tampering with session data.
- **Fix:** Load the secret from the environment with a strong random value per environment; rotate on suspicion.
- **Validate:** Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
- **Verifier notes:** Each hop connects: the entry point reads attacker input and it reaches the sink with no validation anywhere along the bundle.

### 9. [MEDIUM] Error response leaks internals (DB path, API key prefix)

- **Entry point:** GET /report
- **Category:** A05 Security Misconfiguration
- **Path:** `app.report (app.py:89-94)`
- **Sink line:** 94
- **Evidence:** `return f"debug trace: {exc!r} db={DB_PATH} key={API_KEY[:12]}...", 500`
- **Attack path:** Unauthenticated requests receive exception details, the database path, and the first 12 characters of the API key, which aids key-guessing and maps internals for follow-on attacks.
- **Fix:** Return a generic error page to clients and log the detailed trace server-side only; never include secret material, even prefixes, in responses.
