# Dynamic Verification Targets

Confirmed high-severity path findings, formatted as targets for a
dynamic agent (Strix/Shannon, Labs 1-2) running against a LOCAL,
authorized instance. This script does not fire exploits.

## Insecure deserialization of request body with pickle (CRITICAL)
- Entry point: POST /import
- Path: app.import_data (app.py:81-85)
- What to prove: Unauthenticated POST body is passed raw to pickle.loads. A crafted pickle stream executes arbitrary code during deserialization; this is unauthenticated remote code execution.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## OS command injection in ping endpoint (CRITICAL)
- Entry point: GET /ping
- Path: app.ping (app.py:57-61)
- What to prove: Unauthenticated GET parameter 'host' is concatenated into a shell command. /ping?host=127.0.0.1;id executes arbitrary commands as the app user, and output is reflected back in the response.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## SQL injection via string-formatted query (CRITICAL)
- Entry point: GET /user
- Path: app.user_lookup (app.py:47-53) -> app.get_db (app.py:32-33)
- What to prove: Unauthenticated GET parameter 'username' is formatted into a SQL string and executed by the get_db() connection. /user?username=' OR '1'='1 dumps the users table, and the response even echoes the raw query back to the attacker.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Path traversal in file download (HIGH)
- Entry point: GET /download
- Path: app.download (app.py:65-68)
- What to prove: Unauthenticated GET parameter 'name' is joined into a filesystem path with no validation. /download?name=../../../../etc/passwd escapes /tmp/uploads and reads arbitrary files the process can open.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Server-side template injection in greeting (HIGH)
- Entry point: GET /greet
- Path: app.greet (app.py:72-77)
- What to prove: Unauthenticated GET parameter 'name' is concatenated into the Jinja2 template source itself, so payload {{7*7}} evaluates, and Jinja globals (e.g. {{config}} or {{''.__class__.__mro__}} chains) expose secrets or code execution.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Hardcoded API key in source (HIGH)
- Entry point: module import / startup (app.py)
- Path: app.py module level (app.py:26)
- What to prove: A live-format API key committed to source is compromised the moment it is committed; anyone with repo read access holds it, and git history keeps it after deletion.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Hardcoded Flask session secret (HIGH)
- Entry point: module import / startup (app.py)
- Path: app.py module level (app.py:27)
- What to prove: A guessable, committed session secret lets anyone forge Flask session cookies, impersonating any user and tampering with session data.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
