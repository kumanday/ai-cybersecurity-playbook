# Dynamic Verification Targets

Confirmed high-severity path findings, formatted as targets for a
dynamic agent (Strix/Shannon, Labs 1-2) running against a LOCAL,
authorized instance. This script does not fire exploits.

## OS command injection via execSync (CRITICAL)
- Entry point: GET /ping
- Path: server.handler_get_ping (server.js:36-39)
- What to prove: Unauthenticated req.query.host is concatenated into a shell command. /ping?host=127.0.0.1;id runs arbitrary commands as the node process user and reflects output.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## SQL injection via string concatenation across files (CRITICAL)
- Entry point: GET /users
- Path: server.handler_get_users (server.js:28-31) -> db.findUsers (db.js:10-13)
- What to prove: Unauthenticated req.query.name crosses the module boundary into db.findUsers and lands in the SQL string unescaped. /users?name=' OR '1'='1 dumps the users table.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Remote code execution via eval on request body (CRITICAL)
- Entry point: POST /config
- Path: server.handler_post_config (server.js:53-56)
- What to prove: Unauthenticated req.body.expr is evaluated as JavaScript by eval. Any expression, including require('child_process').execSync(...), executes; this is unauthenticated RCE.
- Safe validation: POST {"expr": "1+1"} and observe 2; then with a harmless marker like globalThis.__poc = true.

## Path traversal in file download (HIGH)
- Entry point: GET /download
- Path: server.handler_get_download (server.js:45-48)
- What to prove: Unauthenticated req.query.file is joined into a filesystem path without validation. /download?file=../../../../etc/passwd escapes the files directory; path.join does not protect against .. segments.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Hardcoded API key in source (HIGH)
- Entry point: module import / startup (server.js)
- Path: server.js module level (server.js:17)
- What to prove: A live-format API key committed to source is compromised on commit; repo readers and git history both hold it.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.

## Hardcoded session secret (HIGH)
- Entry point: module import / startup (server.js)
- Path: server.js module level (server.js:18)
- What to prove: A guessable committed session secret lets attackers forge or tamper with session data in any middleware that uses it.
- Safe validation: Trigger the route with the class-typical probe (a quote, a metacharacter, or a traversal sequence) and observe the unsafe behavior in the response or on the host.
