# sample-vuln-js: intentionally vulnerable training target (Express)

Second-language companion to `sample-vuln-app` (Flask). Same teaching
purpose, different parser path: this app exists so Lab 8's Tree-sitter index
and path audit have JavaScript to work on, including a cross-file attack path
(`GET /users` in `server.js` reaches the SQLi sink in `db.js`).

Planted vulnerability classes:

| # | Class | Where |
|---|---|---|
| 1 | SQL injection | `db.js` `findUsers`, reachable from `GET /users` |
| 2 | OS command injection | `server.js` `/ping` (`execSync` + user input) |
| 3 | Path traversal | `server.js` `/download` (unsanitized `path.join`) |
| 4 | Hardcoded secrets | `server.js` module level (`API_KEY`, `SESSION_SECRET`) |
| 5 | Code evaluation | `server.js` `/config` (`eval` on request body) |

You never need to run it; the exercises are static. If you do want it live
for dynamic work (Strix/Shannon), it is a plain Express app, but **only bind
it to localhost**, exactly like the Flask target:

```bash
npm install express
node server.js   # listens on :3000; keep it local, it is full of holes
```
