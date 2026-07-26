# sample-vuln-app: intentionally vulnerable training target

**Do not deploy. Do not expose to any network. Localhost, throwaway environments only.**

This 7-endpoint Flask app exists so the labs in the playbook have a safe,
self-contained target with known vulnerabilities:

| Endpoint | Planted weakness | Maps to |
|---|---|---|
| `GET /user?username=` | SQL injection via string formatting | OWASP A03 |
| `GET /ping?host=` | OS command injection (`shell=True`) | OWASP A03 |
| `GET /download?name=` | Path traversal, no validation | OWASP A01 |
| `GET /greet?name=` | Server-side template injection | OWASP A03 |
| `POST /import` | `pickle.loads` on request body | OWASP A08 |
| `GET /report` | Internal details leaked in error page | OWASP A05 |
| module level | Hardcoded API key + weak session secret, `debug=True` | OWASP A07 / A05 |

## Use it

```bash
# Static audit only (Lab 3), no need to run the app at all:
python3 ../scripts/code_audit.py ../sample-vuln-app --out ./out --verify

# Optional: run it locally if a lab asks for a live target (Lab 6 fix-verify):
pip install flask
python3 app.py        # serves on http://127.0.0.1:5050
```

The point of the exercise is not the app; it is watching how the
divide-and-conquer audit maps, prioritizes, finds, and verifies each issue,
then confirming your fix closes the hole.
