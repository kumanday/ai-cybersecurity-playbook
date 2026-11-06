# AI Cybersecurity Playbook

Practical controls, agentic testing workflows, and incident-response exercises
for builders, operators, and security professionals.

- [Read the interactive playbook](https://kumanday.github.io/ai-cybersecurity-playbook/)
- [Open the exercise pack](https://github.com/kumanday/ai-cybersecurity-playbook/tree/main/exercises)

## Run the exercises

Python 3.10 or later is required.

```bash
cd exercises
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

# Offline pipeline checks. These make no model calls and upload no data.
python3 scripts/code_audit.py sample-vuln-app --out ./out --dry-run
python3 scripts/path_audit.py sample-vuln-app --out ./path-out --dry-run
python3 scripts/path_audit.py sample-vuln-js --out ./path-out-js --dry-run
python3 scripts/nmap_triage.py sample-data/nmap-sample.xml --out ./out --dry-run
python3 scripts/log_triage.py sample-data/auth-sample.log --out ./out --dry-run
```

The full setup, data-upload controls, and lab index are in
[exercises/README.md](exercises/README.md).

## Authorized use

Run offensive tools only against systems you own or have written authorization
to test. The Flask and Express sample applications are intentionally vulnerable.
Keep them bound to localhost and use disposable environments.

See [SECURITY.md](SECURITY.md) before reporting security problems. This project
is available under the [MIT License](LICENSE).
