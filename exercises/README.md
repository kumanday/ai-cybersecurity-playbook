# AI Cybersecurity Playbook: Exercise Pack

Runnable companions to the playbook's Part VI labs. Everything here is built
around **Kimi K3** served through **Fireworks AI** (OpenAI-compatible API);
Moonshot's first-party API works as a fallback by changing one env var.

> Authorized use only. Run every exercise against systems you own: the
> included training app, the included sample data, or your own staging
> environment. See the playbook's safety rules before pointing anything at a
> live target.

## Layout

```
exercises/
├── README.md                    ← you are here
├── requirements.txt             ← pinned deps: requests + tree-sitter grammars
├── scripts/
│   ├── k3_client.py             ← shared K3 client + connectivity check
│   ├── code_audit.py            ← Lab 3: divide-and-conquer repo audit
│   ├── repo_index.py            ← Lab 8: Tree-sitter repo index (call graph, entry points)
│   ├── path_audit.py            ← Lab 8: path-centric audit (reachability, clustering)
│   ├── path_agent.py            ← Lab 9 (optional): K3 tool-calling investigator (reference impl)
│   ├── nmap_triage.py           ← Lab 4: nmap output → triaged exposure report
│   └── log_triage.py            ← Lab 5: auth log → incident assessment
├── sample-vuln-app/             ← intentionally vulnerable Flask target (Lab 3/6/8/9)
├── sample-vuln-js/              ← intentionally vulnerable Express target (Lab 8; JS parsing, cross-file paths)
├── validation/                  ← preserved authoring-time runs of Labs 3/8/9, with method notes
├── sample-data/
│   ├── nmap-sample.xml          ← synthetic scan for Lab 4
│   └── auth-sample.log          ← synthetic brute-force log for Lab 5
└── prompts/                     ← prompt library referenced across the playbook
```

## 5-minute start

```bash
cd exercises
pip install -r requirements.txt

# 1) Configure the model
export FIREWORKS_API_KEY="fw_..."            # https://fireworks.ai → Settings → API Keys
# optional overrides:
# export K3_PROVIDER=moonshot                # use Moonshot's API instead
# export K3_MODEL="accounts/fireworks/models/kimi-k3"

# 2) Verify connectivity (Lab 0)
python3 scripts/k3_client.py --check

# 3) Smoke-test every pipeline offline, no API key needed, nothing uploaded
python3 scripts/code_audit.py sample-vuln-app --out ./out --dry-run
python3 scripts/path_audit.py sample-vuln-app --out ./path-out --dry-run
python3 scripts/path_audit.py sample-vuln-js --out ./path-out-js --dry-run
python3 scripts/nmap_triage.py sample-data/nmap-sample.xml --out ./out --dry-run
python3 scripts/log_triage.py sample-data/auth-sample.log --out ./out --dry-run
```

Every script supports `--dry-run`: the same map → plan → fan-out → fan-in →
report pipeline runs with local heuristics standing in for the model, so you
can test the harness offline. Dry-run output is explicitly labeled and is
**not** a real audit.

## Data-policy gate (required for model calls)

Model calls send file contents, scan output, or logs to the hosted inference
endpoint you configured. Every script refuses to do that until you explicitly
opt in:

```bash
python3 scripts/code_audit.py sample-vuln-app --out ./out --allow-cloud-upload
# or, session-wide:
export K3_ALLOW_UPLOAD=1
```

Confirm your data policy first (see the playbook §2.3; BAA/DPA where
regulated data is in scope). `--dry-run` never uploads anything.

## What a run leaves behind

Every audit run persists evidence, not just a report: `audit-plan.json`
(which files were selected and why), `coverage.json` (in-scope, audited, and
skipped files with reasons), `run-manifest.json` (mode, provider/model,
strict-schema usage, budgets, token usage and estimated cost), plus
`audit-findings.json` and `audit-report.md`. Structured output uses strict
JSON Schema when the provider supports it, with automatic fallback.

`path_audit.py` (Lab 8) persists the path-centric equivalents:
`repo-index.json` (Tree-sitter parse of the repo: call graph, entry points,
taint markers: what the analyzer can see; Python, JavaScript, and
TypeScript/TSX grammars loaded, stdlib `ast` as Python fallback),
`path-bundles.json` (what was analyzed, with entry-point coverage stated),
`path-findings.json`, `path-report.md` (clustered by root cause),
`dynamic-verification-targets.md` (confirmed paths formatted for
Strix/Shannon), and `path-manifest.json`.

`path_agent.py` (Lab 9, optional) persists `agent-transcript.json`, the full
message history *including reasoning fields*, since preserving it is the
point of the lab, and `agent-verdict.md`. Treat transcripts as sensitive.

## The shared client (adapter v2)

`scripts/k3_client.py` is more than a connector:

- **Usage accounting:** accumulates cached/fresh/output tokens across calls;
  `estimate_cost()` uses built-in provider prices. Override with
  `K3_PRICE_JSON='{"input":..,"cached_input":..,"output":..}'`.
- **`reasoning_effort`:** pass `"low"` for cheap bulk passes (default is the
  server-side `"max"`).
- **`chat_with_tools()`:** a bounded tool loop that preserves complete
  assistant messages (reasoning fields included) per the K3 docs, with
  per-tool error isolation. This is the foundation for agentic POCs
  (see the playbook, Part V §5.5).

## The labs

| Lab | Playbook section | Script / tool | Target |
|---|---|---|---|
| 0: Workbench | Part VI | `k3_client.py --check`, Docker, Juice Shop | n/a |
| 1: White-box agentic pentest | Part VI | Shannon (KeygraphHQ) | your local app |
| 2: Black-box agentic pentest | Part VI | Strix | OWASP Juice Shop |
| 3: Divide-and-conquer audit | Part VI | `code_audit.py` | `sample-vuln-app` |
| 4: Network exposure triage | Part VI | `nmap_triage.py` + nmap | `nmap-sample.xml`, then your own host |
| 5: Log anomaly triage | Part VI | `log_triage.py` | `auth-sample.log`, then your own logs |
| 6: Find, fix, verify | Part VI | `code_audit.py` + K3 in your editor | `sample-vuln-app` |
| 7: IR tabletop | Part VI | `prompts/ir-copilot.md` | scenario in the playbook |
| 8: Path-centric audit | Part VI | `repo_index.py` + `path_audit.py` | `sample-vuln-app` or `sample-vuln-js`, then your repo |
| 9: Tool-calling loop (optional capstone) | Part VI | `path_agent.py` | `sample-vuln-app` |

**Which audit script when?** `code_audit.py` answers "what looks dangerous
in these files?"; `path_audit.py` answers "can an attacker reach it, along
which path?": start with Lab 3, graduate to Lab 8. `path_agent.py` is not a
scanner at all: it is the §5.4 reference implementation for readers building
their own agents (see its header before running).

Full step-by-step instructions, expected outputs, and discussion questions
are in **Part VI of the playbook**. Reference outputs from the authoring-time
runs of Labs 3, 8 (both training apps), and 9 are preserved under
`validation/`, with a README there stating exactly what those runs do and do
not establish.
