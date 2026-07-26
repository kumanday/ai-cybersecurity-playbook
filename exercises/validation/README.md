# Validation evidence for the model labs

This folder holds the actual outputs from test runs of the playbook's three model-driven
labs, produced during authoring on July 26, 2026. They exist so the playbook's claims about
the labs are checkable, and so you can compare your own runs against a known-good shape.

## How these runs were produced

Each lab was executed end to end through its real script (`code_audit.py`, `path_audit.py`,
`path_agent.py`) with Kimi K3 as the model. The authoring sandbox has no Fireworks or
Moonshot API key, so the model side ran by manual transport: the script called its usual
client seam, and K3's genuine analysis of the real repo content came back through it.
Everything deterministic (indexing, chunking, bundling, dedupe, verification merge,
clustering, report writing, exit codes) is the scripts' own code running unmodified.

What this validates: prompts and schemas are answerable, the pipelines run to completion,
findings ground out in real file lines, the verification pass can downgrade as well as
confirm, and the reports read the way a reviewer needs them to.

What this does not validate: API transport, authentication, latency, and token billing.
Run the labs with your own key to exercise that layer. The scripts need no changes for it.

## Contents

- `lab3-sample-vuln-app/`: Lab 3 divide-and-conquer audit (`code_audit.py`) on the Python
  training app. 9 findings, 8 confirmed in the verification pass, exit code 1 (the CI gate
  trips on confirmed criticals, as designed). All seven planted vulnerability classes found,
  plus the error-response leak.
- `lab8-sample-vuln-app/`: Lab 8 path-centric audit (`path_audit.py`) on the Python app.
  9 entry-anchored bundles, 9 findings, 8 confirmed. The debug-mode finding was downgraded
  to medium by the verification pass on loopback-bind evidence, which is the calibration
  behavior Lab 8 teaches. Cross-check `path-bundles.json` against your own index output.
- `lab8-sample-vuln-js/`: the same audit on the Express training app, exercising the
  Tree-sitter JavaScript extractor and the cross-file path (route in `server.js` to query
  construction in `db.js`). 6 findings, 6 confirmed, all five planted classes covered.
- `lab9-agent-transcript.md`: full tool-loop transcript of the Lab 9 capstone
  (`path_agent.py`) answering a reachability question about the SQL injection in
  `sample-vuln-app`. Four rounds, real tool outputs, grounded verdict with stated caveats.

## Reproduce

```bash
cd exercises
python3 scripts/code_audit.py sample-vuln-app --out /tmp/my-lab3 --verify --allow-cloud-upload
python3 scripts/path_audit.py sample-vuln-js --out /tmp/my-lab8
python3 scripts/path_agent.py sample-vuln-app
```

Each script needs `FIREWORKS_API_KEY` in the environment for real API transport (or
`K3_PROVIDER=moonshot` plus `MOONSHOT_API_KEY`). Your findings will differ in wording; the
class coverage and verdict shape should not.
