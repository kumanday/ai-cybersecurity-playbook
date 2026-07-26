#!/usr/bin/env python3
"""
path_audit.py: path-centric security audit: from files to attack paths.

The flat divide-and-conquer audit (code_audit.py) answers "what looks
dangerous in this file?" This script answers the question a triage engineer
actually asks: "can an attacker REACH this, and along which path?"

Architecture (playbook §5.7, deterministic outer graph, agentic inner loop):

    1. INDEX      repo_index.build_index(): files, functions, call graph,
                  entry points, per-function taint markers. No model.
    2. RISK QUEUE Rank work: entry points with reachable sinks first, then
                  orphan sinks (no entry path found statically), then
                  module-level code and unparsed files. No model.
    3. BUNDLES    One bounded bundle per analysis unit: the entry handler
                  plus the functions reachable from it in the call graph
                  (BFS, depth-capped, char-capped). Orphan sinks get a
                  backward bundle (who calls this?). No model.
    4. AUDIT      K3 reviews each bundle with a strict JSON schema:
                  is the sink reachable from the entry point, along which
                  path, with what impact? (--dry-run: heuristics emit
                  "plausible path" candidates instead.)
    5. HAND-OFF   Confirmed critical/high findings are written to
                  dynamic-verification-targets.md, the input sheet for
                  dynamic proof with Strix/Shannon (Labs 1–2). We do NOT
                  fire exploits from this script.
    6. CLUSTER    Findings are grouped by root cause (same sink site or
                  same defect class), so a fix list is 3 root causes, not
                  9 tickets. Deterministic.
    7. VERIFY     --verify-model re-interrogates each critical/high path
                  finding in a FRESH context ("prove reachability or
                  downgrade"). Re-run after a fix: the finding must close.

Usage:
    python3 scripts/path_audit.py ../sample-vuln-app --out ./out --dry-run
    python3 scripts/path_audit.py ../sample-vuln-app --out ./out --verify-model --allow-cloud-upload
    python3 scripts/path_audit.py /path/to/repo --out ./out --allow-cloud-upload

Every run persists: repo-index.json, path-bundles.json (what was analyzed:
coverage evidence), path-findings.json, path-report.md,
dynamic-verification-targets.md, path-manifest.json.

Honest limits: static reachability is best-effort (see repo_index.py).
"Reachable" here means E2-E3 on the evidence ladder, a coherent,
code-backed path, not E4 runtime proof. That is what the hand-off is for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k3_client import K3Client, K3Error, require_upload_consent  # noqa: E402
from code_audit import (  # noqa: E402
    iter_repo_files, chunk_file, parse_json_block,
    SEVERITY_ORDER, STRICT_SCHEMA_MAX_FAILURES,
)
from repo_index import (  # noqa: E402
    RepoIndex, FunctionInfo, build_index, index_to_json, summarize,
)

BUNDLE_MAX_CHARS = 12_000        # keep each model call small (§5.2)
MAX_BUNDLES = 40                 # budget cap on analysis units per run
MAX_VERIFY = 10                  # cap on fresh-context verification calls

PATH_AUDIT_SYSTEM = """You are a senior application-security engineer reviewing ONE
attack-path bundle from a larger codebase. The bundle contains an entry
point (attacker-reachable: HTTP route, CLI main, or task) and the functions
reachable from it in the static call graph; for an ORPHAN-SINK bundle,
a dangerous function and its known callers.

Rules:
- Report only issues where attacker-controlled input can plausibly flow from
  the entry point to the dangerous operation WITHIN THIS BUNDLE. If the flow
  is blocked (validation, parameterization, escaping), do not report it.
- For every finding, name the path explicitly: entry -> hop -> ... -> sink,
  citing file:line for each hop.
- Prefer few, high-confidence findings. No style issues, no hypotheticals.
- Answer ONLY with a JSON object, no prose:
{"findings": [{"title": str, "category": str,   # OWASP label e.g. "A03 Injection"
  "severity": "critical"|"high"|"medium"|"low",
  "entry_point": str,          # e.g. "GET /user" or "cli-main"
  "path": [str],               # hops, e.g. ["user_lookup (app.py:47)", "get_db (app.py:35)"]
  "sink_line": int|null,       # line of the dangerous operation
  "evidence": str,             # the key code, quoted briefly
  "attack_path": str,          # 1-3 sentences: who can trigger it and how
  "fix": str}]}                # concrete remediation
If nothing is reachable, return {"findings": []}."""

PATH_FINDINGS_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "path_findings",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "category": {"type": "string"},
                            "severity": {"type": "string",
                                         "enum": ["critical", "high", "medium", "low"]},
                            "entry_point": {"type": "string"},
                            "path": {"type": "array", "items": {"type": "string"}},
                            "sink_line": {"type": ["integer", "null"]},
                            "evidence": {"type": "string"},
                            "attack_path": {"type": "string"},
                            "fix": {"type": "string"},
                        },
                        "required": ["title", "category", "severity", "entry_point",
                                     "path", "sink_line", "evidence",
                                     "attack_path", "fix"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["findings"],
            "additionalProperties": False,
        },
    },
}

VERIFY_SYSTEM = """You are a skeptical security reviewer validating a PATH finding
from an automated audit. You are given the same code bundle and the claimed
finding. Your job: is the claimed attack path actually reachable, end to end,
in a realistic scenario?

Answer ONLY with JSON:
{"verdict": "confirmed"|"downgraded"|"false_positive",
 "adjusted_severity": "critical"|"high"|"medium"|"low"|"info",
 "reason": str,               # 1-3 sentences; trace the path, cite the code
 "validation_steps": str}     # how a developer can confirm safely (no exploit code)
Mark false_positive when a hop in the path does not actually connect
(missing call, validated input, unreachable branch). Downgrade when the path
is real but the impact is lower than claimed."""


@dataclass
class Bundle:
    bundle_id: str
    kind: str                     # "entry" | "orphan-sink" | "module-level" | "file"
    label: str                    # human-readable: "GET /user (app.py:47)"
    entry_point: str
    members: list = field(default_factory=list)   # qualnames or rel paths
    text: str = ""                # the numbered source sent to the model
    trimmed: bool = False
    sinks: list = field(default_factory=list)     # heuristic sink descriptions


@dataclass
class PathFinding:
    bundle_id: str
    title: str
    category: str
    severity: str
    entry_point: str = ""
    path: list = field(default_factory=list)
    sink_line: int | None = None
    evidence: str = ""
    attack_path: str = ""
    fix: str = ""
    verdict: str = "unverified"
    adjusted_severity: str | None = None
    verifier_notes: str = ""
    validation_steps: str = ""
    cluster: str = ""

    @property
    def final_severity(self) -> str:
        return self.adjusted_severity or self.severity

    @property
    def key(self) -> str:
        raw = f"{self.bundle_id}:{self.category}:{self.title.lower()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Steps 1-3: index, risk queue, bundles
# ---------------------------------------------------------------------------

def _numbered_source(root: Path, fi: FunctionInfo) -> str:
    try:
        lines = (root / fi.file).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    seg = lines[fi.start_line - 1:fi.end_line]
    return "\n".join(f"{fi.start_line + n}: {l}" for n, l in enumerate(seg))


def build_bundles(root: Path, index: RepoIndex,
                  max_bundles: int = MAX_BUNDLES) -> tuple[list[Bundle], dict]:
    """Construct bounded analysis bundles; return (bundles, coverage)."""
    bundles: list[Bundle] = []
    covered: set[str] = set()

    # (a) Entry-point bundles: handler + forward-reachable functions.
    for qual in index.entry_points:
        fi = index.functions[qual]
        reach = index.forward(qual)
        label = (f"{fi.route} " if fi.route else "") + f"({fi.entry_kind})"
        text_parts = [f"### ENTRY POINT: {qual} [{fi.entry_kind}] "
                      f"{fi.route}\n" + _numbered_source(root, fi)]
        size = len(text_parts[0])
        trimmed = False
        for callee in reach[1:]:
            cfi = index.functions[callee]
            seg = f"\n### CALLEE: {callee}\n" + _numbered_source(root, cfi)
            if size + len(seg) > BUNDLE_MAX_CHARS:
                trimmed = True
                break
            text_parts.append(seg)
            size += len(seg)
        sinks = sorted({s for q in reach for s in index.functions[q].sinks})
        bundles.append(Bundle(
            bundle_id=f"entry:{qual}", kind="entry", label=label,
            entry_point=(f"{fi.route} " if fi.route else "") + qual,
            members=reach, text="\n".join(text_parts), trimmed=trimmed,
            sinks=sinks))
        covered.update(reach)

    # (b) Orphan sinks: sink-bearing functions no entry bundle covered.
    for qual, fi in index.functions.items():
        if qual in covered or not fi.sinks:
            continue
        chain = index.backward(qual)
        text_parts = [f"### ORPHAN SINK (no static entry path): {qual}\n"
                      + _numbered_source(root, fi)]
        size = len(text_parts[0])
        for caller in chain[1:]:
            cfi = index.functions[caller]
            seg = f"\n### CALLER: {caller}\n" + _numbered_source(root, cfi)
            if size + len(seg) > BUNDLE_MAX_CHARS:
                break
            text_parts.append(seg)
            size += len(seg)
        bundles.append(Bundle(
            bundle_id=f"orphan:{qual}", kind="orphan-sink",
            label=f"orphan sink: {qual}", entry_point="(none found statically)",
            members=chain, text="\n".join(text_parts), sinks=fi.sinks))
        covered.update(chain)

    # (c) Module-level statements (top-level constants/setup) per parsed file
    #     that heuristic-match sinks; this is where hardcoded secrets live.
    for rel, finfo in index.files.items():
        if finfo.language == "other" or finfo.parse_error:
            continue
        try:
            lines = (root / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        in_fn: set[int] = set()
        for q in finfo.functions:
            fi = index.functions[q]
            in_fn.update(range(fi.start_line, fi.end_line + 1))
        top = [(n, l) for n, l in enumerate(lines, 1)
               if n not in in_fn and l.strip()]
        from code_audit import HEURISTIC_SINKS, HEURISTIC_SKIP_LINE
        hits = []
        for n, l in top:
            if HEURISTIC_SKIP_LINE.match(l):
                continue
            for pattern, _c, desc, _sev in HEURISTIC_SINKS:
                if _c != "surface" and re.search(pattern, l):
                    hits.append((n, desc))
                    break
        if hits:
            text = "\n".join(f"{n}: {l}" for n, l in top)[:BUNDLE_MAX_CHARS]
            bundles.append(Bundle(
                bundle_id=f"module:{rel}", kind="module-level",
                label=f"module-level statements ({rel})",
                entry_point=f"module import / startup ({rel})",
                members=[rel], text=("### MODULE-LEVEL STATEMENTS "
                                     f"({rel})\n" + text),
                sinks=sorted({d for _n, d in hits})))

    # (d) Unparsed files (YAML, Dockerfile, languages without a grammar, ...):
    #     whole-file bundles, chunked like code_audit.
    for rel, finfo in index.files.items():
        if finfo.language != "other":
            continue
        try:
            text = (root / rel).read_text(errors="replace")
        except OSError:
            continue
        for start_line, chunk in chunk_file(Path(rel), text):
            numbered = "\n".join(f"{start_line + n}: {l}"
                                 for n, l in enumerate(chunk.splitlines()))
            bundles.append(Bundle(
                bundle_id=f"file:{rel}:{start_line}", kind="file",
                label=f"unparsed file ({rel})",
                entry_point=f"file review ({rel})",
                members=[rel], text=f"### FILE: {rel}\n" + numbered))

    # Risk queue: sink-bearing entry bundles first, then orphans, then the
    # rest; deterministic ordering inside each class.
    def rank(b: Bundle) -> tuple:
        return (0 if b.kind == "entry" and b.sinks else
                1 if b.kind == "orphan-sink" else
                2 if b.kind == "module-level" else
                3 if b.kind == "entry" else 4,
                b.bundle_id)

    bundles.sort(key=rank)
    overflow = bundles[max_bundles:]
    bundles = bundles[:max_bundles]

    covered_in_run = {q for b in bundles for q in b.members
                      if q in index.functions}
    coverage = {
        "entry_points_total": len(index.entry_points),
        "entry_points_bundled": sum(1 for q in index.entry_points
                                    if any(q in b.members for b in bundles)),
        "functions_total": len(index.functions),
        "functions_in_bundles": len(covered_in_run),
        "functions_not_covered": sorted(set(index.functions) - covered_in_run),
        "bundles_dropped_budget": [b.bundle_id for b in overflow],
    }
    return bundles, coverage


# ---------------------------------------------------------------------------
# Step 4: audit each bundle
# ---------------------------------------------------------------------------

def audit_bundle(client: K3Client, bundle: Bundle, dry_run: bool,
                 strict_state: dict) -> list[PathFinding]:
    if dry_run:
        return heuristic_path_audit(bundle)
    messages = [
        {"role": "system", "content": PATH_AUDIT_SYSTEM},
        {"role": "user", "content":
            f"BUNDLE: {bundle.label}\nKIND: {bundle.kind}\n\n{bundle.text}"},
    ]
    use_strict = strict_state["failures"] < STRICT_SCHEMA_MAX_FAILURES
    try:
        raw = client.chat(messages,
                          response_format=PATH_FINDINGS_SCHEMA if use_strict else None)
        if use_strict:
            strict_state["used"] = True
    except K3Error as exc:
        if use_strict and "400" in str(exc):
            strict_state["failures"] += 1
            raw = client.chat(messages)
        else:
            raise
    data = parse_json_block(raw)
    findings = []
    for f in (data.get("findings", []) if isinstance(data, dict) else []):
        if not isinstance(f, dict) or not f.get("title"):
            continue
        findings.append(PathFinding(
            bundle_id=bundle.bundle_id,
            title=str(f.get("title", ""))[:200],
            category=str(f.get("category", "uncategorized"))[:120],
            severity=str(f.get("severity", "info")).lower(),
            entry_point=str(f.get("entry_point", bundle.entry_point))[:200],
            path=[str(p)[:200] for p in (f.get("path") or [])][:12],
            sink_line=f.get("sink_line") if isinstance(f.get("sink_line"), int) else None,
            evidence=str(f.get("evidence", ""))[:600],
            attack_path=str(f.get("attack_path", ""))[:800],
            fix=str(f.get("fix", ""))[:800],
        ))
    return findings


def heuristic_path_audit(bundle: Bundle) -> list[PathFinding]:
    """Offline pipeline check: turn heuristic sink markers into 'plausible
    path' candidates (E1, NOT a security audit)."""
    findings = []
    for sink in bundle.sinks:
        if bundle.kind == "entry":
            hops = [m for m in bundle.members]
            path_summary = " -> ".join(hops[:6])
            findings.append(PathFinding(
                bundle_id=bundle.bundle_id,
                title=f"[heuristic] plausible path: {sink}",
                category="E1 candidate (dry-run)", severity="medium",
                entry_point=bundle.entry_point,
                path=hops[:6],
                evidence=f"sink marker '{sink}' inside bundle {bundle.label}",
                attack_path=(f"dry-run: entry {bundle.entry_point} reaches a "
                             f"sink marker via {path_summary}. Run with an API "
                             f"key for reachability analysis."),
                fix="Review the path; validate and parameterize at the sink."))
        else:
            findings.append(PathFinding(
                bundle_id=bundle.bundle_id,
                title=f"[heuristic] sink needs review: {sink}",
                category="E1 candidate (dry-run)", severity="low",
                entry_point=bundle.entry_point,
                path=bundle.members[:6],
                evidence=f"sink marker '{sink}' in {bundle.label}",
                attack_path="dry-run: no static entry path (or unparsed unit); "
                            "manual review or a model run required.",
                fix="Review reachability and input handling."))
    return findings


# ---------------------------------------------------------------------------
# Step 7: fresh-context verification
# ---------------------------------------------------------------------------

def verify_path_finding(client: K3Client, bundle_map: dict,
                        finding: PathFinding) -> PathFinding:
    bundle = bundle_map.get(finding.bundle_id)
    if bundle is None:
        return finding
    raw = client.chat([
        {"role": "system", "content": VERIFY_SYSTEM},
        {"role": "user", "content":
            f"BUNDLE: {bundle.label}\n\n{bundle.text}\n\n"
            f"CLAIMED FINDING:\n{json.dumps(asdict(finding), indent=2)}"},
    ])
    data = parse_json_block(raw)
    if isinstance(data, dict):
        finding.verdict = str(data.get("verdict", "unverified"))
        adj = str(data.get("adjusted_severity", "")).lower()
        finding.adjusted_severity = adj if adj in SEVERITY_ORDER else None
        finding.verifier_notes = str(data.get("reason", ""))[:600]
        finding.validation_steps = str(data.get("validation_steps", ""))[:600]
    return finding


# ---------------------------------------------------------------------------
# Step 6: root-cause clustering (deterministic)
# ---------------------------------------------------------------------------

def cluster_findings(findings: list[PathFinding]) -> None:
    """Group by root cause: same sink site collapses to one cluster; else
    same defect class on the same file. Sets finding.cluster in place."""
    for f in findings:
        file_guess = f.path[0].split("(")[-1].rstrip(")").split(":")[0] \
            if f.path else f.bundle_id
        site = f"{file_guess}:{f.sink_line}" if f.sink_line else file_guess
        f.cluster = f"{f.category} @ {site}"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_reports(root: Path, out_dir: Path, index: RepoIndex,
                  bundles: list[Bundle], coverage: dict,
                  findings: list[PathFinding], elapsed: float,
                  dry_run: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "path-findings.json").write_text(json.dumps(
        [{**asdict(f), "key": f.key} for f in findings], indent=2))
    (out_dir / "path-bundles.json").write_text(json.dumps({
        "coverage": coverage,
        "bundles": [{"bundle_id": b.bundle_id, "kind": b.kind,
                     "label": b.label, "entry_point": b.entry_point,
                     "members": b.members, "trimmed": b.trimmed,
                     "sinks": b.sinks, "chars": len(b.text)}
                    for b in bundles],
    }, indent=2))

    clusters: dict[str, list[PathFinding]] = {}
    for f in findings:
        clusters.setdefault(f.cluster, []).append(f)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.final_severity] = counts.get(f.final_severity, 0) + 1
    lines = [
        f"# Path-Centric Audit Report: {root.name}",
        "",
        f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Mode: {'DRY-RUN (heuristic path candidates, NOT an audit)' if dry_run else 'Kimi K3 path-centric audit'}",
        f"- Elapsed: {elapsed:.1f}s",
        f"- Entry-point coverage: {coverage['entry_points_bundled']}/"
        f"{coverage['entry_points_total']} entry points bundled; "
        f"{coverage['functions_in_bundles']}/{coverage['functions_total']} "
        f"functions analyzed",
        f"- Findings: " + (", ".join(f"{k}: {v}" for k, v in sorted(
            counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))) or "none"),
        f"- Root-cause clusters: {len(clusters)}",
        "",
        "## Root-cause clusters",
        "",
        "| Cluster | Findings | Worst severity |",
        "|---|---|---|",
    ]
    for name, members in sorted(clusters.items()):
        worst = min((m.final_severity for m in members),
                    key=lambda s: SEVERITY_ORDER.get(s, 9))
        lines.append(f"| {name} | {len(members)} | {worst.upper()} |")
    lines += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        badge = f.final_severity.upper()
        verdict = f" (verdict: {f.verdict})" if f.verdict != "unverified" else ""
        lines += [
            f"### {i}. [{badge}] {f.title}",
            "",
            f"- **Entry point:** {f.entry_point}",
            f"- **Category:** {f.category}{verdict}",
        ]
        if f.path:
            lines.append("- **Path:** " + " → ".join(f"`{p}`" for p in f.path))
        if f.sink_line:
            lines.append(f"- **Sink line:** {f.sink_line}")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence}`")
        if f.attack_path:
            lines.append(f"- **Attack path:** {f.attack_path}")
        if f.fix:
            lines.append(f"- **Fix:** {f.fix}")
        if f.validation_steps:
            lines.append(f"- **Validate:** {f.validation_steps}")
        if f.verifier_notes:
            lines.append(f"- **Verifier notes:** {f.verifier_notes}")
        lines.append("")

    if coverage["functions_not_covered"]:
        lines += ["## Coverage gaps (functions in no analyzed bundle)", ""]
        for q in coverage["functions_not_covered"][:50]:
            lines.append(f"- `{q}`")
        lines.append("")
    (out_dir / "path-report.md").write_text("\n".join(lines))

    # Step 5: hand-off sheet for dynamic verification (Strix/Shannon).
    hot = [f for f in findings
           if f.final_severity in ("critical", "high")
           and f.verdict != "false_positive"]
    hand = [
        "# Dynamic Verification Targets",
        "",
        "Confirmed high-severity path findings, formatted as targets for a",
        "dynamic agent (Strix/Shannon, Labs 1-2) running against a LOCAL,",
        "authorized instance. This script does not fire exploits.",
        "",
    ]
    if not hot:
        hand.append("No confirmed critical/high findings to verify.")
    for f in hot:
        hand += [
            f"## {f.title} ({f.final_severity.upper()})",
            f"- Entry point: {f.entry_point}",
            f"- Path: {' -> '.join(f.path) if f.path else '(see report)'}",
            f"- What to prove: {f.attack_path}",
            f"- Safe validation: {f.validation_steps or 'see report'}",
            "",
        ]
    (out_dir / "dynamic-verification-targets.md").write_text("\n".join(hand))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Path-centric security audit with Kimi K3")
    ap.add_argument("repo", help="path to the repository to audit")
    ap.add_argument("--out", default="./path-out", help="output directory")
    ap.add_argument("--max-bundles", type=int, default=MAX_BUNDLES,
                    help="budget cap on analysis units")
    ap.add_argument("--verify-model", action="store_true",
                    help="fresh-context re-verification of critical/high path "
                         "findings (use after fixes to confirm closure)")
    ap.add_argument("--dry-run", action="store_true",
                    help="offline pipeline test with heuristic path candidates "
                         "(NOT a real audit)")
    ap.add_argument("--allow-cloud-upload", action="store_true",
                    help="consent to sending source code to the hosted inference "
                         "API (or set K3_ALLOW_UPLOAD=1)")
    args = ap.parse_args()

    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    out_dir = Path(args.out).resolve()
    t0 = time.time()

    print("[1/6] Indexing repository (deterministic)")
    index = build_index(root)
    print("      " + summarize(index).replace("\n", "\n      "))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repo-index.json").write_text(json.dumps(
        index_to_json(index), indent=2))

    print("[2/6] Building risk queue and path bundles")
    bundles, coverage = build_bundles(root, index, args.max_bundles)
    print(f"      {len(bundles)} bundles; entry-point coverage "
          f"{coverage['entry_points_bundled']}/{coverage['entry_points_total']}")
    if coverage["bundles_dropped_budget"]:
        print(f"      budget dropped {len(coverage['bundles_dropped_budget'])} "
              f"bundles (raise --max-bundles)")

    client = K3Client()
    if not args.dry_run and not client.configured:
        print("No API key configured; falling back to --dry-run behavior.\n"
              "Set FIREWORKS_API_KEY (or K3_PROVIDER=moonshot + MOONSHOT_API_KEY).")
        args.dry_run = True
    if not args.dry_run:
        try:
            require_upload_consent(args.allow_cloud_upload, client.provider,
                                   "source code from this repository")
        except K3Error as exc:
            print(exc, file=sys.stderr)
            return 2
    strict_state = {"failures": 0, "used": False}

    print(f"[3/6] Auditing {len(bundles)} bundles "
          f"({'heuristic dry-run' if args.dry_run else 'K3, sequential'})")
    findings: list[PathFinding] = []
    bundle_map = {b.bundle_id: b for b in bundles}
    for b in bundles:
        try:
            findings.extend(audit_bundle(client, b, args.dry_run, strict_state))
        except Exception as exc:  # one bad bundle must not kill the audit
            print(f"      warning: bundle failed for {b.label}: {exc}")
    print(f"      raw findings: {len(findings)}")

    # Dedupe by (bundle, category, title).
    seen: dict[str, PathFinding] = {}
    for f in findings:
        seen.setdefault(f.key, f)
    findings = sorted(seen.values(),
                      key=lambda f: (SEVERITY_ORDER.get(f.final_severity, 9),
                                     f.bundle_id))
    print(f"[4/6] Fan-in: {len(findings)} unique findings")

    if args.verify_model and not args.dry_run:
        hot = [f for f in findings
               if f.final_severity in ("critical", "high")][:MAX_VERIFY]
        print(f"[5/6] Fresh-context verification on {len(hot)} critical/high findings")
        for f in hot:
            try:
                verify_path_finding(client, bundle_map, f)
            except K3Error as exc:
                print(f"      warning: verification failed: {exc}")
        findings = [f for f in findings if f.verdict != "false_positive"]
    else:
        print("[5/6] Verification pass skipped (use --verify-model to enable)")

    print("[6/6] Clustering by root cause and writing artifacts")
    cluster_findings(findings)
    elapsed = time.time() - t0
    write_reports(root, out_dir, index, bundles, coverage, findings,
                  elapsed, args.dry_run)
    manifest = {
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "repo": str(root),
        "mode": "dry-run" if args.dry_run else "model",
        "provider": None if args.dry_run else client.provider,
        "model": None if args.dry_run else client.model,
        "strict_json_schema": "used" if strict_state["used"] else
                              ("rejected" if strict_state["failures"] else "not attempted"),
        "verification_pass": bool(args.verify_model and not args.dry_run),
        "bundles": len(bundles),
        "coverage": coverage,
        "findings": len(findings),
        "elapsed_seconds": round(elapsed, 1),
    }
    if not args.dry_run:
        manifest["token_usage"] = client.usage_totals
        manifest["estimated_cost"] = client.estimate_cost() or "pricing unknown"
    (out_dir / "path-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nDone in {elapsed:.1f}s")
    for name in ("path-report.md", "path-findings.json", "path-bundles.json",
                 "repo-index.json", "dynamic-verification-targets.md",
                 "path-manifest.json"):
        print(f"  {out_dir / name}")
    crit = sum(1 for f in findings if f.final_severity in ("critical", "high"))
    return 1 if crit else 0


if __name__ == "__main__":
    sys.exit(main())
