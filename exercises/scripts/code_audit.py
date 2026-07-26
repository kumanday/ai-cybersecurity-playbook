#!/usr/bin/env python3
"""
code_audit.py: divide-and-conquer security audit of a codebase with Kimi K3.

Instead of stuffing a whole repository into one prompt (accuracy decays and
cost explodes with context size), this script runs the fan-out / fan-in loop
described in the playbook, Part V:

    1. MAP       Walk the repo, build a compact repo map (paths, sizes,
                 detected frameworks/entry points).
    2. PLAN      K3 ranks the files most worth auditing and says why.
                 (--dry-run uses local heuristics instead.)
    3. FAN-OUT   Audit each prioritized file (large files are split into
                 function-level chunks) in parallel with a strict
                 JSON findings schema.
    4. FAN-IN    Aggregate, de-duplicate, sort by severity.
    5. VERIFY    Re-interrogate every critical/high finding: "prove it with
                 a concrete attack path, or downgrade it." This second pass
                 is what keeps LLM false positives out of your backlog.
    6. REPORT    Write audit-findings.json + audit-report.md.

Usage:
    python3 scripts/code_audit.py ../sample-vuln-app --out ./out --allow-cloud-upload
    python3 scripts/code_audit.py /path/to/repo --out ./out --max-files 25 --workers 4 --allow-cloud-upload
    python3 scripts/code_audit.py ../sample-vuln-app --dry-run   # offline pipeline test

The --dry-run mode performs the same map/plan/fan-out/fan-in/report pipeline
with local pattern heuristics in place of the model. It exists so you can
test the harness offline; its findings are NOT a security audit.

Every run persists, alongside the report:
  * audit-plan.json     : which files the planner selected, and why
  * coverage.json       : files in scope, files audited, files skipped + reasons
  * run-manifest.json   : mode, provider/model, strict-schema usage, budgets

Model calls require an explicit data-policy opt-in: --allow-cloud-upload or
K3_ALLOW_UPLOAD=1 (source code leaves your machine for the hosted endpoint).
Structured output uses strict JSON Schema when the provider supports it, with
automatic fallback to tolerant parsing.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k3_client import K3Client, K3Error, require_upload_consent  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rb", ".php", ".java", ".kt", ".cs",
    ".yml", ".yaml", ".json", ".toml", ".env", ".sh", ".sql",
    ".html", ".vue", ".svelte", ".tf", ".txt", ".cfg", ".ini", ".conf",
}
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "vendor", "venv",
    ".venv", "__pycache__", ".next", ".cache", "coverage", ".idea",
    ".vscode", "target", "bin", "obj",
}
# Hidden directories that routinely hold security-relevant configuration.
INCLUDE_DOTDIRS = {".github", ".gitlab", ".circleci"}
# Security-critical files that carry no (or a non-code) extension. Matching
# is case-insensitive on the file name.
SPECIAL_FILENAMES = {
    "dockerfile", ".env", "makefile", "jenkinsfile", "requirements.txt",
    "pipfile", "gemfile", "gemfile.lock", "go.mod", "go.sum",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "docker-compose.yml",
    "docker-compose.yaml", ".gitlab-ci.yml", ".drone.yml", "nginx.conf",
    "composer.json", "composer.lock", "cargo.toml", "cargo.lock",
}
MAX_FILE_BYTES = 120_000          # skip very large files (generated code etc.)
CHUNK_TARGET_CHARS = 12_000       # function-level chunks stay near this size
CHUNK_OVERLAP_LINES = 10          # overlap for non-Python line-window chunks
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Strict output contract for fan-out calls (fallback: tolerant parsing).
FINDINGS_JSON_SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "audit_findings",
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
                            "line": {"type": ["integer", "null"]},
                            "evidence": {"type": "string"},
                            "attack_path": {"type": "string"},
                            "fix": {"type": "string"},
                        },
                        "required": ["title", "category", "severity", "line",
                                     "evidence", "attack_path", "fix"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["findings"],
            "additionalProperties": False,
        },
    },
}
# Circuit breaker: strict schema is attempted until it has failed this many
# times in a run, then we stop paying for 400s.
STRICT_SCHEMA_MAX_FAILURES = 2

AUDIT_SYSTEM_PROMPT = """You are a senior application-security engineer performing a
white-box code review of ONE file (or one code chunk) from a larger codebase.

Rules:
- Report only issues a real attacker could plausibly abuse: injection, broken
  authn/authz, SSRF, path traversal, insecure deserialization, hardcoded
  secrets, dangerous defaults, missing validation on security-critical paths.
- For every finding, cite concrete evidence (line numbers and the exact code).
- Prefer few, high-confidence findings over many speculative ones.
- Do NOT report style issues, missing comments, or hypothetical hardening.
- Answer ONLY with a JSON object, no prose:
{"findings": [{"title": str, "category": str,  # OWASP label e.g. "A03 Injection"
  "severity": "critical"|"high"|"medium"|"low", "line": int|null,
  "evidence": str,          # the vulnerable code, quoted briefly
  "attack_path": str,       # 1-3 sentences: how an attacker reaches this
  "fix": str}]}             # concrete remediation, with code sketch if useful
If there is nothing exploitable, return {"findings": []}."""

VERIFY_SYSTEM_PROMPT = """You are a skeptical security reviewer validating a finding
from an automated audit. Given the code context and the claimed finding,
decide whether it is a TRUE, exploitable issue in a realistic attack scenario.

Answer ONLY with JSON:
{"verdict": "confirmed"|"downgraded"|"false_positive",
 "adjusted_severity": "critical"|"high"|"medium"|"low"|"info",
 "reason": str,               # 1-3 sentences, cite the code
 "validation_steps": str}     # how a developer can reproduce/confirm safely
Downgrade when the issue is real but the impact is lower than claimed.
Mark false_positive when the claimed attack path does not actually work."""

# Heuristic sink patterns used ONLY in --dry-run mode and for the local
# pre-planning pass. The model does the real reasoning. Patterns are kept
# deliberately narrow to limit known false-positive classes (import lines,
# DDL statements); dry-run output is a pipeline smoke test, not an audit.
HEURISTIC_SINKS = [
    (r"os\.system|subprocess\.(call|run|Popen|check_output|check_call).*shell\s*=\s*True|check_output\([^)]*\+[^)]*shell\s*=\s*True", "A03 Injection", "Possible OS command injection", "high"),
    (r"(execute|executemany)\s*\([^)]*(%|\.format\(|f[\"']|\+)|(SELECT|INSERT|UPDATE|DELETE).*(%s|\.format\(|\{\w*\}|\+\s*\w+)", "A03 Injection", "Possible SQL injection via string formatting", "high"),
    (r"render_template_string\(|Markup\(|innerHTML\s*=|dangerouslySetInnerHTML", "A03 Injection", "Possible template/XSS injection", "medium"),
    (r"pickle\.loads?|yaml\.load\((?!.*Loader)", "A08 Software and Data Integrity Failures", "Insecure deserialization", "high"),
    (r"requests\.(get|post)\([^)]*request\.|urlopen\(.*request", "A10 SSRF", "Possible server-side request forgery", "medium"),
    (r"(?i)(API_KEY|SECRET|PASSWORD|TOKEN)\w*\s*=\s*[\"'][^\"']{7,}[\"']", "A07 Identification and Authentication Failures", "Hardcoded secret", "high"),
    (r"open\([^)]*request\.|send_file\(|\.\./", "A01 Broken Access Control", "Possible path traversal", "medium"),
    (r"debug\s*=\s*True|verify\s*=\s*False|check_hostname\s*=\s*False", "A05 Security Misconfiguration", "Dangerous default (debug/TLS verification off)", "medium"),
    (r"child_process[^\n]{0,12}\.(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|\b(eval|execSync|execFileSync|spawnSync)\s*\(|new\s+Function\s*\(", "A03 Injection", "Possible JS code/command injection", "high"),
    (r"(query|execute)\s*\(\s*[`\"'][^)]*(\+|\$\{)", "A03 Injection", "Possible SQL injection via string concatenation", "high"),
    (r"@app\.route|app\.(get|post|put|delete)\(|def\s+\w+\(request", "surface", "HTTP entry point", "info"),
]

# Lines that should never raise a heuristic finding (FP filters).
HEURISTIC_SKIP_LINE = re.compile(
    r"^\s*(from\s+\S+\s+import|import\s+\S+|#)", re.IGNORECASE)


@dataclass
class Finding:
    file: str
    title: str
    category: str
    severity: str
    line: int | None = None
    evidence: str = ""
    attack_path: str = ""
    fix: str = ""
    verdict: str = "unverified"
    adjusted_severity: str | None = None
    verifier_notes: str = ""
    validation_steps: str = ""

    @property
    def final_severity(self) -> str:
        return self.adjusted_severity or self.severity

    @property
    def key(self) -> str:
        raw = f"{self.file}:{self.line}:{self.category}:{self.title.lower()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Phase 1: MAP
# ---------------------------------------------------------------------------

def iter_repo_files(root: Path) -> tuple[list[Path], list[dict]]:
    """Collect in-scope files; also record what was skipped and why.

    CI config directories (.github/, .gitlab/, .circleci/) and security-
    critical extensionless files (Dockerfile, .env, requirements.txt, …)
    are explicitly IN scope; they are where supply-chain findings live.
    """
    files: list[Path] = []
    skipped: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        kept = []
        for d in dirnames:
            if d in SKIP_DIRS:
                skipped.append({"file": str(rel_dir / d) + "/",
                                "reason": "excluded directory"})
            elif d.startswith(".") and d not in INCLUDE_DOTDIRS:
                skipped.append({"file": str(rel_dir / d) + "/",
                                "reason": "hidden directory (not CI config)"})
            else:
                kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            p = Path(dirpath) / name
            in_scope = (p.suffix.lower() in CODE_EXTENSIONS
                        or name.lower() in SPECIAL_FILENAMES)
            if not in_scope:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                skipped.append({"file": str(p.relative_to(root)),
                                "reason": f"over {MAX_FILE_BYTES} bytes"})
                continue
            files.append(p)
    return sorted(files), skipped


def detect_stack(root: Path, files: list[Path]) -> list[str]:
    hints: list[str] = []
    names = {p.name for p in files}
    if "package.json" in names:
        hints.append("Node.js/JavaScript (package.json)")
    if "requirements.txt" in names or any(p.suffix == ".py" for p in files):
        hints.append("Python")
    if (root / "manage.py").exists():
        hints.append("Django")
    if "go.mod" in names:
        hints.append("Go")
    if "composer.json" in names:
        hints.append("PHP")
    if any(p.name == "Dockerfile" for p in files):
        hints.append("Docker")
    return hints or ["generic source tree"]


def build_repo_map(root: Path, files: list[Path]) -> str:
    lines = [f"Repository: {root}", f"Stack hints: {', '.join(detect_stack(root, files))}",
             f"Files in scope: {len(files)}", ""]
    for p in files:
        rel = p.relative_to(root)
        size = p.stat().st_size
        lines.append(f"- {rel} ({size} B)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Phase 2: PLAN (prioritize what to audit)
# ---------------------------------------------------------------------------

def heuristic_priority(root: Path, files: list[Path]) -> list[dict]:
    """Rank files by security-relevant keyword density. Offline fallback."""
    ranked = []
    for p in files:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        score, reasons = 0, set()
        for pattern, category, desc, _sev in HEURISTIC_SINKS:
            if re.search(pattern, text):
                score += 3
                reasons.add(desc)
        for kw in ("auth", "login", "password", "token", "session", "admin",
                   "upload", "download", "exec", "query", "sql", "redirect"):
            if kw in p.name.lower() or kw in text.lower():
                score += 1
        ranked.append({"file": str(p.relative_to(root)), "score": score,
                       "reasons": sorted(reasons)})
    ranked.sort(key=lambda r: (-r["score"], r["file"]))
    return ranked


def llm_priority(client: K3Client, repo_map: str, max_files: int) -> list[dict]:
    prompt = (
        "You are planning a security audit. Below is a repository map.\n"
        f"Pick the {max_files} files MOST likely to contain exploitable "
        "security issues (entry points, auth, data access, exec/eval, config, "
        "secret handling). Answer ONLY with JSON: "
        '{"plan": [{"file": str, "reason": str}]}\n\n' + repo_map
    )
    raw = client.chat([
        {"role": "system", "content": "You are a security audit planner. JSON only."},
        {"role": "user", "content": prompt},
    ])
    data = parse_json_block(raw)
    plan = data.get("plan", []) if isinstance(data, dict) else []
    return [{"file": str(item.get("file")), "reason": item.get("reason", ""),
             "score": 10, "reasons": [item.get("reason", "")]}
            for item in plan if item.get("file")]


# ---------------------------------------------------------------------------
# Phase 3: FAN-OUT (audit files / chunks in parallel)
# ---------------------------------------------------------------------------

def chunk_python(text: str, target: int = CHUNK_TARGET_CHARS) -> list[tuple[int, str]]:
    """Split large Python files on top-level def/class boundaries."""
    if len(text) <= target:
        return [(1, text)]
    chunks: list[tuple[int, str]] = []
    current: list[str] = []
    start_line = 1
    for i, line in enumerate(text.splitlines(keepends=True), start=1):
        if (re.match(r"^(def |class |async def )", line)
                and sum(len(l) for l in current) > target):
            chunks.append((start_line, "".join(current)))
            start_line, current = i, []
        current.append(line)
    if current:
        chunks.append((start_line, "".join(current)))
    return chunks or [(1, text)]


def chunk_lines(text: str, target: int = CHUNK_TARGET_CHARS,
                overlap: int = CHUNK_OVERLAP_LINES) -> list[tuple[int, str]]:
    """Generic window chunker for non-Python files: split near the target
    size on blank lines, with a small line overlap for context."""
    if len(text) <= target:
        return [(1, text)]
    lines = text.splitlines(keepends=True)
    chunks: list[tuple[int, str]] = []
    start, size = 0, 0
    for i, line in enumerate(lines):
        size += len(line)
        if size > target and not line.strip():
            chunks.append((start + 1, "".join(lines[start:i + 1])))
            start = max(start + 1, i + 1 - overlap)
            size = sum(len(l) for l in lines[start:i + 1])
    if start < len(lines):
        chunks.append((start + 1, "".join(lines[start:])))
    return chunks or [(1, text)]


def chunk_file(path: Path, text: str) -> list[tuple[int, str]]:
    if path.suffix.lower() == ".py":
        chunks = chunk_python(text)
        # No top-level def/class boundaries found (script-style files):
        # fall back to windows so oversize files never go as one chunk.
        if len(chunks) == 1 and len(text) > CHUNK_TARGET_CHARS * 1.6:
            return chunk_lines(text)
        return chunks
    return chunk_lines(text)


def audit_chunk(client: K3Client, rel: str, chunk: str, start_line: int,
                dry_run: bool, strict_state: dict) -> list[Finding]:
    if dry_run:
        return heuristic_audit(rel, chunk, start_line)
    numbered = "\n".join(
        f"{start_line + n}: {line}" for n, line in enumerate(chunk.splitlines())
    )
    messages = [
        {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
        {"role": "user", "content": f"FILE: {rel}\n\n{numbered}"},
    ]
    # Prefer strict JSON Schema; fall back to tolerant parsing if the
    # provider rejects it (and stop paying for rejections after a few).
    use_strict = strict_state["failures"] < STRICT_SCHEMA_MAX_FAILURES
    try:
        raw = client.chat(messages,
                          response_format=FINDINGS_JSON_SCHEMA if use_strict else None)
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
        findings.append(Finding(
            file=rel,
            title=str(f.get("title", ""))[:200],
            category=str(f.get("category", "uncategorized"))[:120],
            severity=str(f.get("severity", "info")).lower(),
            line=f.get("line") if isinstance(f.get("line"), int) else None,
            evidence=str(f.get("evidence", ""))[:600],
            attack_path=str(f.get("attack_path", ""))[:800],
            fix=str(f.get("fix", ""))[:800],
        ))
    return findings


def heuristic_audit(rel: str, chunk: str, start_line: int) -> list[Finding]:
    findings = []
    for n, line in enumerate(chunk.splitlines(), start=start_line):
        if HEURISTIC_SKIP_LINE.match(line):
            continue
        for pattern, category, desc, sev in HEURISTIC_SINKS:
            if category == "surface":
                continue
            if re.search(pattern, line):
                findings.append(Finding(
                    file=rel, title=f"[heuristic] {desc}", category=category,
                    severity=sev, line=n, evidence=line.strip()[:200],
                    attack_path="(dry-run heuristic; run with an API key for analysis)",
                    fix="Review and validate input handling on this line."))
                break
    return findings


# ---------------------------------------------------------------------------
# Phase 5: VERIFY
# ---------------------------------------------------------------------------

def verify_finding(client: K3Client, root: Path, finding: Finding,
                   dry_run: bool) -> Finding:
    if dry_run:
        finding.verdict = "unverified"
        finding.verifier_notes = "dry-run: verification pass requires the model"
        return finding
    path = root / finding.file
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        finding.verdict = "unverified"
        return finding
    lo = max(0, (finding.line or 1) - 30)
    hi = min(len(lines), (finding.line or len(lines)) + 30)
    context = "\n".join(f"{lo + i + 1}: {l}" for i, l in enumerate(lines[lo:hi]))
    raw = client.chat([
        {"role": "system", "content": VERIFY_SYSTEM_PROMPT},
        {"role": "user", "content":
            f"FILE: {finding.file}\n\nCODE CONTEXT:\n{context}\n\n"
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
# Helpers
# ---------------------------------------------------------------------------

def parse_json_block(raw: str) -> dict | list:
    """Extract the first JSON object/array from a model reply."""
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return {}


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.key, f)
    out = sorted(seen.values(),
                 key=lambda f: (SEVERITY_ORDER.get(f.final_severity, 9), f.file,
                                f.line or 0))
    return out


def write_reports(findings: list[Finding], out_dir: Path, repo: Path,
                  elapsed: float, dry_run: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "audit-findings.json").write_text(
        json.dumps([asdict(f) for f in findings], indent=2))

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.final_severity] = counts.get(f.final_severity, 0) + 1
    lines = [
        f"# Security Audit Report: {repo.name}",
        "",
        f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Mode: {'DRY-RUN (local heuristics, not a real audit)' if dry_run else 'Kimi K3 divide-and-conquer audit'}",
        f"- Elapsed: {elapsed:.1f}s",
        f"- Findings: " + (", ".join(f"{k}: {v}" for k, v in sorted(
            counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))) or "none"),
        "",
        "## Findings",
        "",
    ]
    for i, f in enumerate(findings, 1):
        badge = f.final_severity.upper()
        verdict = f" (verdict: {f.verdict})" if f.verdict != "unverified" else ""
        lines += [
            f"### {i}. [{badge}] {f.title}",
            "",
            f"- **File:** `{f.file}`" + (f" (line {f.line})" if f.line else ""),
            f"- **Category:** {f.category}{verdict}",
            f"- **Evidence:** `{f.evidence}`" if f.evidence else "",
            f"- **Attack path:** {f.attack_path}" if f.attack_path else "",
            f"- **Fix:** {f.fix}" if f.fix else "",
        ]
        if f.validation_steps:
            lines.append(f"- **Validate:** {f.validation_steps}")
        if f.verifier_notes:
            lines.append(f"- **Verifier notes:** {f.verifier_notes}")
        lines.append("")
    (out_dir / "audit-report.md").write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Divide-and-conquer security audit with Kimi K3")
    ap.add_argument("repo", help="path to the repository to audit")
    ap.add_argument("--out", default="./audit-out", help="output directory")
    ap.add_argument("--max-files", type=int, default=20, help="max files to fan out on")
    ap.add_argument("--workers", type=int, default=4, help="parallel audit workers")
    ap.add_argument("--verify", action="store_true",
                    help="run the second-pass verification on critical/high findings")
    ap.add_argument("--dry-run", action="store_true",
                    help="offline pipeline test with local heuristics (NOT a real audit)")
    ap.add_argument("--allow-cloud-upload", action="store_true",
                    help="consent to sending source code to the hosted inference API "
                         "(or set K3_ALLOW_UPLOAD=1)")
    args = ap.parse_args()

    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    out_dir = Path(args.out).resolve()
    t0 = time.time()

    print(f"[1/5] Mapping repository: {root}")
    files, skipped = iter_repo_files(root)
    if not files:
        print("No source files found in scope.", file=sys.stderr)
        return 2
    repo_map = build_repo_map(root, files)
    print(f"      {len(files)} files in scope, {len(skipped)} skipped "
          f"(see coverage.json)")

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

    print("[2/5] Planning audit priorities")
    if args.dry_run:
        plan = heuristic_priority(root, files)
    else:
        try:
            plan = llm_priority(client, repo_map, args.max_files)
        except K3Error as exc:
            print(f"      model planning failed ({exc}); using heuristics")
            plan = heuristic_priority(root, files)
        known = {str(p.relative_to(root)) for p in files}
        plan = [p for p in plan if p["file"] in known] or heuristic_priority(root, files)
    plan = plan[: args.max_files]
    for p in plan[:5]:
        print(f"      - {p['file']}")

    # Persist the plan and coverage BEFORE the fan-out, so a run always
    # leaves evidence of what it intended to audit and what it covered.
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "audit-plan.json").write_text(json.dumps(
        {"planner": "heuristic" if args.dry_run else "model",
         "files": plan}, indent=2))

    print(f"[3/5] Fan-out: auditing {len(plan)} files with {args.workers} workers")
    all_findings: list[Finding] = []
    tasks = []
    chunks_per_file: dict[str, int] = {}
    for item in plan:
        path = root / item["file"]
        try:
            text = path.read_text(errors="replace")
        except OSError:
            skipped.append({"file": item["file"], "reason": "unreadable"})
            continue
        file_chunks = chunk_file(path, text)
        chunks_per_file[item["file"]] = len(file_chunks)
        for start_line, chunk in file_chunks:
            tasks.append((item["file"], chunk, start_line))
    (out_dir / "coverage.json").write_text(json.dumps({
        "in_scope_files": [str(p.relative_to(root)) for p in files],
        "audited_files": [item["file"] for item in plan],
        "chunks_per_file": chunks_per_file,
        "skipped": skipped,
    }, indent=2))
    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(audit_chunk, client, rel, chunk, sl,
                            args.dry_run, strict_state): rel
                for rel, chunk, sl in tasks}
        for fut in futures.as_completed(futs):
            try:
                all_findings.extend(fut.result())
            except Exception as exc:  # one bad chunk must not kill the audit
                print(f"      warning: chunk failed for {futs[fut]}: {exc}")
    print(f"      raw findings: {len(all_findings)}")

    print("[4/5] Fan-in: de-duplicating and ranking")
    findings = dedupe(all_findings)
    print(f"      unique findings: {len(findings)}")

    if args.verify and not args.dry_run:
        hot = [f for f in findings if f.final_severity in ("critical", "high")]
        print(f"[5/5] Verification pass on {len(hot)} critical/high findings")
        with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(lambda f: verify_finding(client, root, f, args.dry_run), hot))
        findings = [f for f in findings
                    if not (f.verdict == "false_positive")]
        findings = dedupe(findings)
    else:
        print("[5/5] Verification pass skipped (use --verify to enable)")

    elapsed = time.time() - t0
    write_reports(findings, out_dir, root, elapsed, args.dry_run)
    manifest = {
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "repo": str(root),
        "mode": "dry-run" if args.dry_run else "model",
        "provider": None if args.dry_run else client.provider,
        "model": None if args.dry_run else client.model,
        "strict_json_schema": "used" if strict_state["used"] else
                              ("rejected" if strict_state["failures"] else "not attempted"),
        "verification_pass": bool(args.verify and not args.dry_run),
        "files_in_scope": len(files),
        "files_audited": len({f.file for f in all_findings} | {t[0] for t in tasks}),
        "chunks_audited": len(tasks),
        "findings": len(findings),
        "elapsed_seconds": round(elapsed, 1),
    }
    if not args.dry_run:
        manifest["token_usage"] = client.usage_totals
        manifest["estimated_cost"] = client.estimate_cost() or "pricing unknown"
    (out_dir / "run-manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  JSON:     {out_dir / 'audit-findings.json'}")
    print(f"  Report:   {out_dir / 'audit-report.md'}")
    print(f"  Plan:     {out_dir / 'audit-plan.json'}")
    print(f"  Coverage: {out_dir / 'coverage.json'}")
    print(f"  Manifest: {out_dir / 'run-manifest.json'}")
    crit = sum(1 for f in findings if f.final_severity in ("critical", "high"))
    return 1 if crit else 0


if __name__ == "__main__":
    sys.exit(main())
