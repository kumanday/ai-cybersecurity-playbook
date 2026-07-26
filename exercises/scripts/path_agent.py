#!/usr/bin/env python3
"""
path_agent.py: a minimal K3 tool-calling security investigator (Level 3).

*** READ THIS FIRST: what this script is and is not ***

This is the hands-on capstone for playbook §5.4 ("Three ways to orchestrate").
It is a REFERENCE IMPLEMENTATION of native tool-calling with Kimi K3, written
to be read and adapted, not a better scanner.

  * It finds NOTHING that path_audit.py doesn't find, and it does so
    non-deterministically: same question, different investigation path,
    different cost. That contrast is the lesson (least agency, §5.4).
  * Its practical value is the PATTERN: how to register tools, run a bounded
    loop, preserve complete assistant messages (reasoning fields included;
    the K3 multi-turn contract, handled by k3_client.chat_with_tools), and
    sandbox tool file access to a target directory. If you are building your
    own agentic tooling on K3, lift this skeleton and swap in your tools.
  * If you just want reachability answers on your repo, use path_audit.py.

What it does: you give it a repo and a security question
("is the SQLi in app.py reachable from an unauthenticated route?"). K3 then
drives the investigation itself through a small read-only tool set
(list_files, read_file, search_code, get_references) for up to N rounds,
and returns a verdict with the evidence path it actually used.

Usage:
    python3 scripts/path_agent.py ../sample-vuln-app \
        --question "Is the SQL injection in app.py reachable from an
                    unauthenticated route?" --allow-cloud-upload

Artifacts: agent-transcript.json (every message and tool call, the
debugging/teaching payload) and agent-verdict.md.

Safety properties: tools are read-only and path-sandboxed to the target
directory; the loop is bounded; every tool call is logged; the model cannot
write, execute, or network-call from this harness. The --allow-cloud-upload
gate applies because file contents leave your machine.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k3_client import K3Client, K3Error, require_upload_consent  # noqa: E402
from code_audit import iter_repo_files  # noqa: E402

MAX_READ_LINES = 300          # per read_file call; keeps rounds cheap
MAX_SEARCH_HITS = 50
DEFAULT_QUESTION = ("Is the SQL injection in app.py reachable from an "
                    "unauthenticated route? Trace the path from the route "
                    "to the database call.")

SYSTEM_PROMPT = """You are a security investigator with read-only tools into ONE
codebase. Answer the user's question by investigating; do not guess from
filenames. Rules:
- Use tools to read the actual code. Cite file:line for every claim.
- Keep reads small and targeted (line windows, searches), not whole files.
- Your tools are READ-ONLY and sandboxed to the target directory.
- When you have enough evidence, STOP calling tools and answer with:
  VERDICT: <reachable | not reachable | inconclusive>
  PATH: entry -> hop -> ... -> sink (file:line per hop)
  EVIDENCE: the key lines, quoted briefly
  CAVEATS: what static reading cannot establish
- If a tool errors, adapt; do not retry the identical call."""


# ---------------------------------------------------------------------------
# Tool implementations (read-only, sandboxed to root)
# ---------------------------------------------------------------------------

class RepoTools:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.files, _skipped = iter_repo_files(self.root)
        self.rel_files = sorted(str(p.relative_to(self.root)) for p in self.files)

    def _resolve(self, path: str) -> Path:
        """Confine all access to the target tree (no ../ escapes)."""
        p = (self.root / path).resolve()
        if not str(p).startswith(str(self.root) + os.sep) and p != self.root:
            raise K3Error(f"path escapes the sandbox: {path!r}")
        return p

    def list_files(self, args: dict) -> str:
        sub = args.get("path", "").strip()
        if sub:
            base = self._resolve(sub)
            listing = [str(p.relative_to(self.root)) for p in self.files
                       if str(p).startswith(str(base))]
        else:
            listing = self.rel_files
        if not listing:
            return f"(no files under {sub or '.'})"
        return "\n".join(listing[:200])

    def read_file(self, args: dict) -> str:
        path = self._resolve(str(args.get("path", "")))
        if not path.is_file():
            return f"error: no such file {args.get('path')!r}"
        lines = path.read_text(errors="replace").splitlines()
        start = max(int(args.get("start_line", 1) or 1), 1)
        end = int(args.get("end_line", 0) or 0)
        end = min(end, len(lines)) if end else min(start + MAX_READ_LINES - 1,
                                                   len(lines))
        if start > len(lines):
            return f"(file has {len(lines)} lines; start_line {start} is beyond it)"
        body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
        return f"{path.relative_to(self.root)} lines {start}-{end} of {len(lines)}:\n{body}"

    def search_code(self, args: dict) -> str:
        pattern = str(args.get("pattern", ""))
        if not pattern:
            return "error: empty pattern"
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"error: bad regex: {exc}"
        hits = []
        for p in self.files:
            try:
                for n, line in enumerate(p.read_text(errors="replace")
                                         .splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{p.relative_to(self.root)}:{n}: "
                                    f"{line.strip()[:160]}")
                        if len(hits) >= MAX_SEARCH_HITS:
                            return "\n".join(hits) + "\n(truncated)"
            except OSError:
                continue
        return "\n".join(hits) if hits else f"(no matches for {pattern!r})"

    def get_references(self, args: dict) -> str:
        symbol = str(args.get("symbol", "")).strip()
        if not symbol:
            return "error: empty symbol"
        rx = re.compile(rf"\b(def\s+{re.escape(symbol)}|{re.escape(symbol)}\s*\()")
        defs, calls = [], []
        for p in self.files:
            try:
                for n, line in enumerate(p.read_text(errors="replace")
                                         .splitlines(), 1):
                    if rx.search(line):
                        entry = f"{p.relative_to(self.root)}:{n}: {line.strip()[:140]}"
                        (defs if re.search(rf"def\s+{re.escape(symbol)}", line)
                         else calls).append(entry)
            except OSError:
                continue
        out = [f"definitions of {symbol!r}:"] + (defs or ["  (none)"])
        out += [f"call sites ({len(calls)}, first 25):"] + calls[:25]
        return "\n".join(out)


TOOL_SPECS = [
    {"type": "function", "function": {
        "name": "list_files",
        "description": "List in-scope source files in the repository "
                       "(optionally under a subdirectory).",
        "parameters": {"type": "object",
                       "properties": {"path": {"type": "string",
                                               "description": "subdirectory, optional"}},
                       "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a line window of a file (default first 300 lines). "
                       "Use small windows; follow up for more.",
        "parameters": {"type": "object",
                       "properties": {
                           "path": {"type": "string"},
                           "start_line": {"type": "integer"},
                           "end_line": {"type": "integer"}},
                       "required": ["path"],
                       "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "search_code",
        "description": "Regex search across all in-scope files; returns "
                       "file:line matches (max 50).",
        "parameters": {"type": "object",
                       "properties": {"pattern": {"type": "string"}},
                       "required": ["pattern"],
                       "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "get_references",
        "description": "Find where a function/symbol is defined and called "
                       "across the repo.",
        "parameters": {"type": "object",
                       "properties": {"symbol": {"type": "string"}},
                       "required": ["symbol"],
                       "additionalProperties": False}}},
]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="K3 tool-calling security investigator (§5.4 Level 3 capstone "
                    "(a reference implementation, not a scanner)")
    ap.add_argument("repo", help="path to the repository to investigate")
    ap.add_argument("--question", default=DEFAULT_QUESTION,
                    help="the security question K3 investigates")
    ap.add_argument("--out", default="./agent-out", help="output directory")
    ap.add_argument("--max-rounds", type=int, default=8,
                    help="bound on tool-loop rounds")
    ap.add_argument("--effort", default=None, choices=["low", "high", "max"],
                    help="reasoning_effort override (default: server default, max)")
    ap.add_argument("--allow-cloud-upload", action="store_true",
                    help="consent to sending source code to the hosted inference "
                         "API (or set K3_ALLOW_UPLOAD=1)")
    args = ap.parse_args()

    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    client = K3Client()
    if not client.configured:
        print("This lab IS the model loop; there is no offline mode.\n"
              "Set FIREWORKS_API_KEY (or K3_PROVIDER=moonshot + MOONSHOT_API_KEY).",
              file=sys.stderr)
        return 2
    try:
        require_upload_consent(args.allow_cloud_upload, client.provider,
                               "source code from this repository")
    except K3Error as exc:
        print(exc, file=sys.stderr)
        return 2

    tools = RepoTools(root)
    handlers = {"list_files": tools.list_files, "read_file": tools.read_file,
                "search_code": tools.search_code,
                "get_references": tools.get_references}

    print(f"Question: {args.question}")
    print(f"Repo:     {root} ({len(tools.rel_files)} in-scope files)")
    print(f"Loop:     max {args.max_rounds} rounds, tools: {list(handlers)}")
    t0 = time.time()
    result = client.chat_with_tools(
        messages=[{"role": "system", "content": SYSTEM_PROMPT},
                  {"role": "user", "content":
                   f"Repository root has these files available via tools.\n\n"
                   f"QUESTION: {args.question}"}],
        tools=TOOL_SPECS, handlers=handlers,
        max_rounds=args.max_rounds, reasoning_effort=args.effort)
    elapsed = time.time() - t0

    tool_log = [m for m in result["messages"] if m.get("role") == "tool"]
    print(f"\nRounds: {result['rounds']}   tool calls: {len(tool_log)}   "
          f"elapsed: {elapsed:.1f}s")
    if result.get("error"):
        print(f"WARNING: {result['error']}")

    transcript = {
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "repo": str(root), "question": args.question,
        "rounds": result["rounds"], "tool_calls": len(tool_log),
        "elapsed_seconds": round(elapsed, 1),
        "token_usage": client.usage_totals,
        "estimated_cost": client.estimate_cost() or "pricing unknown",
        "error": result.get("error"),
        # Full history INCLUDING reasoning fields: the K3 contract this
        # lab exists to demonstrate. Handle as sensitive.
        "messages": result["messages"],
    }
    (out_dir / "agent-transcript.json").write_text(json.dumps(
        transcript, indent=2, default=str))

    verdict = result.get("content") or "(no final answer; see transcript)"
    (out_dir / "agent-verdict.md").write_text(
        f"# Agent Verdict\n\n**Question:** {args.question}\n\n"
        f"**Rounds:** {result['rounds']} | **Tool calls:** {len(tool_log)} | "
        f"**Elapsed:** {elapsed:.1f}s\n\n---\n\n{verdict}\n")
    print(f"\n{verdict}\n")
    print(f"  Verdict:    {out_dir / 'agent-verdict.md'}")
    print(f"  Transcript: {out_dir / 'agent-transcript.json'}")
    cost = client.estimate_cost()
    if cost:
        print(f"  Estimated cost: ${cost['usd']:.4f} "
              f"({cost['fresh_input_tokens']} fresh in / "
              f"{cost['cached_input_tokens']} cached in / "
              f"{cost['output_tokens']} out)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
