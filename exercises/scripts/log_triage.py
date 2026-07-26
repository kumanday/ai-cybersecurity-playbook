#!/usr/bin/env python3
"""
log_triage.py: authentication-log anomaly triage with Kimi K3.

Demonstrates the "model as SOC analyst" pattern (playbook, Part IV §9):
deterministic code computes the statistics that matter (failure bursts,
success-after-failure, impossible travel, off-hours access), then K3 turns
those facts into an incident assessment with containment steps. The model
never has to count; it only has to reason.

Usage:
    python3 scripts/log_triage.py ../sample-data/auth-sample.log --dry-run
    python3 scripts/log_triage.py /var/log/auth.log --out ./out
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k3_client import K3Client, K3Error, require_upload_consent  # noqa: E402

ANALYST_SYSTEM_PROMPT = """You are a SOC analyst writing an incident assessment for
a small-company responder who is not a security professional.

You receive deterministic statistics computed from an authentication log,
plus sample raw lines. Do NOT recount the numbers; reason about them.

Produce Markdown:

## Assessment
One paragraph: what is happening, confidence level, and why.

## Severity
critical / high / medium / low, with a one-line justification.

## Timeline
Bulleted, minute-level where the data allows.

## Immediate containment (next 30 minutes)
Numbered, concrete, and safe for a non-expert (disable account X, block IP Y
at the firewall/WAF, force credential reset, preserve the log file).

## Follow-up investigation
What to check next (which commands / consoles), and what evidence to preserve.

## Prevention
2-4 durable controls that would have stopped or caught this earlier.

Rules: stay within what the data supports; flag uncertainty explicitly;
no offensive tradecraft detail."""

TS_FORMATS = ["%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
OK_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")


def parse_ts(line: str) -> datetime | None:
    for fmt in TS_FORMATS:
        for cand in (line[:15], line[:19]):
            try:
                text = cand.strip()
                if fmt == "%b %d %H:%M:%S":  # syslog style has no year
                    text = f"{datetime.now().year} {text}"
                    return datetime.strptime(text, f"%Y {fmt}")
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def analyze(events: list[dict]) -> dict:
    """Deterministic anomaly statistics over parsed events."""
    stats: dict = {
        "total_events": len(events),
        "failed_by_ip": defaultdict(int),
        "failed_by_user": defaultdict(int),
        "successes": [],
        "success_after_failures": [],
        "off_hours_successes": [],
        "impossible_travel": [],
        "privilege_users_targeted": defaultdict(int),
    }
    failures_by_user: dict[str, list[datetime]] = defaultdict(list)
    success_by_user: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    for ev in events:
        if ev["kind"] == "failed":
            stats["failed_by_ip"][ev["ip"]] += 1
            stats["failed_by_user"][ev["user"]] += 1
            failures_by_user[ev["user"]].append(ev["ts"])
            if ev["user"] in ("root", "admin", "administrator"):
                stats["privilege_users_targeted"][ev["user"]] += 1
        else:
            stats["successes"].append(
                {"user": ev["user"], "ip": ev["ip"], "ts": ev["ts"].isoformat()})
            success_by_user[ev["user"]].append((ev["ts"], ev["ip"]))
            if ev["ts"].hour < 6 or ev["ts"].hour >= 22:
                stats["off_hours_successes"].append(
                    {"user": ev["user"], "ip": ev["ip"], "ts": ev["ts"].isoformat()})

    # Success shortly after >= 5 failures from the same IP → possible breach.
    for ev in events:
        if ev["kind"] != "ok":
            continue
        recent = [f for f in events
                  if f["kind"] == "failed" and f["ip"] == ev["ip"]
                  and 0 <= (ev["ts"] - f["ts"]).total_seconds() <= 3600]
        if len(recent) >= 5:
            stats["success_after_failures"].append({
                "user": ev["user"], "ip": ev["ip"],
                "failures_in_prior_hour": len(recent), "ts": ev["ts"].isoformat()})

    # Same user, different IPs, far apart, within 30 min → impossible travel.
    for user, hits in success_by_user.items():
        hits.sort()
        for (t1, ip1), (t2, ip2) in zip(hits, hits[1:]):
            first_octets = ip1.split(".")[:2] != ip2.split(".")[:2]
            minutes = (t2 - t1).total_seconds() / 60
            if first_octets and 0 < minutes <= 30:
                stats["impossible_travel"].append({
                    "user": user, "ip_from": ip1, "ip_to": ip2,
                    "minutes_apart": round(minutes, 1)})

    for key in ("failed_by_ip", "failed_by_user", "privilege_users_targeted"):
        stats[key] = dict(sorted(stats[key].items(), key=lambda kv: -kv[1])[:10])
    return stats


def dry_run_assessment(stats: dict) -> str:
    lines = ["## Deterministic signals (offline mode)", ""]
    if stats["success_after_failures"]:
        lines.append(
            f"- **Possible successful brute force:** {len(stats['success_after_failures'])} "
            f"login(s) succeeded within an hour of 5+ failures from the same IP.")
    if stats["impossible_travel"]:
        lines.append(
            f"- **Impossible travel:** {len(stats['impossible_travel'])} user(s) logged in "
            "from distant networks minutes apart.")
    if stats["off_hours_successes"]:
        lines.append(f"- **Off-hours logins:** {len(stats['off_hours_successes'])}")
    top_ip = next(iter(stats["failed_by_ip"].items()), None)
    if top_ip:
        lines.append(f"- **Noisiest source:** {top_ip[0]} with {top_ip[1]} failures")
    if not any([stats["success_after_failures"], stats["impossible_travel"],
                stats["off_hours_successes"]]):
        lines.append("- No strong anomaly signals in the deterministic pass.")
    lines += ["", "*Run with a Fireworks/Moonshot API key for the full K3 incident "
              "assessment (timeline, containment, follow-up).*"]
    return "\n".join(lines)


def render_markdown(stats: dict, assessment: str, source: str, dry_run: bool) -> str:
    return "\n".join([
        f"# Authentication Log Triage: {source}", "",
        f"- Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Mode: {'DRY-RUN (statistics only)' if dry_run else 'Kimi K3 SOC analyst pass'}",
        f"- Events parsed: {stats['total_events']}", "",
        "## Computed statistics", "",
        "```json", json.dumps(stats, indent=2, default=str)[:6000], "```", "",
        "## Analyst assessment", "", assessment, "",
    ])


def main() -> int:
    ap = argparse.ArgumentParser(description="Auth-log anomaly triage with Kimi K3")
    ap.add_argument("logfile", help="auth.log-style file to analyze")
    ap.add_argument("--out", help="output directory (defaults to log file's directory)")
    ap.add_argument("--dry-run", action="store_true", help="statistics only, no model call")
    ap.add_argument("--sample-lines", type=int, default=40,
                    help="raw lines to include for the model as color")
    ap.add_argument("--allow-cloud-upload", action="store_true",
                    help="consent to sending log data to the hosted inference API "
                         "(or set K3_ALLOW_UPLOAD=1)")
    args = ap.parse_args()

    path = Path(args.logfile).resolve()
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2

    print(f"[1/3] Parsing {path.name}")
    events: list[dict] = []
    raw_lines = path.read_text(errors="replace").splitlines()
    for line in raw_lines:
        m = FAILED_RE.search(line) or OK_RE.search(line)
        if not m:
            continue
        ts = parse_ts(line)
        if ts is None:
            continue
        events.append({"kind": "failed" if "Failed" in line else "ok",
                       "user": m.group("user"), "ip": m.group("ip"), "ts": ts})
    if not events:
        print("No sshd-style auth events parsed. Expecting lines like "
              "'Failed password for user from ip'.", file=sys.stderr)
        return 2
    print(f"      {len(events)} auth events")

    print("[2/3] Computing anomaly statistics")
    stats = analyze(events)
    print(f"      success-after-failures: {len(stats['success_after_failures'])}, "
          f"impossible travel: {len(stats['impossible_travel'])}, "
          f"off-hours: {len(stats['off_hours_successes'])}")

    client = K3Client()
    dry = args.dry_run or not client.configured
    if dry and not args.dry_run:
        print("      no API key; statistics-only mode")
    if not dry:
        try:
            require_upload_consent(args.allow_cloud_upload, client.provider,
                                   "authentication log contents")
        except K3Error as exc:
            print(exc, file=sys.stderr)
            return 2
    print("[3/3] Analyst assessment")
    if dry:
        assessment = dry_run_assessment(stats)
    else:
        sample = "\n".join(raw_lines[-args.sample_lines:])
        assessment = client.chat([
            {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
            {"role": "user", "content":
                "COMPUTED STATISTICS (trust these, they are exact):\n"
                + json.dumps(stats, indent=2, default=str)
                + "\n\nSAMPLE RAW LINES (most recent):\n" + sample},
        ], max_tokens=8192)
        cost = client.estimate_cost()
        assessment += (f"\n\n---\n*Model usage: "
                       f"{client.usage_totals.get('prompt_tokens', 0)} prompt + "
                       f"{client.usage_totals.get('completion_tokens', 0)} completion tokens"
                       + (f"; estimated cost ${cost['usd']}" if cost else "")
                       + f" ({client.provider} / {client.model}).*")

    out_dir = Path(args.out).resolve() if args.out else path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / "log-triage-report.md"
    report.write_text(render_markdown(stats, assessment, path.name, dry))
    print(f"  Report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
