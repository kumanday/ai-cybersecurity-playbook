#!/usr/bin/env python3
"""
nmap_triage.py: turn raw nmap output into a prioritized exposure report.

The pattern this demonstrates (playbook, Part IV §9): classic tools stay
classic: nmap does the scanning. The model replaces the *analyst staring at
the output*: it correlates services, versions, and exposure, then produces a
prioritized action list a non-specialist can execute.

Pipeline:
    1. Parse nmap XML (-oX) or grepable (-oG) output.
    2. Deterministic rule pass flags well-known bad exposures.
    3. K3 turns the parsed inventory + rule hits into a triaged report with
       rationale and safe next-step validation commands.
    4. Markdown report written to disk.

Authorized use only: scan networks you own or have written permission to test.

Usage:
    nmap -sV -oX scan.xml 192.0.2.10            # your own host
    python3 scripts/nmap_triage.py scan.xml --out ./out
    python3 scripts/nmap_triage.py ../sample-data/nmap-sample.xml --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from k3_client import K3Client, K3Error, require_upload_consent  # noqa: E402

TRIAGE_SYSTEM_PROMPT = """You are a network-security analyst triaging port-scan
results for a small-company defender with limited security staff.

You receive: (a) a parsed inventory of hosts/open ports/services/versions and
(b) rule-based flags already raised. Produce a triage report in Markdown:

## Exposure summary
One short paragraph: overall posture in plain language.

## Priority findings
A table: Priority | Host | Port/Service | Why it matters | Next step.
- Rank by real-world exploitability and blast radius, not by CVSS theater.
- "Next step" must be a safe, read-only validation or a concrete fix
  (e.g. "confirm whether X requires auth", "restrict to VPN", "upgrade Y").
- Do NOT include exploit instructions or weaponization detail.

## Quick wins
Bulleted list of changes achievable in under an hour.

## What looks fine
One line on what does NOT need action, so the reader can stop worrying about it.

Be concrete and calm. If something is ambiguous, say what to check."""

# Deterministic rules: (matcher, severity, why, next_step)
RULES = [
    (lambda s: s["port"] == 23, "high", "Telnet is cleartext and frequently internet-scanned", "Disable Telnet; use SSH"),
    (lambda s: s["port"] == 21, "medium", "FTP is cleartext; check for anonymous login", "Confirm auth required; prefer SFTP"),
    (lambda s: s["port"] == 445, "medium", "SMB exposed; ransomware-favorite lateral movement vector", "Restrict to LAN/VPN; disable SMBv1"),
    (lambda s: s["port"] == 3389, "medium", "RDP exposed; common brute-force/BlueKeep-class target", "Put behind VPN/gateway; enforce MFA"),
    (lambda s: s["port"] in (27017, 9200, 6379, 11211), "high",
     "Datastore port open; these are routinely found unauthenticated on the internet",
     "Verify auth + bind address; restrict to app subnet"),
    (lambda s: s["port"] in (2375, 2376), "high", "Docker daemon socket exposed = trivial root on host", "Close or require TLS client certs"),
    (lambda s: bool(re.search(r"Apache httpd 2\.2|OpenSSH [1-6]\.|vsftpd 2\.3\.4|Samba [23]\.",
                              s.get("version", ""))), "high",
     "Service version with well-known public exploits", "Inventory and patch/upgrade immediately"),
    (lambda s: s["port"] in (8080, 8443, 8000, 8888) and "http" in s.get("service", ""), "low",
     "Alternate HTTP port; often forgotten admin panels or dev servers", "Identify the app; confirm it should exist"),
]


@dataclass
class Service:
    host: str
    port: int
    proto: str
    service: str
    version: str = ""
    flags: list[dict] = field(default_factory=list)


def parse_nmap_xml(path: Path) -> list[Service]:
    tree = ET.parse(path)
    services: list[Service] = []
    for host in tree.getroot().iter("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr", "?") if addr_el is not None else "?"
        for port_el in host.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            version = ""
            if svc_el is not None:
                version = " ".join(filter(None, [
                    svc_el.get("product", ""), svc_el.get("version", ""),
                    svc_el.get("extrainfo", "")])).strip()
            services.append(Service(
                host=addr,
                port=int(port_el.get("portid", "0")),
                proto=port_el.get("protocol", "tcp"),
                service=svc_name, version=version))
    return services


def parse_nmap_grepable(path: Path) -> list[Service]:
    services: list[Service] = []
    current_host = "?"
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("Host:"):
            m = re.match(r"Host:\s+(\S+)", line)
            if m:
                current_host = m.group(1)
            for port_desc in re.findall(r"(\d+)/open/[^/]*/([^/]*)/[^/]*/([^/]*)/", line):
                port, svc, ver = port_desc
                services.append(Service(host=current_host, port=int(port),
                                        proto="tcp", service=svc, version=ver))
    return services


def apply_rules(services: list[Service]) -> None:
    for s in services:
        d = {"port": s.port, "service": s.service, "version": s.version}
        for matcher, severity, why, step in RULES:
            try:
                if matcher(d):
                    s.flags.append({"severity": severity, "why": why, "next_step": step})
            except Exception:
                continue


def inventory_text(services: list[Service]) -> str:
    lines = []
    for s in services:
        line = f"- {s.host}:{s.port}/{s.proto} {s.service} {s.version}".rstrip()
        if s.flags:
            line += "  FLAGS: " + "; ".join(f["why"] for f in s.flags)
        lines.append(line)
    return "\n".join(lines) or "(no open ports parsed)"


def render_report(services: list[Service], analysis: str, scan_name: str,
                  out_dir: Path, elapsed: float, dry_run: bool) -> Path:
    flagged = [s for s in services if s.flags]
    md = [
        f"# Network Exposure Triage: {scan_name}",
        "",
        f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Mode: {'DRY-RUN (rules only, no model analysis)' if dry_run else 'Kimi K3 analyst pass'}",
        f"- Hosts/services parsed: {len({s.host for s in services})} / {len(services)}",
        f"- Rule-flagged services: {len(flagged)}",
        "",
        "## Parsed inventory",
        "",
        inventory_text(services),
        "",
        "## Analyst report",
        "",
        analysis,
        "",
    ]
    out = out_dir / "nmap-triage-report.md"
    out.write_text("\n".join(md))
    return out


def dry_run_analysis(services: list[Service]) -> str:
    flagged = [s for s in services if s.flags]
    if not flagged:
        return ("No rule-based flags raised. Run with an API key for full "
                "contextual analysis (exposure correlation, version risk, "
                "prioritized next steps).")
    lines = ["### Rule-based flags (offline mode)", "",
             "| Priority | Host | Port/Service | Why it matters | Next step |",
             "|---|---|---|---|---|"]
    order = {"high": 0, "medium": 1, "low": 2}
    for s in sorted(flagged, key=lambda x: order.get(x.flags[0]["severity"], 9)):
        for f in s.flags:
            lines.append(f"| {f['severity'].upper()} | {s.host} | "
                         f"{s.port}/{s.service or '?'} | {f['why']} | {f['next_step']} |")
    lines += ["", "*Run with a Fireworks/Moonshot API key for the K3 analyst "
              "pass: correlation across services, version-specific risk, and a "
              "prioritized action plan.*"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Triage nmap output with Kimi K3")
    ap.add_argument("scan", help="nmap output file (.xml from -oX, or .gnmap from -oG)")
    ap.add_argument("--out", help="output directory (defaults to scan file's directory)")
    ap.add_argument("--dry-run", action="store_true", help="rules-only, no model call")
    ap.add_argument("--allow-cloud-upload", action="store_true",
                    help="consent to sending scan data to the hosted inference API "
                         "(or set K3_ALLOW_UPLOAD=1)")
    args = ap.parse_args()

    scan_path = Path(args.scan).resolve()
    if not scan_path.is_file():
        print(f"error: {scan_path} not found", file=sys.stderr)
        return 2

    print(f"[1/3] Parsing {scan_path.name}")
    if scan_path.suffix.lower() == ".xml":
        services = parse_nmap_xml(scan_path)
    else:
        services = parse_nmap_grepable(scan_path)
    if not services:
        print("No open services parsed from the scan file.", file=sys.stderr)
        return 2
    print(f"      {len(services)} open services on {len({s.host for s in services})} hosts")

    print("[2/3] Applying exposure rules")
    apply_rules(services)
    flagged = sum(1 for s in services if s.flags)
    print(f"      {flagged} services flagged by rules")

    t0 = time.time()
    client = K3Client()
    dry = args.dry_run or not client.configured
    if dry and not args.dry_run:
        print("      no API key; using rules-only mode")
    if not dry:
        try:
            require_upload_consent(args.allow_cloud_upload, client.provider,
                                   "network scan inventory")
        except K3Error as exc:
            print(exc, file=sys.stderr)
            return 2
    print("[3/3] Analyst pass")
    if dry:
        analysis = dry_run_analysis(services)
    else:
        analysis = client.chat([
            {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content":
                "PARSED INVENTORY (with rule flags):\n" + inventory_text(services)},
        ], max_tokens=8192)
        cost = client.estimate_cost()
        usage = (f"\n\n---\n*Model usage: "
                 f"{client.usage_totals.get('prompt_tokens', 0)} prompt + "
                 f"{client.usage_totals.get('completion_tokens', 0)} completion tokens"
                 + (f"; estimated cost ${cost['usd']}" if cost else "")
                 + f" ({client.provider} / {client.model}).*")
        analysis += usage

    out_dir = Path(args.out).resolve() if args.out else scan_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    report = render_report(services, analysis, scan_path.name, out_dir,
                           time.time() - t0, dry)
    print(f"  Report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
