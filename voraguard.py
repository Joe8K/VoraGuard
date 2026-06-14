#!/usr/bin/env python3
"""
VoraGuard CLI
Professional threat intelligence scanner.

Usage:
  python voraguard.py --domain example.com
  python voraguard.py --ip 45.33.32.156
  python voraguard.py --target scanme.nmap.org
  python voraguard.py --domain example.com --passive
  python voraguard.py --domain example.com --json
  python voraguard.py --web
"""

import argparse
import sys
import os
import json
from pathlib import Path

# Ensure package root is on path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import settings
from utils.logger import get_logger
from utils.validator import validate_domain
from scanner.orchestrator import run_scan
from scanner.ip_intel import resolve_ip
from reports.html_report import generate_html_report

log = get_logger("voraguard.cli")

BANNER = r"""
 __   __ ___  ____   __    ___  _  _   __   ____  ____
 \ \ / // _ \|  _ \ / _|  / __|| || | / /  |  _ \|  _ \
  \ V /| | | | |_) | |_  | (_ || __ |/ /   | |_) | | | |
   \_/ |_| |_|____/ \__|  \___||_||_/_/    |____/|_| |_|

  Threat Intelligence Platform  |  v3.0  |  For authorized use only
"""


def print_banner():
    print("\033[36m" + BANNER + "\033[0m")


def print_summary(result):
    """Print a clean CLI summary of scan results."""
    risk = result.risk
    score = risk.get("score", 0)
    level = risk.get("risk_level", "UNKNOWN")

    # Color codes
    colors = {
        "LOW": "\033[32m",      # green
        "MODERATE": "\033[33m", # yellow
        "HIGH": "\033[31m",     # red
        "CRITICAL": "\033[91m"  # bright red
    }
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"
    cyan = "\033[36m"

    c = colors.get(level, "\033[37m")

    print(f"\n{bold}{'─'*60}{reset}")
    print(f"{bold}  VORAGUARD SCAN RESULTS — {result.domain.upper()}{reset}")
    print(f"{'─'*60}")
    print(f"\n  {bold}Risk Score:{reset}  {c}{bold}{score}/100  [{level}]{reset}")
    print(f"  {dim}Scan ID:    {result.scan_id}{reset}")
    print(f"  {dim}Duration:   {result.duration_seconds:.1f}s{reset}\n")

    # Open ports
    ports = result.nmap.get("open_ports", [])
    print(f"  {cyan}━━ OPEN PORTS ({len(ports)}){reset}")
    if ports:
        for p in ports:
            high_risk = p["port"] in [21, 22, 23, 25, 3306, 3389, 5900, 6379, 27017]
            flag = f"\033[31m[HIGH RISK]\033[0m" if high_risk else dim + "[monitor]" + reset
            print(f"    {p['port']:5}/{p['protocol']:<4}  {p['service']:<15} {p.get('version','')[:30]:<30} {flag}")
    else:
        print(f"    {dim}No open ports found / scan skipped{reset}")

    # Typosquatting
    typos = result.dnstwist.get("registered_count", 0)
    print(f"\n  {cyan}━━ TYPOSQUATTING{reset}")
    print(f"    Registered lookalike domains: {'\033[31m' if typos > 5 else '\033[33m' if typos > 0 else '\033[32m'}{typos}{reset}")

    # OSINT
    emails = result.harvester.get("emails", [])
    hosts = result.harvester.get("hosts", [])
    print(f"\n  {cyan}━━ OSINT{reset}")
    print(f"    Emails discovered:    {len(emails)}")
    print(f"    Subdomains found:     {len(hosts)}")

    # VirusTotal
    vt = result.vt_domain
    print(f"\n  {cyan}━━ VIRUSTOTAL{reset}")
    if vt.get("available"):
        vt_c = colors.get(vt.get("risk_level","").upper(), "\033[37m")
        print(f"    Verdict:  {vt_c}{vt.get('risk_level','unknown').upper()}{reset}  "
              f"({vt.get('malicious',0)}/{vt.get('total_engines',0)} engines)")
    else:
        print(f"    {dim}{vt.get('reason', 'Unavailable')}{reset}")

    # DNS
    dns = result.dns_health
    spf = "✓" if dns.get("spf", {}).get("present") else "✗"
    dmarc = "✓" if dns.get("dmarc", {}).get("present") else "✗"
    spf_c = "\033[32m" if spf == "✓" else "\033[31m"
    dmarc_c = "\033[32m" if dmarc == "✓" else "\033[31m"
    print(f"\n  {cyan}━━ DNS HEALTH{reset}")
    print(f"    SPF:    {spf_c}{spf}{reset}   DMARC:  {dmarc_c}{dmarc}{reset}")

    # SSL
    ssl = result.ssl_info
    print(f"\n  {cyan}━━ SSL / TLS{reset}")
    if ssl.get("valid"):
        days = ssl.get("expires_in_days", "?")
        print(f"    Valid certificate — expires in {days} days  ({ssl.get('issuer','')})")
    else:
        issues = ssl.get("issues", ["Unknown issue"])
        print(f"    \033[31m{issues[0]}\033[0m")

    # Key findings
    findings = risk.get("key_findings", [])
    if findings:
        print(f"\n  {cyan}━━ KEY FINDINGS{reset}")
        for f in findings:
            print(f"    \033[31m▲\033[0m {f}")

    print(f"\n{'─'*60}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="voraguard",
        description="VoraGuard — Professional Threat Intelligence Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--domain", "-d",
        help="Target domain to scan (e.g. example.com)"
    )
    parser.add_argument(
        "--ip", "-i",
        help="Target IP address to scan (e.g. 192.168.1.1)"
    )
    parser.add_argument(
        "--target", "-t",
        help="Auto-detect: scan domain or IP (e.g. example.com or 1.2.3.4)"
    )
    parser.add_argument(
        "--passive", "-p",
        action="store_true",
        help="Passive mode — skip nmap active scanning"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        dest="output_json",
        help="Output full results as JSON"
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML report generation"
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start the web dashboard instead of scanning"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.WEB_PORT,
        help=f"Web server port (default: {settings.WEB_PORT})"
    )

    args = parser.parse_args()

    # Web mode
    if args.web:
        os.environ["WEB_PORT"] = str(args.port)
        print(f"\033[36m  Starting VoraGuard web dashboard on http://localhost:{args.port}\033[0m\n")
        # Import here to avoid loading Flask for CLI-only runs
        from web.app import app
        app.run(host="0.0.0.0", port=args.port, debug=False)
        return

    # Determine target — support --domain, --ip, --target, or positional
    import re as _re
    raw_target = args.domain or args.ip or args.target or None

    if not raw_target:
        parser.print_help()
        print("\n\033[31mError: specify a target: ./scan.sh example.com  OR  ./scan.sh 45.33.32.156\033[0m\n")
        sys.exit(1)

    # Auto-detect IP vs domain
    _is_ip = bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_target.strip()))
    scan_mode = "ip" if (_is_ip or bool(args.ip)) else "domain"

    if scan_mode == "domain":
        try:
            domain = validate_domain(raw_target)
        except ValueError as e:
            print(f"\n\033[31mInvalid domain: {e}\033[0m\n")
            sys.exit(1)
    else:
        domain = raw_target.strip()

    # Check config warnings
    warnings = settings.validate()
    if warnings:
        print("\033[33m  Warnings:\033[0m")
        for w in warnings:
            print(f"  \033[33m⚠ {w}\033[0m")
        print()

    print(f"\033[36m  Target: {domain}\033[0m")
    mode_str = "IP Scan (4 APIs)" if scan_mode == "ip" else ("Passive (no nmap)" if args.passive else "Active Domain Scan")
    print(f"\033[36m  Mode:   {mode_str}\033[0m\n")

    # Run scan
    result = run_scan(domain, active_scan=not args.passive, scan_mode=scan_mode)

    if not result.success:
        print(f"\n\033[31mScan failed: {result.error}\033[0m\n")
        sys.exit(1)

    # Output
    if args.output_json:
        print(result.to_json())
    else:
        print_summary(result)

    # HTML Report
    if not args.no_report:
        report_path = generate_html_report(result.to_dict(), result.output_dir)
        print(f"\n  \033[32m✓ HTML report saved:\033[0m  file://{os.path.abspath(report_path)}")
        print(f"  \033[32m✓ Raw data saved:\033[0m     {result.output_dir}\n")


if __name__ == "__main__":
    main()
