"""
VoraGuard Core Scanners
Wrappers around nmap, dnstwist, theHarvester.
Each scanner returns a structured dict result.
"""

import subprocess
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

from utils.logger import get_logger
from config.settings import settings

log = get_logger(__name__)


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""


@dataclass
class NmapResult:
    success: bool
    target: str
    open_ports: List[OpenPort] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""

    def has_port(self, port: int) -> bool:
        return any(p.port == port for p in self.open_ports)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "target": self.target,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version
                }
                for p in self.open_ports
            ],
            "error": self.error
        }


@dataclass
class TyposquatEntry:
    fuzzer: str
    domain: str
    dns_a: str = ""
    dns_mx: str = ""
    registered: bool = False


@dataclass
class DnstwistResult:
    success: bool
    target: str
    typosquats: List[TyposquatEntry] = field(default_factory=list)
    registered_count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "target": self.target,
            "total_found": len(self.typosquats),
            "registered_count": self.registered_count,
            "typosquats": [
                {
                    "fuzzer": t.fuzzer,
                    "domain": t.domain,
                    "dns_a": t.dns_a,
                    "registered": t.registered
                }
                for t in self.typosquats[:50]  # cap at 50 for report
            ],
            "error": self.error
        }


@dataclass
class HarvesterResult:
    success: bool
    target: str
    emails: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "target": self.target,
            "emails": self.emails,
            "hosts": self.hosts,
            "ips": self.ips,
            "email_count": len(self.emails),
            "host_count": len(self.hosts),
            "error": self.error
        }


def run_nmap(domain: str, output_dir: Path) -> NmapResult:
    """Run nmap -sV --open against target. Parse results into OpenPort objects."""
    log.info(f"[nmap] Scanning {domain}...")
    outfile = output_dir / "nmap-active.txt"

    cmd = [
        settings.NMAP_PATH,
        "-sV",          # service version detection
        "-sC",          # default scripts
        "--open",       # only open ports
        "-T4",          # faster timing
        "--max-retries", "2",
        "-oN", str(outfile),
        domain
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.NMAP_TIMEOUT
        )

        raw = outfile.read_text() if outfile.exists() else result.stdout
        ports = _parse_nmap_output(raw)

        log.info(f"[nmap] Found {len(ports)} open ports on {domain}")
        return NmapResult(success=True, target=domain, open_ports=ports, raw_output=raw)

    except subprocess.TimeoutExpired:
        log.warning(f"[nmap] Timeout scanning {domain}")
        return NmapResult(success=False, target=domain, error="Scan timed out")
    except FileNotFoundError:
        log.error("[nmap] nmap not found. Install with: sudo apt install nmap")
        return NmapResult(success=False, target=domain, error="nmap not installed")
    except Exception as e:
        log.error(f"[nmap] Unexpected error: {e}")
        return NmapResult(success=False, target=domain, error=str(e))


def _parse_nmap_output(raw: str) -> List[OpenPort]:
    """Parse nmap -oN text output into OpenPort objects."""
    ports = []
    # Match lines like: 22/tcp   open  ssh     OpenSSH 8.9
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$",
        re.MULTILINE
    )
    for match in pattern.finditer(raw):
        port_num, proto, service, version = match.groups()
        ports.append(OpenPort(
            port=int(port_num),
            protocol=proto,
            state="open",
            service=service.strip(),
            version=(version or "").strip()
        ))
    return ports


def run_dnstwist(domain: str, output_dir: Path) -> DnstwistResult:
    """Run dnstwist to find typosquatting domains."""
    log.info(f"[dnstwist] Checking typosquats for {domain}...")
    outfile = output_dir / "typosquats.json"

    cmd = [
        settings.DNSTWIST_PATH,
        "--registered",         # only show registered domains
        "--format", "json",
        "--output", str(outfile),
        domain
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.DNSTWIST_TIMEOUT
        )

        if not outfile.exists():
            return DnstwistResult(success=False, target=domain, error="No output file generated")

        data = json.loads(outfile.read_text())
        typosquats = []

        for entry in data:
            # Skip the original domain entry
            if entry.get("fuzzer") == "*original":
                continue
            dns_a = entry.get("dns_a", [""])[0] if entry.get("dns_a") else ""
            t = TyposquatEntry(
                fuzzer=entry.get("fuzzer", "unknown"),
                domain=entry.get("domain", ""),
                dns_a=dns_a,
                dns_mx=str(entry.get("dns_mx", "")),
                registered=bool(dns_a)
            )
            typosquats.append(t)

        registered = [t for t in typosquats if t.registered]
        log.info(f"[dnstwist] {len(registered)} registered typosquats found")

        return DnstwistResult(
            success=True,
            target=domain,
            typosquats=typosquats,
            registered_count=len(registered)
        )

    except subprocess.TimeoutExpired:
        return DnstwistResult(success=False, target=domain, error="Scan timed out")
    except FileNotFoundError:
        log.error("[dnstwist] dnstwist not found. Install: pip install dnstwist")
        return DnstwistResult(success=False, target=domain, error="dnstwist not installed")
    except json.JSONDecodeError as e:
        log.error(f"[dnstwist] JSON parse error: {e}")
        return DnstwistResult(success=False, target=domain, error=f"Parse error: {e}")
    except Exception as e:
        log.error(f"[dnstwist] Error: {e}")
        return DnstwistResult(success=False, target=domain, error=str(e))


def run_theharvester(domain: str, output_dir: Path) -> HarvesterResult:
    """Run theHarvester for OSINT - emails, hosts, IPs."""
    log.info(f"[theHarvester] Harvesting OSINT for {domain}...")
    outfile = output_dir / "harvester"

    cmd = [
        settings.THEHARVESTER_PATH,
        "-d", domain,
        "-b", "crtsh,dnsdumpster,hackertarget,otx",  # free sources only
        "-l", "200",
        "-f", str(outfile)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.HARVESTER_TIMEOUT
        )

        output = result.stdout + result.stderr
        emails = _extract_emails(output)
        hosts = _extract_hosts(output, domain)
        ips = _extract_ips(output)

        # Also try to parse XML output if generated
        xml_file = Path(str(outfile) + ".xml")
        if xml_file.exists():
            emails, hosts, ips = _parse_harvester_xml(xml_file, emails, hosts, ips)

        log.info(f"[theHarvester] Found {len(emails)} emails, {len(hosts)} hosts")
        return HarvesterResult(
            success=True,
            target=domain,
            emails=list(set(emails)),
            hosts=list(set(hosts)),
            ips=list(set(ips))
        )

    except subprocess.TimeoutExpired:
        return HarvesterResult(success=False, target=domain, error="Scan timed out")
    except FileNotFoundError:
        log.error("[theHarvester] theHarvester not found")
        return HarvesterResult(success=False, target=domain, error="theHarvester not installed")
    except Exception as e:
        log.error(f"[theHarvester] Error: {e}")
        return HarvesterResult(success=False, target=domain, error=str(e))


def _extract_emails(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)


def _extract_hosts(text: str, domain: str) -> List[str]:
    pattern = re.compile(rf"[\w\-]+\.{re.escape(domain)}", re.IGNORECASE)
    return pattern.findall(text)


def _extract_ips(text: str) -> List[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _parse_harvester_xml(xml_file: Path, emails, hosts, ips):
    """Try to extract more data from theHarvester XML output."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for email in root.findall(".//email"):
            if email.text:
                emails.append(email.text.strip())
        for host in root.findall(".//host"):
            if host.text:
                hosts.append(host.text.strip())
        for ip in root.findall(".//ip"):
            if ip.text:
                ips.append(ip.text.strip())
    except Exception:
        pass
    return emails, hosts, ips
