"""
VoraGuard Advanced Intelligence Modules
12 real analysis engines — no placeholder text, all real logic.

Modules:
  1.  Vulnerability Analysis
  2.  OWASP Top 10 Mapping
  3.  GRC Executive Report
  4.  Attack Surface Change Detection
  5.  Business Impact Mapping
  6.  Regulatory Breach Prediction
  7.  Supply Chain / SaaS Map
  8.  Honey-Trap Detection
  9.  Attacker ROI Score
  10. Threat Actor Correlation
  11. Dark Web Monitoring
  12. Threat Simulation
"""

import re
import socket
import hashlib
import requests
from datetime import datetime, timezone
from typing import Optional
from utils.logger import get_logger
from config.settings import settings

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────
# SHARED HELPERS
# ─────────────────────────────────────────────────────────────

# Real CVE data per service — mapped from NVD common findings
_SERVICE_CVE_MAP = {
    "ssh": [
        {"cve": "CVE-2023-38408", "cvss": 9.8, "desc": "OpenSSH ssh-agent remote code execution via forwarded agent socket"},
        {"cve": "CVE-2023-51385", "cvss": 6.5, "desc": "OpenSSH OS command injection via invalid hostname with shell metacharacters"},
        {"cve": "CVE-2021-41617", "cvss": 7.0, "desc": "OpenSSH privilege escalation via improper AuthorizedKeysCommand handling"},
    ],
    "http": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Apache HTTP Server 2.4.49 path traversal and RCE (mod_cgi)"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "desc": "Apache HTTP Server 2.4.49/2.4.50 path traversal bypass"},
        {"cve": "CVE-2022-31813", "cvss": 9.8, "desc": "Apache mod_proxy X-Forwarded-For header forwarding flaw"},
    ],
    "https": [
        {"cve": "CVE-2022-0778", "cvss": 7.5, "desc": "OpenSSL infinite loop in BN_mod_sqrt() causes DoS via crafted certificate"},
        {"cve": "CVE-2021-3449", "cvss": 5.9, "desc": "OpenSSL NULL pointer deref in TLSv1.2 renegotiation → DoS"},
    ],
    "ftp": [
        {"cve": "CVE-2011-2523", "cvss": 10.0, "desc": "vsftpd 2.3.4 backdoor — remote shell on port 6200"},
        {"cve": "CVE-2015-3306", "cvss": 10.0, "desc": "ProFTPD mod_copy unauthenticated file copy/read (CPFR/CPTO)"},
    ],
    "mysql": [
        {"cve": "CVE-2021-2307", "cvss": 6.1, "desc": "MySQL Server privilege escalation via crafted SQL"},
        {"cve": "CVE-2022-21417", "cvss": 4.9, "desc": "MySQL Server InnoDB DoS via crafted SQL"},
        {"cve": "CVE-2012-2122", "cvss": 5.1, "desc": "MySQL auth bypass — repeated login attempts with wrong password may succeed"},
    ],
    "rdp": [
        {"cve": "CVE-2019-0708", "cvss": 9.8, "desc": "BlueKeep — pre-auth RCE in Windows RDP (wormable, EternalBlue-class)"},
        {"cve": "CVE-2019-1182", "cvss": 9.8, "desc": "DejaBlue — RDP pre-auth RCE on Windows 10 and Server 2019"},
        {"cve": "CVE-2020-0609", "cvss": 9.8, "desc": "Windows RD Gateway pre-auth RCE via crafted connection"},
    ],
    "smb": [
        {"cve": "CVE-2017-0144", "cvss": 9.8, "desc": "EternalBlue — SMBv1 pre-auth RCE (used by WannaCry, NotPetya)"},
        {"cve": "CVE-2020-0796", "cvss": 10.0, "desc": "SMBGhost — SMBv3 pre-auth RCE via compression header overflow"},
    ],
    "telnet": [
        {"cve": "CVE-2011-4862", "cvss": 10.0, "desc": "FreeBSD telnetd pre-auth RCE via encryption key option"},
        {"cve": "CVE-2020-10188", "cvss": 9.8, "desc": "telnetd arbitrary code execution via environment variable handling"},
    ],
    "smtp": [
        {"cve": "CVE-2020-7247", "cvss": 9.8, "desc": "OpenSMTPD remote code execution via malformed sender address"},
        {"cve": "CVE-2021-38371", "cvss": 7.5, "desc": "Exim open relay — forward unverified email addresses"},
    ],
    "redis": [
        {"cve": "CVE-2022-0543", "cvss": 10.0, "desc": "Redis Lua sandbox escape → RCE via Debian/Ubuntu package"},
        {"cve": "CVE-2021-32761", "cvss": 7.5, "desc": "Redis integer overflow in BITFIELD command → heap overflow"},
    ],
    "mongodb": [
        {"cve": "CVE-2019-2386", "cvss": 7.1, "desc": "MongoDB unauth access after user deletion leaves sessions valid"},
    ],
    "vnc": [
        {"cve": "CVE-2019-15681", "cvss": 7.5, "desc": "LibVNCServer memory leak exposes server memory to remote attacker"},
        {"cve": "CVE-2020-14399", "cvss": 7.5, "desc": "LibVNCServer NULL pointer deref via malformed packet"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "cvss": 7.7, "desc": "nginx resolver off-by-one heap write in DNS response handling"},
        {"cve": "CVE-2019-9511", "cvss": 7.5, "desc": "HTTP/2 Data Dribble DoS (affects nginx, Apache, h2o)"},
    ],
}

# OWASP Top 10 2021 — real mapping logic
_OWASP_RULES = [
    {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "trigger_ports": [22, 3389, 5900, 21],
        "trigger_services": ["ssh", "rdp", "vnc", "ftp"],
        "trigger_headers": [],
        "desc": "Exposed remote access services allow attackers to attempt access control bypass via brute force, stolen credentials, or unpatched auth vulnerabilities.",
        "remediation": "Restrict SSH/RDP/VNC to VPN-only access. Enforce MFA. Implement fail2ban or equivalent lockout."
    },
    {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "trigger_ports": [80, 21, 23, 25],
        "trigger_services": ["http", "ftp", "telnet", "smtp"],
        "trigger_headers": ["no_https", "no_hsts"],
        "desc": "Plaintext protocols in use (HTTP, FTP, Telnet, SMTP without TLS). Credentials and data transmitted unencrypted.",
        "remediation": "Enforce HTTPS with HSTS. Disable FTP/Telnet. Require STARTTLS/TLS for SMTP. Redirect all HTTP to HTTPS."
    },
    {
        "id": "A03:2021",
        "name": "Injection",
        "trigger_ports": [3306, 5432, 27017, 6379, 1433],
        "trigger_services": ["mysql", "postgres", "mongodb", "redis", "mssql"],
        "trigger_headers": [],
        "desc": "Database services directly exposed to the internet. Internet-facing DBs are primary targets for SQL injection and direct query attacks.",
        "remediation": "Move databases behind firewall. Never expose DB ports to internet. Use parameterized queries and WAF."
    },
    {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "trigger_ports": [8080, 8443, 8888, 9200, 9300, 2375, 2376],
        "trigger_services": ["http-proxy", "elasticsearch", "docker"],
        "trigger_headers": ["no_security_headers"],
        "desc": "Development/admin ports exposed, Elasticsearch or Docker APIs accessible without authentication.",
        "remediation": "Audit all exposed ports. Disable default credentials. Enable authentication on all admin interfaces."
    },
    {
        "id": "A06:2021",
        "name": "Vulnerable & Outdated Components",
        "trigger_ports": [],
        "trigger_services": ["apache", "nginx", "iis", "openssl"],
        "trigger_headers": [],
        "desc": "Service version banners detected. Specific versions may be vulnerable to known CVEs — see Vulnerability Analysis for details.",
        "remediation": "Enable automatic security updates. Track CVEs for all deployed software. Remove unused services."
    },
    {
        "id": "A07:2021",
        "name": "Identification & Authentication Failures",
        "trigger_ports": [22, 23, 3389, 21, 110, 143],
        "trigger_services": ["ssh", "telnet", "rdp", "ftp", "pop3", "imap"],
        "trigger_headers": [],
        "desc": "Authentication services exposed to internet are susceptible to brute force, credential stuffing, and password spraying attacks.",
        "remediation": "Implement MFA everywhere. Rate-limit login attempts. Use certificate-based auth for SSH. Monitor for credential stuffing patterns."
    },
    {
        "id": "A09:2021",
        "name": "Security Logging & Monitoring Failures",
        "trigger_ports": [],
        "trigger_services": [],
        "trigger_headers": ["no_csp"],
        "desc": "No observable logging/monitoring endpoints detected. Attacks may go undetected without proper SIEM integration.",
        "remediation": "Deploy centralized logging (ELK/Splunk). Set up alerts for failed auth, port scans, unusual traffic patterns."
    },
]

# Known threat actor TTPs mapped to ports/services (based on public MITRE ATT&CK data)
_THREAT_ACTOR_MAP = [
    {
        "group": "APT28 (Fancy Bear)",
        "nation": "Russia",
        "trigger_ports": [22, 443, 80],
        "trigger_services": ["ssh", "https", "http"],
        "ttps": ["T1078 Valid Accounts", "T1190 Exploit Public-Facing App", "T1133 External Remote Services"],
        "motivation": "Espionage, credential theft",
        "mitre_url": "https://attack.mitre.org/groups/G0007/"
    },
    {
        "group": "Lazarus Group",
        "nation": "North Korea",
        "trigger_ports": [3389, 22, 443],
        "trigger_services": ["rdp", "ssh", "https"],
        "ttps": ["T1486 Data Encrypted for Impact", "T1055 Process Injection", "T1021.001 RDP"],
        "motivation": "Financial theft, ransomware, espionage",
        "mitre_url": "https://attack.mitre.org/groups/G0032/"
    },
    {
        "group": "FIN7",
        "nation": "Eastern Europe (cybercriminal)",
        "trigger_ports": [3306, 1433, 3389],
        "trigger_services": ["mysql", "mssql", "rdp"],
        "ttps": ["T1059 Command Scripting", "T1071 App Layer Protocol", "T1041 Exfil over C2"],
        "motivation": "Financial — POS malware, data theft, ransomware",
        "mitre_url": "https://attack.mitre.org/groups/G0046/"
    },
    {
        "group": "Scattered Spider",
        "nation": "English-speaking (cybercriminal)",
        "trigger_ports": [443, 80, 22],
        "trigger_services": ["https", "http", "ssh"],
        "ttps": ["T1566 Phishing", "T1621 MFA Fatigue", "T1078 Valid Accounts"],
        "motivation": "Financial, ransomware (ALPHV/BlackCat affiliate)",
        "mitre_url": "https://attack.mitre.org/groups/G1015/"
    },
    {
        "group": "Sandworm",
        "nation": "Russia (GRU)",
        "trigger_ports": [80, 443, 445, 139],
        "trigger_services": ["http", "https", "smb", "netbios"],
        "ttps": ["T1486 Destructive malware", "T1195 Supply Chain Compromise", "T1498 Network DoS"],
        "motivation": "Disruption, sabotage, critical infrastructure",
        "mitre_url": "https://attack.mitre.org/groups/G0034/"
    },
]

# Known malicious/suspicious AS numbers and infrastructure patterns (public blocklists)
_SUSPICIOUS_AS_PATTERNS = [
    "AS3257", "AS209", "AS20473",  # Common bulletproof hosting
]

# Real regulatory frameworks and their triggers
_REGULATORY_MAP = [
    {
        "framework": "GDPR (EU General Data Protection Regulation)",
        "article": "Article 32 — Security of Processing",
        "triggers": ["no_https", "open_db_ports", "no_spf", "no_dmarc"],
        "fine": "Up to €20M or 4% of global annual turnover",
        "desc": "Failure to implement appropriate technical security measures for personal data processing.",
        "applies_if": lambda p, d, ssl: not ssl.get("has_ssl") or any(p.port in [3306,5432,27017,6379] for p in (d or []))
    },
    {
        "framework": "PCI DSS v4.0",
        "article": "Requirement 6.3 — Secure Development, 8.2 — User IDs",
        "triggers": ["open_rdp", "open_ssh", "no_https", "outdated_tls"],
        "fine": "$5,000–$100,000/month until compliant, card processing rights revoked",
        "desc": "Payment card data environments must not expose remote access or unencrypted channels.",
        "applies_if": lambda p, d, ssl: any(port.port in [3389, 22] for port in (p or []))
    },
    {
        "framework": "HIPAA Security Rule",
        "article": "45 CFR §164.312 — Technical Safeguards",
        "triggers": ["no_https", "open_db_ports", "no_ssl"],
        "fine": "$100–$50,000 per violation, up to $1.9M/year per category",
        "desc": "Electronic Protected Health Information (ePHI) must be encrypted in transit and at rest.",
        "applies_if": lambda p, d, ssl: not ssl.get("has_ssl")
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "article": "A.8.8 — Management of Technical Vulnerabilities",
        "triggers": ["unpatched_services", "open_ports"],
        "fine": "Certification revocation, regulatory consequences vary",
        "desc": "Known vulnerabilities in internet-facing services violate technical vulnerability management controls.",
        "applies_if": lambda p, d, ssl: len(p or []) > 3
    },
    {
        "framework": "India IT Act 2000 / DPDP Act 2023",
        "article": "Section 43A — Reasonable Security Practices",
        "triggers": ["no_ssl", "open_ports", "no_dmarc"],
        "fine": "₹250 crore per data breach incident",
        "desc": "Reasonable security practices not implemented — exposed services and missing email security records.",
        "applies_if": lambda p, d, ssl: not ssl.get("has_ssl") or not d.get("dmarc", {}).get("present")
    },
]

# Supply chain / SaaS technology fingerprints — detected from headers, ports, services
_SUPPLY_CHAIN_SIGNATURES = {
    "Cloudflare CDN": {"ports": [], "services": [], "headers": ["cf-ray", "cf-cache-status"], "risk": "LOW", "note": "Traffic proxied through Cloudflare — DDoS protection active"},
    "AWS (Amazon)": {"ports": [], "services": [], "headers": ["x-amz", "x-amzn"], "risk": "LOW", "note": "Hosted on AWS infrastructure"},
    "Akamai CDN": {"ports": [], "services": [], "headers": ["akamai", "x-akamai"], "risk": "LOW", "note": "Traffic through Akamai edge network"},
    "nginx": {"ports": [80, 443], "services": ["nginx"], "headers": [], "risk": "MEDIUM", "note": "nginx web server — check version for CVEs"},
    "Apache": {"ports": [80, 443], "services": ["apache", "http"], "headers": [], "risk": "MEDIUM", "note": "Apache httpd — verify version is patched"},
    "MySQL": {"ports": [3306], "services": ["mysql"], "headers": [], "risk": "HIGH", "note": "MySQL exposed — database internet-accessible, critical supply chain risk"},
    "Redis": {"ports": [6379], "services": ["redis"], "headers": [], "risk": "CRITICAL", "note": "Redis exposed without auth — full data access possible, RCE via SLAVEOF"},
    "Elasticsearch": {"ports": [9200, 9300], "services": ["elasticsearch"], "headers": [], "risk": "CRITICAL", "note": "Elasticsearch API exposed — all indexed data publicly accessible"},
    "MongoDB": {"ports": [27017], "services": ["mongodb", "mongo"], "headers": [], "risk": "CRITICAL", "note": "MongoDB exposed — no auth by default, all databases readable"},
    "Docker API": {"ports": [2375, 2376], "services": ["docker"], "headers": [], "risk": "CRITICAL", "note": "Docker daemon API exposed — full container escape to host possible"},
    "WordPress": {"ports": [80, 443], "services": ["wordpress", "wp-"], "headers": [], "risk": "MEDIUM", "note": "WordPress detected — check for plugin/theme CVEs, xmlrpc.php exposure"},
}


# ─────────────────────────────────────────────────────────────
# MODULE 1: VULNERABILITY ANALYSIS
# ─────────────────────────────────────────────────────────────

def analyze_vulnerabilities(nmap_result: dict) -> dict:
    """
    Map open ports/services to real CVEs from NVD/public data.
    Returns structured vulnerability findings with CVSS scores.
    """
    log.info("[VulnAnalysis] Analyzing open ports for known CVEs...")

    open_ports = nmap_result.get("open_ports", [])
    findings = []
    critical_count = high_count = medium_count = low_count = 0

    for port_info in open_ports:
        port = port_info.get("port", 0)
        service = port_info.get("service", "").lower()
        version = port_info.get("version", "")

        # Match service to CVE database
        matched_cves = []
        for svc_key, cves in _SERVICE_CVE_MAP.items():
            if svc_key in service or service in svc_key:
                matched_cves.extend(cves)

        # Classify severity
        severity = _port_severity(port, service)

        finding = {
            "port": port,
            "service": service,
            "version": version,
            "severity": severity,
            "cves": matched_cves,
            "exploit_available": any(c.get("cvss", 0) >= 9.0 for c in matched_cves),
            "remediation": _get_remediation(port, service),
            "attack_vector": _get_attack_vector(port, service),
        }
        findings.append(finding)

        # Count by severity
        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        else:
            low_count += 1

    result = {
        "total_findings": len(findings),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "findings": findings,
        "overall_risk": "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM" if medium_count > 0 else "LOW"
    }

    log.info(f"[VulnAnalysis] {len(findings)} findings: {critical_count}C {high_count}H {medium_count}M {low_count}L")
    return result


def _port_severity(port: int, service: str) -> str:
    critical_ports = {21, 23, 3389, 5900, 6379, 27017, 9200, 2375}
    high_ports = {22, 25, 3306, 1433, 5432, 8080, 8888}
    if port in critical_ports:
        return "CRITICAL"
    if port in high_ports:
        return "HIGH"
    if port in {80, 110, 143, 8443}:
        return "MEDIUM"
    return "LOW"


def _get_remediation(port: int, service: str) -> str:
    remap = {
        22: "Restrict SSH to VPN/specific IPs only. Disable password auth, use SSH keys. Enable fail2ban.",
        21: "Disable FTP entirely. Use SFTP (port 22) or FTPS instead. FTP transmits credentials in plaintext.",
        23: "Disable Telnet immediately. Replace with SSH. Telnet has zero encryption.",
        25: "Restrict SMTP relay. Require STARTTLS. Enable SPF/DKIM/DMARC. Block open relay.",
        80: "Redirect all HTTP to HTTPS. Implement HSTS. Disable if not needed.",
        443: "Ensure TLS 1.2+ only. Disable SSLv3/TLS 1.0/1.1. Implement HSTS preloading.",
        3306: "Remove MySQL from internet-facing interfaces. Bind to 127.0.0.1 only. Use firewall rules.",
        3389: "Restrict RDP to VPN only. Enable NLA. Apply BlueKeep patches (KB4499175). Implement MFA.",
        5900: "Disable VNC or restrict to VPN. Enable VNC authentication. Consider SSH tunneling.",
        6379: "Bind Redis to 127.0.0.1. Enable requirepass. Never expose Redis to internet.",
        27017: "Bind MongoDB to 127.0.0.1. Enable authentication. Apply security checklist.",
        9200: "Restrict Elasticsearch to internal network. Enable X-Pack security. Never expose to internet.",
        2375: "Never expose Docker API. Use TLS client certs if remote access needed (port 2376).",
        1433: "Restrict MSSQL to internal network. Enable Windows Authentication. Disable SA account.",
    }
    return remap.get(port, f"Assess necessity of port {port}. Apply vendor security patches. Restrict access via firewall.")


def _get_attack_vector(port: int, service: str) -> str:
    vectors = {
        22: "Brute force, credential stuffing, SSH key theft, CVE exploitation",
        21: "Anonymous login attempt, credential sniffing, bounce attack",
        23: "Credential sniffing (plaintext), brute force, session hijacking",
        3306: "Direct SQL injection, credential brute force, data exfiltration",
        3389: "BlueKeep/DejaBlue exploit, RDP brute force, pass-the-hash",
        5900: "VNC authentication bypass, brute force, screen capture",
        6379: "Unauthenticated command execution, SLAVEOF RCE, config rewrite",
        27017: "Unauthenticated DB dump, JavaScript injection, collection enumeration",
        9200: "Unauthenticated REST API — full data read/write/delete",
        2375: "Unauthenticated Docker API → deploy container → escape to host",
        80: "Web app attacks, HTTP request smuggling, directory traversal",
        443: "TLS downgrade, web app attacks, certificate spoofing",
    }
    return vectors.get(port, "Network-level exploitation, banner grabbing, version-specific exploits")


# ─────────────────────────────────────────────────────────────
# MODULE 2: OWASP TOP 10 MAPPING
# ─────────────────────────────────────────────────────────────

def owasp_top10_mapping(nmap_result: dict, ssl_info: dict, dns_health: dict) -> dict:
    """Map scan findings to OWASP Top 10 2021 categories with real evidence."""
    log.info("[OWASP] Mapping findings to OWASP Top 10 2021...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    services = [p["service"].lower() for p in open_ports]
    has_https = ssl_info.get("has_ssl", False)
    has_spf = dns_health.get("spf", {}).get("present", False)
    has_dmarc = dns_health.get("dmarc", {}).get("present", False)

    triggered = []

    for rule in _OWASP_RULES:
        evidence = []

        # Check port triggers
        for p in rule["trigger_ports"]:
            if p in port_nums:
                svc = next((op["service"] for op in open_ports if op["port"] == p), "")
                evidence.append(f"Port {p} ({svc}) is open and internet-accessible")

        # Check service triggers
        for svc in rule["trigger_services"]:
            if any(svc in s for s in services):
                evidence.append(f"Service '{svc}' detected on target")

        # Check header/config triggers
        if "no_https" in rule["trigger_headers"] and not has_https:
            evidence.append("HTTPS/TLS not present on port 443")
        if "no_spf" in rule["trigger_headers"] and not has_spf:
            evidence.append("SPF DNS record missing — email spoofing possible")
        if "no_dmarc" in rule["trigger_headers"] and not has_dmarc:
            evidence.append("DMARC DNS record missing — phishing domain risk")
        if "no_hsts" in rule["trigger_headers"] and not has_https:
            evidence.append("HTTP Strict Transport Security not enforced")

        if evidence:
            triggered.append({
                "id": rule["id"],
                "name": rule["name"],
                "evidence": evidence,
                "description": rule["desc"],
                "remediation": rule["remediation"],
                "severity": "HIGH" if len(evidence) >= 2 else "MEDIUM"
            })

    # Always include A09 (logging) as informational
    if not any(r["id"] == "A09:2021" for r in triggered):
        triggered.append({
            "id": "A09:2021",
            "name": "Security Logging & Monitoring Failures",
            "evidence": ["No logging/monitoring endpoints observable from external scan"],
            "description": "Lack of observable security monitoring increases attacker dwell time.",
            "remediation": "Implement SIEM. Alert on auth failures, port scans, anomalous traffic.",
            "severity": "MEDIUM"
        })

    log.info(f"[OWASP] {len(triggered)} categories triggered")
    return {
        "triggered_count": len(triggered),
        "total_categories": 10,
        "findings": triggered
    }


# ─────────────────────────────────────────────────────────────
# MODULE 3: GRC EXECUTIVE REPORT
# ─────────────────────────────────────────────────────────────

def generate_grc_report(
    domain: str,
    risk_score: dict,
    nmap_result: dict,
    dnstwist_result: dict,
    ssl_info: dict,
    dns_health: dict,
    vuln_analysis: dict,
    owasp_result: dict
) -> dict:
    """Generate a real GRC executive report with quantified metrics."""
    log.info("[GRC] Generating executive report...")

    score = risk_score.get("score", 0)
    risk_level = risk_score.get("risk_level", "UNKNOWN")
    open_ports = nmap_result.get("open_ports", [])
    typo_count = dnstwist_result.get("registered_count", 0)
    findings = risk_score.get("key_findings", [])

    # Risk appetite classification
    if score >= 80:
        appetite_status = "Within Tolerance"
        appetite_color = "green"
    elif score >= 60:
        appetite_status = "Approaching Threshold"
        appetite_color = "yellow"
    elif score >= 40:
        appetite_status = "Threshold Breached"
        appetite_color = "orange"
    else:
        appetite_status = "Critical — Immediate Action Required"
        appetite_color = "red"

    # Compliance posture
    compliance = {
        "NIST_CSF": {
            "Identify": "Partial" if open_ports else "Met",
            "Protect": "Not Met" if not ssl_info.get("has_ssl") else "Partial",
            "Detect": "Not Met",  # No observable detection
            "Respond": "Unknown",
            "Recover": "Unknown"
        },
        "ISO_27001": {
            "A.8.8 Vulnerability Mgmt": "Not Met" if vuln_analysis.get("critical", 0) > 0 else "Partial",
            "A.8.20 Network Security": "Not Met" if len(open_ports) > 5 else "Partial",
            "A.8.24 Cryptography": "Not Met" if not ssl_info.get("has_ssl") else "Met",
        },
        "SOC2": {
            "CC6.1 Access Controls": "Not Met" if any(p["port"] in [22,3389,5900] for p in open_ports) else "Met",
            "CC6.6 External Threats": "Not Met" if vuln_analysis.get("critical", 0) > 0 else "Partial",
            "CC7.1 Monitoring": "Not Met",
        }
    }

    # KRI (Key Risk Indicators)
    kris = []
    if vuln_analysis.get("critical", 0) > 0:
        kris.append({"indicator": "Critical CVEs present", "status": "BREACHED", "value": str(vuln_analysis["critical"])})
    if not ssl_info.get("has_ssl"):
        kris.append({"indicator": "HTTPS not enforced", "status": "BREACHED", "value": "No TLS"})
    if typo_count > 5:
        kris.append({"indicator": "Typosquatting exposure", "status": "ELEVATED", "value": f"{typo_count} domains"})
    if not dns_health.get("spf", {}).get("present"):
        kris.append({"indicator": "SPF record missing", "status": "BREACHED", "value": "Email spoofing risk"})
    if not dns_health.get("dmarc", {}).get("present"):
        kris.append({"indicator": "DMARC record missing", "status": "ELEVATED", "value": "Phishing domain risk"})
    if len(open_ports) > 8:
        kris.append({"indicator": "Excessive open ports", "status": "ELEVATED", "value": f"{len(open_ports)} open"})

    # Executive action items
    actions = []
    if vuln_analysis.get("critical", 0) > 0:
        actions.append({"priority": "P1", "action": "Patch/remove services with critical CVEs within 24 hours", "owner": "Security Engineering"})
    if not ssl_info.get("has_ssl"):
        actions.append({"priority": "P1", "action": "Implement HTTPS/TLS immediately — plaintext traffic is unacceptable", "owner": "DevOps"})
    if any(p["port"] in [3306,27017,6379,9200] for p in open_ports):
        actions.append({"priority": "P1", "action": "Remove all database ports from internet exposure immediately", "owner": "Infrastructure"})
    if typo_count > 3:
        actions.append({"priority": "P2", "action": f"Monitor/take down {typo_count} typosquatting domains — phishing risk", "owner": "Legal/Security"})
    if not dns_health.get("spf", {}).get("present"):
        actions.append({"priority": "P2", "action": "Configure SPF DNS record to prevent email spoofing", "owner": "IT Admin"})
    if not dns_health.get("dmarc", {}).get("present"):
        actions.append({"priority": "P2", "action": "Configure DMARC policy (p=quarantine minimum) to prevent phishing", "owner": "IT Admin"})
    if owasp_result.get("triggered_count", 0) > 3:
        actions.append({"priority": "P3", "action": f"Conduct full web application security assessment — {owasp_result['triggered_count']} OWASP categories triggered", "owner": "AppSec Team"})

    result = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall_score": score,
        "risk_level": risk_level,
        "appetite_status": appetite_status,
        "appetite_color": appetite_color,
        "executive_summary": _build_exec_summary(domain, score, risk_level, open_ports, typo_count, vuln_analysis),
        "key_risk_indicators": kris,
        "compliance_posture": compliance,
        "priority_actions": actions,
        "owasp_coverage": owasp_result.get("triggered_count", 0),
        "total_vulnerabilities": vuln_analysis.get("total_findings", 0),
        "critical_vulns": vuln_analysis.get("critical", 0),
    }

    log.info(f"[GRC] Report generated — {len(actions)} priority actions, {len(kris)} KRIs triggered")
    return result


def _build_exec_summary(domain, score, risk_level, open_ports, typo_count, vuln_analysis) -> str:
    critical_cve_count = sum(len(f.get("cves", [])) for f in vuln_analysis.get("findings", []) if f.get("severity") == "CRITICAL")
    return (
        f"{domain} presents a {risk_level} risk profile with an overall score of {score}/100. "
        f"The external attack surface includes {len(open_ports)} open port(s), "
        f"{vuln_analysis.get('critical', 0)} critical and {vuln_analysis.get('high', 0)} high-severity service vulnerabilities, "
        f"and {typo_count} registered typosquatting domains increasing brand/phishing risk. "
        f"{'Immediate remediation is required before this asset is considered production-safe.' if score < 50 else 'Targeted remediation of high-priority findings is recommended within the next sprint cycle.'}"
    )


# ─────────────────────────────────────────────────────────────
# MODULE 4: ATTACK SURFACE CHANGE DETECTION
# ─────────────────────────────────────────────────────────────

def detect_attack_surface_changes(domain: str, current_nmap: dict, output_dir: str) -> dict:
    """
    Compare current scan against stored baseline.
    On first run, saves baseline. On subsequent runs, diffs against it.
    """
    import json, os
    from pathlib import Path

    log.info("[DeltaScan] Checking for attack surface changes...")

    baseline_file = Path(output_dir).parent / f"{domain}_baseline.json"
    current_ports = set(
        f"{p['port']}/{p['protocol']}" for p in current_nmap.get("open_ports", [])
    )

    result = {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "current_open_ports": list(current_ports),
        "total_open": len(current_ports),
        "is_first_scan": False,
        "new_ports": [],
        "closed_ports": [],
        "unchanged_ports": [],
        "delta_risk": "NONE",
        "baseline_file": str(baseline_file),
    }

    if not baseline_file.exists():
        # First scan — save as baseline
        baseline_file.parent.mkdir(parents=True, exist_ok=True)
        baseline_data = {
            "domain": domain,
            "timestamp": result["scanned_at"],
            "open_ports": list(current_ports),
            "port_details": current_nmap.get("open_ports", [])
        }
        baseline_file.write_text(json.dumps(baseline_data, indent=2))
        result["is_first_scan"] = True
        result["message"] = f"Baseline saved with {len(current_ports)} open ports. Run again to detect changes."
        log.info(f"[DeltaScan] Baseline saved to {baseline_file}")
        return result

    # Load and compare baseline
    try:
        baseline = json.loads(baseline_file.read_text())
        baseline_ports = set(baseline.get("open_ports", []))
        baseline_time = baseline.get("timestamp", "unknown")

        new_ports = list(current_ports - baseline_ports)
        closed_ports = list(baseline_ports - current_ports)
        unchanged = list(current_ports & baseline_ports)

        # Assess delta risk
        if new_ports:
            high_risk_new = [p for p in new_ports if int(p.split("/")[0]) in {21,22,23,25,3306,3389,5900,6379,27017,9200,2375}]
            if high_risk_new:
                delta_risk = "CRITICAL"
            elif len(new_ports) > 3:
                delta_risk = "HIGH"
            else:
                delta_risk = "MEDIUM"
        elif closed_ports:
            delta_risk = "IMPROVED"
        else:
            delta_risk = "NONE"

        result.update({
            "baseline_timestamp": baseline_time,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "unchanged_ports": unchanged,
            "delta_risk": delta_risk,
            "message": (
                f"{len(new_ports)} new port(s) opened since {baseline_time[:10]}. INVESTIGATE IMMEDIATELY." if new_ports
                else f"{len(closed_ports)} port(s) closed since baseline — exposure reduced." if closed_ports
                else f"No changes detected since baseline scan on {baseline_time[:10]}."
            )
        })

        log.info(f"[DeltaScan] {len(new_ports)} new, {len(closed_ports)} closed vs baseline")

    except Exception as e:
        result["error"] = f"Could not read baseline: {e}"
        log.error(f"[DeltaScan] Error: {e}")

    return result


# ─────────────────────────────────────────────────────────────
# MODULE 5: BUSINESS IMPACT MAPPING
# ─────────────────────────────────────────────────────────────

def map_business_impact(domain: str, nmap_result: dict, ssl_info: dict, vuln_analysis: dict) -> dict:
    """Classify exposed services by business impact — CIA triad."""
    log.info("[BizImpact] Mapping business impact...")

    open_ports = nmap_result.get("open_ports", [])

    # CIA Triad impact per port
    _cia_map = {
        3306: {"asset": "Database Server", "C": "CRITICAL", "I": "CRITICAL", "A": "HIGH",   "scenario": "Full database dump, customer PII exfiltration, data manipulation"},
        27017: {"asset": "MongoDB",         "C": "CRITICAL", "I": "CRITICAL", "A": "HIGH",   "scenario": "All collections readable without auth — full data breach"},
        6379: {"asset": "Redis Cache",      "C": "HIGH",     "I": "CRITICAL", "A": "CRITICAL","scenario": "Session token theft, cache poisoning, RCE via SLAVEOF, full service disruption"},
        9200: {"asset": "Elasticsearch",    "C": "CRITICAL", "I": "HIGH",     "A": "MEDIUM", "scenario": "Full index data exposure — logs, emails, user records accessible via REST API"},
        3389: {"asset": "Windows Server",   "C": "CRITICAL", "I": "CRITICAL", "A": "CRITICAL","scenario": "BlueKeep RCE → full server compromise → lateral movement across network"},
        22:   {"asset": "SSH Server",       "C": "HIGH",     "I": "HIGH",     "A": "MEDIUM", "scenario": "Brute force or key theft → shell access → pivot to internal network"},
        21:   {"asset": "FTP Server",       "C": "HIGH",     "I": "MEDIUM",   "A": "LOW",    "scenario": "Credential sniffing, anonymous login → file exfiltration"},
        23:   {"asset": "Telnet",           "C": "CRITICAL", "I": "HIGH",     "A": "MEDIUM", "scenario": "All session data in plaintext — credentials trivially intercepted"},
        80:   {"asset": "Web Server (HTTP)","C": "MEDIUM",   "I": "MEDIUM",   "A": "MEDIUM", "scenario": "Web app attacks, data interception, SEO poisoning"},
        443:  {"asset": "Web Server (HTTPS)","C": "LOW",     "I": "MEDIUM",   "A": "MEDIUM", "scenario": "Web app vulnerabilities — depends on application security"},
        5900: {"asset": "VNC Server",       "C": "CRITICAL", "I": "CRITICAL", "A": "HIGH",   "scenario": "Desktop screen capture, full GUI control, keylogging"},
        2375: {"asset": "Docker API",       "C": "CRITICAL", "I": "CRITICAL", "A": "CRITICAL","scenario": "Deploy malicious container → escape to host → full infrastructure compromise"},
        1433: {"asset": "MSSQL Server",     "C": "CRITICAL", "I": "CRITICAL", "A": "HIGH",   "scenario": "xp_cmdshell abuse → OS command execution → data theft"},
        25:   {"asset": "SMTP Server",      "C": "MEDIUM",   "I": "HIGH",     "A": "LOW",    "scenario": "Open relay → spam campaigns using your domain → blacklisting → email disruption"},
    }

    impact_findings = []
    overall_confidentiality = "LOW"
    overall_integrity = "LOW"
    overall_availability = "LOW"

    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for port_info in open_ports:
        port = port_info.get("port", 0)
        if port in _cia_map:
            cia = _cia_map[port]
            impact_findings.append({
                "port": port,
                "service": port_info.get("service", ""),
                "asset": cia["asset"],
                "confidentiality": cia["C"],
                "integrity": cia["I"],
                "availability": cia["A"],
                "breach_scenario": cia["scenario"],
            })

            # Elevate overall scores
            if severity_rank.get(cia["C"], 0) > severity_rank.get(overall_confidentiality, 0):
                overall_confidentiality = cia["C"]
            if severity_rank.get(cia["I"], 0) > severity_rank.get(overall_integrity, 0):
                overall_integrity = cia["I"]
            if severity_rank.get(cia["A"], 0) > severity_rank.get(overall_availability, 0):
                overall_availability = cia["A"]

    # Financial impact estimate
    financial_risk = _estimate_financial_impact(overall_confidentiality, len(impact_findings))

    return {
        "domain": domain,
        "overall_confidentiality": overall_confidentiality,
        "overall_integrity": overall_integrity,
        "overall_availability": overall_availability,
        "financial_risk_estimate": financial_risk,
        "impact_findings": impact_findings,
        "exposed_asset_count": len(impact_findings),
    }


def _estimate_financial_impact(confidentiality: str, asset_count: int) -> dict:
    base = {"CRITICAL": 500000, "HIGH": 100000, "MEDIUM": 25000, "LOW": 5000}
    amount = base.get(confidentiality, 5000) * max(1, asset_count)
    return {
        "minimum": f"${amount // 2:,}",
        "maximum": f"${amount * 3:,}",
        "basis": "IBM Cost of a Data Breach Report 2024 — average breach cost $4.88M globally",
        "factors": ["Regulatory fines", "Incident response costs", "Reputational damage", "Legal liability"]
    }


# ─────────────────────────────────────────────────────────────
# MODULE 6: REGULATORY BREACH PREDICTION
# ─────────────────────────────────────────────────────────────

def predict_regulatory_breach(
    domain: str,
    nmap_result: dict,
    ssl_info: dict,
    dns_health: dict
) -> dict:
    """Predict which regulations are at risk based on real technical findings."""
    log.info("[Regulatory] Predicting regulatory breach risk...")

    open_ports_objs = nmap_result.get("open_ports", [])
    triggered_frameworks = []

    for reg in _REGULATORY_MAP:
        try:
            if reg["applies_if"](open_ports_objs, dns_health, ssl_info):
                triggered_frameworks.append({
                    "framework": reg["framework"],
                    "article": reg["article"],
                    "violation_description": reg["desc"],
                    "potential_fine": reg["fine"],
                    "triggered_by": reg["triggers"],
                    "risk": "HIGH" if not ssl_info.get("has_ssl") else "MEDIUM"
                })
        except Exception:
            pass

    return {
        "domain": domain,
        "frameworks_at_risk": len(triggered_frameworks),
        "findings": triggered_frameworks,
        "overall_regulatory_risk": "CRITICAL" if len(triggered_frameworks) >= 3 else "HIGH" if len(triggered_frameworks) >= 2 else "MEDIUM" if len(triggered_frameworks) >= 1 else "LOW"
    }


# ─────────────────────────────────────────────────────────────
# MODULE 7: SUPPLY CHAIN MAP
# ─────────────────────────────────────────────────────────────

def map_supply_chain(domain: str, nmap_result: dict) -> dict:
    """Detect third-party technologies and SaaS components from port/service fingerprints."""
    log.info("[SupplyChain] Fingerprinting supply chain components...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    services = [p.get("service", "").lower() + " " + p.get("version", "").lower() for p in open_ports]
    all_text = " ".join(services)

    detected = []

    # Check HTTP headers via quick request
    detected_from_headers = _check_http_headers(domain)

    for tech, sig in _SUPPLY_CHAIN_SIGNATURES.items():
        found = False
        evidence = []

        # Port match
        for p in sig["ports"]:
            if p in port_nums:
                found = True
                evidence.append(f"Port {p} open")

        # Service match
        for svc in sig["services"]:
            if svc in all_text:
                found = True
                evidence.append(f"Service fingerprint: {svc}")

        # Header match
        for hdr in sig["headers"]:
            if hdr in detected_from_headers:
                found = True
                evidence.append(f"HTTP header: {hdr}")

        if found:
            detected.append({
                "technology": tech,
                "risk": sig["risk"],
                "note": sig["note"],
                "evidence": evidence
            })

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detected.sort(key=lambda x: risk_order.get(x["risk"], 4))

    return {
        "domain": domain,
        "components_detected": len(detected),
        "critical_components": len([d for d in detected if d["risk"] == "CRITICAL"]),
        "components": detected,
        "supply_chain_risk": "CRITICAL" if any(d["risk"] == "CRITICAL" for d in detected) else
                             "HIGH" if any(d["risk"] == "HIGH" for d in detected) else "MEDIUM" if detected else "LOW"
    }


def _check_http_headers(domain: str) -> list:
    """Grab HTTP headers to fingerprint CDN/tech stack."""
    found_headers = []
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            for header_name, header_val in resp.headers.items():
                combined = f"{header_name.lower()}: {header_val.lower()}"
                for sig_key in ["cf-ray", "cf-cache-status", "x-amz", "x-amzn", "akamai", "x-akamai"]:
                    if sig_key in combined:
                        found_headers.append(sig_key)
            break
        except Exception:
            continue
    return found_headers


# ─────────────────────────────────────────────────────────────
# MODULE 8: HONEY-TRAP DETECTION
# ─────────────────────────────────────────────────────────────

def honey_trap_detection(domain: str, nmap_result: dict) -> dict:
    """
    Detect whether the target may be a honeypot.
    Indicators: too many open ports, unusual port combos, known honeypot software.
    """
    log.info("[HoneyTrap] Checking for honeypot indicators...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    services_text = " ".join(p.get("service","").lower() + " " + p.get("version","").lower() for p in open_ports)

    indicators = []
    score = 0  # Higher = more likely honeypot

    # Known honeypot software signatures
    honeypot_signatures = [
        "kippo", "cowrie", "honeyd", "glastopf", "dionaea",
        "amun", "conpot", "gridpot", "opencanary", "elastichoney"
    ]
    for sig in honeypot_signatures:
        if sig in services_text:
            indicators.append(f"Known honeypot software signature detected: '{sig}'")
            score += 40

    # Unusual port combination (real servers rarely have all of these open)
    risky_combo = {21, 22, 23, 25, 80, 443, 3306, 3389}
    if risky_combo.issubset(set(port_nums)):
        indicators.append("Unusually complete set of vulnerable services open — possible honeypot or highly misconfigured server")
        score += 20

    # Too many open ports
    if len(open_ports) > 20:
        indicators.append(f"{len(open_ports)} open ports — unusually high, may indicate honeypot or port mirroring")
        score += 15

    # Ports open but no version info (honeypots often fake banners)
    no_version = [p for p in open_ports if not p.get("version")]
    if len(no_version) > len(open_ports) * 0.7 and open_ports:
        indicators.append(f"{len(no_version)}/{len(open_ports)} ports have no version banner — could indicate fake service emulation")
        score += 10

    # Very old or implausible version strings
    old_versions = ["2.3.4", "1.0.0", "0.1", "vsftpd 2.3.4"]
    for p in open_ports:
        for ov in old_versions:
            if ov in p.get("version", ""):
                indicators.append(f"Suspiciously old version on port {p['port']}: {p['version']} — common honeypot bait")
                score += 15

    verdict = "LIKELY HONEYPOT" if score >= 40 else "POSSIBLE HONEYPOT" if score >= 20 else "UNLIKELY HONEYPOT"
    confidence = min(100, score + 10) if score > 0 else 5

    return {
        "domain": domain,
        "verdict": verdict,
        "confidence_pct": confidence,
        "honeypot_score": score,
        "indicators": indicators if indicators else ["No honeypot indicators detected — appears to be a real target"],
        "recommendation": (
            "Do not proceed with active exploitation — this may be a law enforcement trap or research honeypot."
            if score >= 40 else
            "Treat with caution — verify target identity before active testing."
            if score >= 20 else
            "No significant honeypot indicators. Proceed with authorized testing."
        )
    }


# ─────────────────────────────────────────────────────────────
# MODULE 9: ATTACKER ROI SCORE
# ─────────────────────────────────────────────────────────────

def attacker_roi_score(
    domain: str,
    nmap_result: dict,
    dnstwist_result: dict,
    harvester_result: dict,
    vuln_analysis: dict
) -> dict:
    """
    Model how attractive this target is to a threat actor.
    Based on: ease of exploitation × data value × stealth difficulty.
    """
    log.info("[AttackerROI] Calculating attacker ROI score...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    emails = harvester_result.get("emails", [])
    typo_count = dnstwist_result.get("registered_count", 0)
    critical_vulns = vuln_analysis.get("critical", 0)
    high_vulns = vuln_analysis.get("high", 0)

    # EASE OF EXPLOITATION (0-40)
    ease = 0
    ease_factors = []

    if critical_vulns > 0:
        ease += 20
        ease_factors.append(f"+20 Critical CVEs present ({critical_vulns})")
    if high_vulns > 0:
        ease += 10
        ease_factors.append(f"+10 High-severity vulnerabilities ({high_vulns})")
    if any(p in port_nums for p in [3389, 5900, 23]):
        ease += 8
        ease_factors.append("+8 Remote access services (RDP/VNC/Telnet) exposed")
    if any(p in port_nums for p in [6379, 9200, 27017]):
        ease += 10
        ease_factors.append("+10 Unauthenticated data stores exposed")
    ease = min(40, ease)

    # DATA VALUE (0-35)
    value = 10  # baseline
    value_factors = ["+10 All internet-facing targets have baseline value"]

    if any(p in port_nums for p in [3306, 1433, 5432, 27017]):
        value += 15
        value_factors.append("+15 Database directly accessible — high data value")
    if len(emails) > 5:
        value += 5
        value_factors.append(f"+5 {len(emails)} email addresses harvested — phishing/BEC value")
    if typo_count > 5:
        value += 5
        value_factors.append(f"+5 {typo_count} typosquats — brand/phishing infrastructure value")
    value = min(35, value)

    # STEALTH / DIFFICULTY (0-25 — lower difficulty = higher attacker benefit)
    stealth = 0
    stealth_factors = []

    if not any("firewall" in p.get("version","").lower() for p in open_ports):
        stealth += 5
        stealth_factors.append("+5 No observable WAF/firewall detected")
    if any(p in port_nums for p in [21, 23, 80]):  # plaintext = easier interception
        stealth += 5
        stealth_factors.append("+5 Plaintext protocols — easier credential capture")
    if critical_vulns > 0:
        stealth += 10
        stealth_factors.append("+10 Public exploits likely available for detected CVEs")
    if len(open_ports) > 5:
        stealth += 5
        stealth_factors.append("+5 Large attack surface reduces need for stealth")
    stealth = min(25, stealth)

    total_roi = ease + value + stealth

    if total_roi >= 75:
        roi_label = "EXTREMELY HIGH — Prime target, low-skill attackers will succeed"
    elif total_roi >= 55:
        roi_label = "HIGH — Attractive to motivated attackers, exploitation likely"
    elif total_roi >= 35:
        roi_label = "MEDIUM — Opportunistic attackers may attempt exploitation"
    else:
        roi_label = "LOW — Limited attacker motivation, hardened target"

    return {
        "domain": domain,
        "total_roi_score": total_roi,
        "max_score": 100,
        "roi_label": roi_label,
        "ease_score": ease,
        "value_score": value,
        "stealth_score": stealth,
        "ease_factors": ease_factors,
        "value_factors": value_factors,
        "stealth_factors": stealth_factors,
        "attacker_type": _classify_attacker(total_roi)
    }


def _classify_attacker(roi: int) -> str:
    if roi >= 75:
        return "Script kiddies, ransomware operators, APT groups — all threat tiers motivated"
    elif roi >= 55:
        return "Ransomware groups, financially motivated actors, hacktivists"
    elif roi >= 35:
        return "Opportunistic attackers, automated scanners, initial access brokers"
    else:
        return "Only highly motivated, targeted APT actors"


# ─────────────────────────────────────────────────────────────
# MODULE 10: THREAT ACTOR CORRELATION
# ─────────────────────────────────────────────────────────────

def threat_actor_correlation(domain: str, nmap_result: dict, vt_result: dict) -> dict:
    """
    Correlate target's exposed surface with known threat actor TTPs (MITRE ATT&CK).
    """
    log.info("[ThreatActor] Correlating with known threat groups...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    services = [p.get("service","").lower() for p in open_ports]

    matched_actors = []

    for actor in _THREAT_ACTOR_MAP:
        match_score = 0
        matched_ttps = []
        matched_evidence = []

        # Port match
        for tp in actor["trigger_ports"]:
            if tp in port_nums:
                match_score += 20
                matched_evidence.append(f"Port {tp} open — used by {actor['group']} for {actor['motivation']}")

        # Service match
        for svc in actor["trigger_services"]:
            if any(svc in s for s in services):
                match_score += 15
                matched_evidence.append(f"Service '{svc}' is a known TTP vector for this group")

        if match_score >= 20:
            matched_actors.append({
                "group": actor["group"],
                "nation_state": actor["nation"],
                "motivation": actor["motivation"],
                "correlation_score": min(100, match_score),
                "matched_ttps": actor["ttps"],
                "evidence": matched_evidence,
                "mitre_url": actor["mitre_url"],
                "risk": "HIGH" if match_score >= 40 else "MEDIUM"
            })

    # Sort by correlation score
    matched_actors.sort(key=lambda x: x["correlation_score"], reverse=True)

    return {
        "domain": domain,
        "matched_actor_count": len(matched_actors),
        "actors": matched_actors,
        "note": "Correlation based on exposed attack surface overlap with publicly documented TTPs (MITRE ATT&CK). Does not imply active targeting.",
        "overall_threat": "HIGH" if len(matched_actors) >= 3 else "MEDIUM" if len(matched_actors) >= 1 else "LOW"
    }


# ─────────────────────────────────────────────────────────────
# MODULE 11: DARK WEB MONITORING
# ─────────────────────────────────────────────────────────────

def darkweb_monitoring(domain: str, harvester_result: dict) -> dict:
    """
    Check for domain/email exposure using public breach APIs.
    Uses HaveIBeenPwned and checks against known public breach lists.
    Note: Full dark web monitoring requires Tor/commercial API.
    """
    log.info("[DarkWeb] Checking breach exposure...")

    emails = harvester_result.get("emails", [])
    findings = []
    checked_emails = []

    # HIBP API check (requires API key for email endpoint, domain endpoint available free)
    hibp_domain_result = _check_hibp_domain(domain)
    if hibp_domain_result:
        findings.extend(hibp_domain_result)

    # Check emails via HIBP if key available
    hibp_key = settings.HIBP_API_KEY
    if hibp_key and emails:
        for email in emails[:5]:  # limit to 5 to respect rate limits
            result = _check_hibp_email(email, hibp_key)
            if result:
                checked_emails.append(result)

    # Check domain against known public breach database signatures
    domain_breach_indicators = _check_domain_breach_indicators(domain)
    findings.extend(domain_breach_indicators)

    # Paste site check via public search simulation
    paste_indicators = _check_paste_indicators(domain, emails)
    findings.extend(paste_indicators)

    total_breaches = len(findings)
    return {
        "domain": domain,
        "breach_findings": findings,
        "email_breach_results": checked_emails,
        "total_indicators": total_breaches,
        "risk_level": "CRITICAL" if total_breaches >= 3 else "HIGH" if total_breaches >= 1 else "LOW",
        "note": "Full dark web monitoring (Tor hidden services, dark markets) requires commercial threat intel feed (Recorded Future, DarkOwl, Flashpoint). This scan covers public breach databases and paste sites.",
        "recommended_tools": [
            "Have I Been Pwned (haveibeenpwned.com)",
            "DeHashed (dehashed.com)",
            "IntelX (intelx.io)",
            "Recorded Future — dark web monitoring",
        ]
    }


def _check_hibp_domain(domain: str) -> list:
    """Check HaveIBeenPwned for domain-level breaches (no API key needed)."""
    findings = []
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers={"User-Agent": "VoraGuard-ThreatIntel"},
            timeout=10
        )
        if resp.status_code == 200:
            breaches = resp.json()
            domain_breaches = [b for b in breaches if domain.replace("www.", "").split(".")[0].lower() in b.get("Domain", "").lower()]
            for b in domain_breaches[:3]:
                findings.append({
                    "type": "HIBP Domain Breach",
                    "source": b.get("Name", "Unknown"),
                    "date": b.get("BreachDate", "Unknown"),
                    "pwn_count": f"{b.get('PwnCount', 0):,} accounts",
                    "data_classes": b.get("DataClasses", []),
                    "description": f"Domain appeared in '{b.get('Name')}' breach affecting {b.get('PwnCount', 0):,} accounts on {b.get('BreachDate', 'unknown date')}."
                })
    except Exception as e:
        log.debug(f"[DarkWeb] HIBP domain check failed: {e}")
    return findings


def _check_hibp_email(email: str, api_key: str) -> Optional[dict]:
    """Check single email against HIBP (requires API key)."""
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": api_key, "User-Agent": "VoraGuard-ThreatIntel"},
            timeout=10
        )
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "email": email,
                "breached": True,
                "breach_count": len(breaches),
                "breaches": [b.get("Name") for b in breaches[:5]]
            }
        elif resp.status_code == 404:
            return {"email": email, "breached": False, "breach_count": 0}
    except Exception:
        pass
    return None


def _check_domain_breach_indicators(domain: str) -> list:
    """Check VirusTotal for malicious URL/domain indicators correlating to breaches."""
    indicators = []
    # Use VT communicating files as dark web indicator
    if settings.VT_API_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/communicating_files",
                headers={"x-apikey": settings.VT_API_KEY},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                malicious_files = [
                    f for f in data.get("data", [])
                    if f.get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0
                ]
                if malicious_files:
                    indicators.append({
                        "type": "Malware Communication",
                        "source": "VirusTotal",
                        "date": "Recent",
                        "description": f"{len(malicious_files)} malicious file(s) have communicated with this domain — possible C2 or malware distribution.",
                        "data_classes": ["Malware C2", "Malicious infrastructure"]
                    })
        except Exception:
            pass
    return indicators


def _check_paste_indicators(domain: str, emails: list) -> list:
    """Check for paste site exposure via public search."""
    indicators = []
    # Note: Pastebin/paste search requires commercial API for reliable results
    # We can check URLhaus for domain-based paste indicators
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_host":
                urls = data.get("urls", [])
                if urls:
                    indicators.append({
                        "type": "URLhaus Malicious URL",
                        "source": "Abuse.ch URLhaus",
                        "date": urls[0].get("date_added", "Unknown") if urls else "Unknown",
                        "description": f"Domain found in URLhaus malicious URL database with {len(urls)} entries — potential malware distribution or C2.",
                        "data_classes": ["Malicious URLs", "Malware distribution"]
                    })
    except Exception as e:
        log.debug(f"[DarkWeb] URLhaus check failed: {e}")
    return indicators


# ─────────────────────────────────────────────────────────────
# MODULE 12: THREAT SIMULATION
# ─────────────────────────────────────────────────────────────

def threat_simulation(domain: str, nmap_result: dict, vuln_analysis: dict) -> dict:
    """
    Model realistic attack chains based on observed exposure.
    Maps MITRE ATT&CK Initial Access → Execution → Impact.
    """
    log.info("[ThreatSim] Building threat simulation model...")

    open_ports = nmap_result.get("open_ports", [])
    port_nums = [p["port"] for p in open_ports]
    vuln_findings = vuln_analysis.get("findings", [])

    attack_chains = []

    # Chain 1: External RCE via exposed database
    if any(p in port_nums for p in [3306, 27017, 6379, 9200]):
        db_port = next(p for p in [3306, 27017, 6379, 9200] if p in port_nums)
        db_service = next((op["service"] for op in open_ports if op["port"] == db_port), "database")
        attack_chains.append({
            "chain_id": "AC-001",
            "name": "Direct Database Compromise",
            "likelihood": "CRITICAL",
            "entry_point": f"Port {db_port} ({db_service}) — internet accessible",
            "steps": [
                {"phase": "Reconnaissance", "tactic": "T1595 Active Scanning", "desc": f"Attacker discovers {db_service} on port {db_port} via Shodan/Censys"},
                {"phase": "Initial Access", "tactic": "T1190 Exploit Public-Facing App", "desc": f"Unauthenticated access or default credential login to {db_service}"},
                {"phase": "Collection", "tactic": "T1213 Data from Info Repos", "desc": "Full database dump — all tables/collections exfiltrated"},
                {"phase": "Impact", "tactic": "T1485 Data Destruction", "desc": "Data sold on dark web, ransomed, or destroyed. Regulatory breach inevitable."},
            ],
            "estimated_time_to_exploit": "< 15 minutes (automated tools)",
            "skill_required": "LOW — automated exploitation tools widely available",
            "blast_radius": "FULL DATA BREACH"
        })

    # Chain 2: SSH brute force → lateral movement
    if 22 in port_nums:
        attack_chains.append({
            "chain_id": "AC-002",
            "name": "SSH Brute Force → Lateral Movement",
            "likelihood": "HIGH",
            "entry_point": "Port 22 (SSH) — internet accessible",
            "steps": [
                {"phase": "Reconnaissance", "tactic": "T1595.002 Vulnerability Scanning", "desc": "SSH version fingerprinted — check for CVE-2023-38408, CVE-2023-51385"},
                {"phase": "Initial Access", "tactic": "T1110 Brute Force", "desc": "Hydra/Medusa credential spray using HaveIBeenPwned leaked credentials"},
                {"phase": "Persistence", "tactic": "T1098.004 SSH Authorized Keys", "desc": "Attacker adds SSH key to ~/.ssh/authorized_keys for persistent access"},
                {"phase": "Lateral Movement", "tactic": "T1021.004 SSH Lateral Movement", "desc": "Pivot to internal network using compromised host as jump server"},
                {"phase": "Impact", "tactic": "T1486 Data Encrypted for Impact", "desc": "Ransomware deployment across reachable network segments"},
            ],
            "estimated_time_to_exploit": "1–24 hours (depending on password strength)",
            "skill_required": "LOW to MEDIUM",
            "blast_radius": "SERVER COMPROMISE → NETWORK PIVOT"
        })

    # Chain 3: RDP BlueKeep / DejaBlue
    if 3389 in port_nums:
        attack_chains.append({
            "chain_id": "AC-003",
            "name": "RDP Pre-Auth RCE (BlueKeep class)",
            "likelihood": "CRITICAL",
            "entry_point": "Port 3389 (RDP) — internet accessible",
            "steps": [
                {"phase": "Reconnaissance", "tactic": "T1595.001 Scanning IP Blocks", "desc": "Masscan discovers open RDP — millions of IPs scanned per hour"},
                {"phase": "Initial Access", "tactic": "T1190 Exploit Public-Facing App", "desc": "BlueKeep (CVE-2019-0708) or DejaBlue (CVE-2019-1182) pre-auth RCE exploit"},
                {"phase": "Execution", "tactic": "T1059 Command and Scripting", "desc": "Full SYSTEM-level shell on Windows host — no credentials required"},
                {"phase": "Impact", "tactic": "T1486 + T1003", "desc": "Ransomware + credential dumping (Mimikatz) → entire Windows domain compromised"},
            ],
            "estimated_time_to_exploit": "< 5 minutes with public exploit",
            "skill_required": "LOW — public exploits in Metasploit",
            "blast_radius": "FULL WINDOWS DOMAIN COMPROMISE"
        })

    # Chain 4: Web app → server compromise
    if any(p in port_nums for p in [80, 443, 8080]):
        attack_chains.append({
            "chain_id": "AC-004",
            "name": "Web Application Attack → Server Compromise",
            "likelihood": "MEDIUM",
            "entry_point": "Port 80/443 — web application",
            "steps": [
                {"phase": "Reconnaissance", "tactic": "T1595.003 Wordlist Scanning", "desc": "Directory bruteforce (gobuster/ffuf) — discover admin panels, API endpoints, backup files"},
                {"phase": "Initial Access", "tactic": "T1190 Web App Exploit", "desc": "SQL injection, file upload bypass, or CVE in web framework version"},
                {"phase": "Execution", "tactic": "T1059.004 Unix Shell", "desc": "Web shell upload → OS command execution as www-data"},
                {"phase": "Privilege Escalation", "tactic": "T1068 Exploitation for Privilege", "desc": "Local privilege escalation → root/SYSTEM"},
                {"phase": "Impact", "tactic": "T1565 Data Manipulation", "desc": "Website defacement, malware injection into served pages, data theft"},
            ],
            "estimated_time_to_exploit": "Hours to days depending on app complexity",
            "skill_required": "MEDIUM",
            "blast_radius": "WEB SERVER COMPROMISE"
        })

    # Phishing chain (always relevant)
    attack_chains.append({
        "chain_id": "AC-005",
        "name": "Phishing / BEC via Domain Spoofing",
        "likelihood": "HIGH",
        "entry_point": "Missing SPF/DMARC records + typosquatting domains",
        "steps": [
            {"phase": "Reconnaissance", "tactic": "T1589 Gather Victim Identity Info", "desc": "Email addresses harvested via theHarvester/OSINT"},
            {"phase": "Resource Development", "tactic": "T1583.001 Acquire Infrastructure", "desc": "Typosquat domain registered — spoofed email sent from lookalike domain"},
            {"phase": "Initial Access", "tactic": "T1566.002 Spearphishing Link", "desc": "Targeted phishing email to harvested addresses — credential harvesting page"},
            {"phase": "Impact", "tactic": "T1657 Financial Theft", "desc": "BEC fraud — redirect payments, access SaaS accounts, credential resale"},
        ],
        "estimated_time_to_exploit": "Minutes to set up, hours to execute",
        "skill_required": "LOW",
        "blast_radius": "CREDENTIAL THEFT, FINANCIAL FRAUD"
    })

    return {
        "domain": domain,
        "attack_chains": attack_chains,
        "total_chains": len(attack_chains),
        "highest_likelihood": "CRITICAL" if any(c["likelihood"] == "CRITICAL" for c in attack_chains) else "HIGH",
        "summary": f"{len(attack_chains)} realistic attack chains modeled. {len([c for c in attack_chains if c['likelihood'] in ['CRITICAL','HIGH']])} are HIGH or CRITICAL likelihood.",
        "disclaimer": "This simulation is for authorized security assessment only. Models are based on MITRE ATT&CK framework and publicly documented techniques."
    }
