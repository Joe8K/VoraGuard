"""
VoraGuard Vulnerability Assessment Engine v1.0
Full-featured VA with credentialed/non-credentialed scanning,
CVE matching, CVSS scoring, risk prioritization, compliance auditing,
attack path analysis, and SOAR integration.
"""
import subprocess, socket, ssl, json, re, os, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional



from utils.logger import get_logger

log = get_logger(__name__)
import re as _re

def _parse_version(version_str):
    if not version_str:
        return None
    parts = _re.findall(r"\d+", version_str)
    if not parts:
        return None
    return tuple(int(x) for x in parts[:4])

def _version_in_range(version_tuple, affected_str):
    if not version_tuple or not affected_str:
        return None
    versions = _re.findall(r"[\d]+(?:\.[\d]+)*(?:p[\d]+)?", affected_str)
    parsed = [_parse_version(v) for v in versions if _parse_version(v)]
    if not parsed:
        return None
    if _re.search(r"<\s*[\d]", affected_str):
        return version_tuple < parsed[-1]
    if "-" in affected_str and len(parsed) >= 2:
        return parsed[0] <= version_tuple <= parsed[-1]
    if len(parsed) == 1:
        exact = parsed[0]
        return version_tuple[:len(exact)] == exact[:len(version_tuple)]
    return None

def _extract_banner_version(service, banner):
    patterns = {
        "ssh":  r"openssh[_\s]+([\d]+\.[\d]+\.?[\d]*p?[\d]*)",
        "http": r"apache/([\d]+\.[\d]+\.?[\d]*)",
        "https":r"apache/([\d]+\.[\d]+\.?[\d]*)",
        "ftp":  r"vsftpd\s+([\d]+\.[\d]+\.?[\d]*)",
        "smtp": r"exim\s+([\d]+\.[\d]+\.?[\d]*)",
        "mysql":r"([\d]+\.[\d]+\.[\d]+)-mysql",
        "redis":r"redis\s+([\d]+\.[\d]+\.[\d]*)",
    }
    pattern = patterns.get(service)
    if not pattern:
        return None
    m = _re.search(pattern, banner.lower())
    if m:
        return next((g for g in m.groups() if g), None)
    return None


import re as _re

def _parse_version(version_str):
    if not version_str:
        return None
    parts = _re.findall(r'\d+', version_str)
    if not parts:
        return None
    return tuple(int(x) for x in parts[:4])

def _version_in_range(version_tuple, affected_str):
    if not version_tuple or not affected_str:
        return None
    versions = _re.findall(r'[\d]+(?:\.[\d]+)*(?:p[\d]+)?', affected_str)
    parsed = [_parse_version(v) for v in versions if _parse_version(v)]
    if not parsed:
        return None
    if _re.search(r'<\s*[\d]', affected_str):
        upper = parsed[-1]
        return version_tuple < upper
    if '-' in affected_str and len(parsed) >= 2:
        lower, upper = parsed[0], parsed[-1]
        return lower <= version_tuple <= upper
    if len(parsed) == 1:
        exact = parsed[0]
        return version_tuple[:len(exact)] == exact[:len(version_tuple)]
    return None

def _extract_banner_version(service, banner):
    banner = banner.lower()
    patterns = {
        'ssh':   r'openssh[_\s]+([\d]+\.[\d]+\.?[\d]*p?[\d]*)',
        'http':  r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'https': r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'ftp':   r'vsftpd\s+([\d]+\.[\d]+\.?[\d]*)',
        'smtp':  r'exim\s+([\d]+\.[\d]+\.?[\d]*)',
        'mysql': r'([\d]+\.[\d]+\.[\d]+)-mysql',
        'redis': r'redis\s+([\d]+\.[\d]+\.[\d]*)',
    }
    pattern = patterns.get(service)
    if not pattern:
        return None
    m = _re.search(pattern, banner)
    if m:
        return next((g for g in m.groups() if g), None)
    return None

import re as _re

def _parse_version(version_str):
    if not version_str:
        return None
    parts = _re.findall(r'\d+', version_str)
    if not parts:
        return None
    return tuple(int(x) for x in parts[:4])

def _version_in_range(version_tuple, affected_str):
    if not version_tuple or not affected_str:
        return None
    versions = _re.findall(r'[\d]+(?:\.[\d]+)*(?:p[\d]+)?', affected_str)
    parsed = [_parse_version(v) for v in versions if _parse_version(v)]
    if not parsed:
        return None
    if _re.search(r'<\s*[\d]', affected_str):
        upper = parsed[-1]
        return version_tuple < upper
    if '-' in affected_str and len(parsed) >= 2:
        lower, upper = parsed[0], parsed[-1]
        return lower <= version_tuple <= upper
    if len(parsed) == 1:
        exact = parsed[0]
        return version_tuple[:len(exact)] == exact[:len(version_tuple)]
    return None

def _extract_banner_version(service, banner):
    banner = banner.lower()
    patterns = {
        'ssh':   r'openssh[_\s]+([\d]+\.[\d]+\.?[\d]*p?[\d]*)',
        'http':  r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'https': r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'ftp':   r'vsftpd\s+([\d]+\.[\d]+\.?[\d]*)',
        'smtp':  r'exim\s+([\d]+\.[\d]+\.?[\d]*)',
        'mysql': r'([\d]+\.[\d]+\.[\d]+)-mysql',
        'redis': r'redis\s+([\d]+\.[\d]+\.[\d]*)',
    }
    pattern = patterns.get(service)
    if not pattern:
        return None
    m = _re.search(pattern, banner)
    if m:
        return next((g for g in m.groups() if g), None)
    return None

import re as _re

def _parse_version(version_str):
    if not version_str:
        return None
    parts = _re.findall(r'\d+', version_str)
    if not parts:
        return None
    return tuple(int(x) for x in parts[:4])

def _version_in_range(version_tuple, affected_str):
    if not version_tuple or not affected_str:
        return None
    versions = _re.findall(r'[\d]+(?:\.[\d]+)*(?:p[\d]+)?', affected_str)
    parsed = [_parse_version(v) for v in versions if _parse_version(v)]
    if not parsed:
        return None
    if _re.search(r'<\s*[\d]', affected_str):
        upper = parsed[-1]
        return version_tuple < upper
    if '-' in affected_str and len(parsed) >= 2:
        lower, upper = parsed[0], parsed[-1]
        return lower <= version_tuple <= upper
    if len(parsed) == 1:
        exact = parsed[0]
        return version_tuple[:len(exact)] == exact[:len(version_tuple)]
    return None

def _extract_banner_version(service, banner):
    banner = banner.lower()
    patterns = {
        'ssh':   r'openssh[_\s]+([\d]+\.[\d]+\.?[\d]*p?[\d]*)',
        'http':  r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'https': r'apache/([\d]+\.[\d]+\.?[\d]*)',
        'ftp':   r'vsftpd\s+([\d]+\.[\d]+\.?[\d]*)',
        'smtp':  r'exim\s+([\d]+\.[\d]+\.?[\d]*)',
        'mysql': r'([\d]+\.[\d]+\.[\d]+)-mysql',
        'redis': r'redis\s+([\d]+\.[\d]+\.[\d]*)',
    }
    pattern = patterns.get(service)
    if not pattern:
        return None
    m = _re.search(pattern, banner)
    if m:
        return next((g for g in m.groups() if g), None)
    return None

# ── CVE/Service Knowledge Base ─────────────────────────────────────────────
SERVICE_CVE_DB = {
    "ssh": [
        {"cve":"CVE-2023-38408","cvss":9.8,"severity":"CRITICAL","description":"OpenSSH remote code execution via ssh-agent","affected":"OpenSSH < 9.3p2","fix":"Upgrade to OpenSSH 9.3p2+","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2023-51385","cvss":6.5,"severity":"HIGH","description":"OpenSSH OS command injection via user/hostname","affected":"OpenSSH < 9.6","fix":"Upgrade to OpenSSH 9.6+","exploitable":True,"exploit_available":False},
        {"cve":"CVE-2024-6387","cvss":8.1,"severity":"HIGH","description":"RegreSSHion: race condition RCE in OpenSSH","affected":"OpenSSH 8.5p1-9.7p1","fix":"Upgrade to OpenSSH 9.8p1+","exploitable":True,"exploit_available":True},
    ],
    "http": [
        {"cve":"CVE-2021-41773","cvss":9.8,"severity":"CRITICAL","description":"Apache HTTP Server path traversal and RCE","affected":"Apache 2.4.49","fix":"Upgrade Apache to 2.4.51+","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2022-22720","cvss":9.8,"severity":"CRITICAL","description":"Apache HTTP request smuggling","affected":"Apache 2.4.0-2.4.52","fix":"Upgrade Apache to 2.4.53+","exploitable":True,"exploit_available":False},
        {"cve":"CVE-2023-25690","cvss":9.8,"severity":"CRITICAL","description":"Apache HTTP request splitting","affected":"Apache 2.4.0-2.4.55","fix":"Upgrade Apache to 2.4.56+","exploitable":True,"exploit_available":True},
    ],
    "https": [
        {"cve":"CVE-2022-0778","cvss":7.5,"severity":"HIGH","description":"OpenSSL infinite loop in BN_mod_sqrt()","affected":"OpenSSL < 1.0.2zd, < 1.1.1n, < 3.0.2","fix":"Upgrade OpenSSL","exploitable":False,"exploit_available":False},
        {"cve":"CVE-2023-0286","cvss":7.4,"severity":"HIGH","description":"OpenSSL X.400 address type confusion","affected":"OpenSSL 1.0.2-3.0.7","fix":"Upgrade to OpenSSL 3.0.8+","exploitable":False,"exploit_available":False},
    ],
    "ftp": [
        {"cve":"CVE-2023-1227","cvss":9.8,"severity":"CRITICAL","description":"vsftpd authentication bypass","affected":"vsftpd < 3.0.5","fix":"Upgrade vsftpd or disable anonymous FTP","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2011-2523","cvss":10.0,"severity":"CRITICAL","description":"vsftpd 2.3.4 backdoor command execution","affected":"vsftpd 2.3.4","fix":"Upgrade vsftpd immediately","exploitable":True,"exploit_available":True},
    ],
    "smtp": [
        {"cve":"CVE-2020-28017","cvss":9.8,"severity":"CRITICAL","description":"Exim buffer overflow in receive_add_recipient","affected":"Exim < 4.94.2","fix":"Upgrade Exim to 4.94.2+","exploitable":True,"exploit_available":False},
        {"cve":"CVE-2023-42115","cvss":9.8,"severity":"CRITICAL","description":"Exim AUTH out-of-bounds write","affected":"Exim < 4.96.1","fix":"Upgrade Exim to 4.96.1+","exploitable":True,"exploit_available":True},
    ],
    "mysql": [
        {"cve":"CVE-2023-21980","cvss":8.8,"severity":"HIGH","description":"MySQL Server optimizer RCE","affected":"MySQL 8.0.x < 8.0.33","fix":"Upgrade MySQL to 8.0.33+","exploitable":True,"exploit_available":False},
        {"cve":"CVE-2022-21417","cvss":4.9,"severity":"MEDIUM","description":"MySQL InnoDB denial of service","affected":"MySQL 5.7.x, 8.0.x","fix":"Apply Oracle CPU April 2022","exploitable":False,"exploit_available":False},
    ],
    "rdp": [
        {"cve":"CVE-2019-0708","cvss":9.8,"severity":"CRITICAL","description":"BlueKeep: RDP pre-auth RCE (wormable)","affected":"Windows 7/Server 2008","fix":"Apply MS19-0708 patch, disable RDP if unused","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2023-35332","cvss":6.8,"severity":"MEDIUM","description":"RDP security feature bypass","affected":"Windows Server 2012-2022","fix":"Apply KB5028166","exploitable":False,"exploit_available":False},
    ],
    "smb": [
        {"cve":"CVE-2017-0144","cvss":9.8,"severity":"CRITICAL","description":"EternalBlue: SMBv1 buffer overflow (WannaCry)","affected":"Windows XP-Server 2016 without MS17-010","fix":"Apply MS17-010, disable SMBv1","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2020-0796","cvss":10.0,"severity":"CRITICAL","description":"SMBGhost: SMBv3 compression buffer overflow","affected":"Windows 10 1903/1909","fix":"Apply KB4551762","exploitable":True,"exploit_available":True},
    ],
    "telnet": [
        {"cve":"CVE-2011-4862","cvss":10.0,"severity":"CRITICAL","description":"Telnet encryption key exchange buffer overflow","affected":"FreeBSD telnetd","fix":"Disable telnet, use SSH","exploitable":True,"exploit_available":True},
    ],
    "redis": [
        {"cve":"CVE-2022-0543","cvss":10.0,"severity":"CRITICAL","description":"Redis Lua sandbox escape RCE","affected":"Redis on Debian/Ubuntu","fix":"Upgrade Redis, disable Lua or restrict access","exploitable":True,"exploit_available":True},
        {"cve":"CVE-2023-41056","cvss":8.8,"severity":"HIGH","description":"Redis heap overflow in SRANDMEMBER","affected":"Redis < 7.0.13, < 7.2.4","fix":"Upgrade Redis","exploitable":True,"exploit_available":False},
    ],
    "mongodb": [
        {"cve":"CVE-2021-20328","cvss":6.8,"severity":"MEDIUM","description":"MongoDB client-side field encryption bypass","affected":"MongoDB < 4.4.8","fix":"Upgrade MongoDB","exploitable":False,"exploit_available":False},
    ],
    "vnc": [
        {"cve":"CVE-2022-47952","cvss":7.8,"severity":"HIGH","description":"LibVNCServer integer overflow","affected":"LibVNCServer < 0.9.14","fix":"Upgrade LibVNCServer","exploitable":True,"exploit_available":False},
    ],
    "elasticsearch": [
        {"cve":"CVE-2021-22145","cvss":6.5,"severity":"MEDIUM","description":"Elasticsearch information disclosure","affected":"Elasticsearch < 7.13.4","fix":"Upgrade Elasticsearch","exploitable":False,"exploit_available":False},
    ],
    "docker": [
        {"cve":"CVE-2024-21626","cvss":8.6,"severity":"HIGH","description":"Leaky Vessels: container escape via runc","affected":"runc < 1.1.12","fix":"Upgrade runc/Docker","exploitable":True,"exploit_available":True},
    ],
}

COMPLIANCE_CHECKS = {
    "PCI-DSS": {
        "open_telnet": {"rule":"2.2.2","description":"Telnet is insecure — violates PCI-DSS Req 2.2.2","severity":"CRITICAL"},
        "open_ftp": {"rule":"2.2.2","description":"FTP transmits credentials in cleartext — violates PCI-DSS Req 2.2.2","severity":"HIGH"},
        "no_https": {"rule":"4.2.1","description":"No HTTPS detected — cardholder data may be transmitted unencrypted","severity":"CRITICAL"},
        "open_rdp": {"rule":"8.6.1","description":"RDP exposed — requires MFA per PCI-DSS v4 Req 8.6.1","severity":"HIGH"},
        "no_ssh_version": {"rule":"6.3.3","description":"Cannot verify SSH patch level — Req 6.3.3 requires current patches","severity":"MEDIUM"},
        "open_smb": {"rule":"1.3.2","description":"SMB exposed to network — violates PCI-DSS network segmentation Req 1.3.2","severity":"HIGH"},
    },
    "HIPAA": {
        "open_telnet": {"rule":"164.312(e)(1)","description":"Telnet exposes PHI in transit — violates Transmission Security","severity":"CRITICAL"},
        "no_https": {"rule":"164.312(e)(2)(ii)","description":"No encryption in transit for potential PHI","severity":"CRITICAL"},
        "open_rdp": {"rule":"164.312(d)","description":"Unprotected RDP access — person or entity authentication required","severity":"HIGH"},
        "open_ftp": {"rule":"164.312(e)(1)","description":"FTP transmits data unencrypted — PHI transmission risk","severity":"HIGH"},
    },
    "GDPR": {
        "no_https": {"rule":"Art.32","description":"No HTTPS — personal data may be transmitted without encryption (Art. 32)","severity":"CRITICAL"},
        "open_telnet": {"rule":"Art.32","description":"Telnet exposes credentials — violates appropriate technical measures (Art. 32)","severity":"HIGH"},
        "open_ftp": {"rule":"Art.32","description":"FTP unencrypted transfer — violates Art. 32 data security","severity":"HIGH"},
        "open_rdp": {"rule":"Art.25","description":"Exposed RDP — violates Privacy by Design (Art. 25)","severity":"MEDIUM"},
    },
    "SOC2": {
        "open_telnet": {"rule":"CC6.1","description":"Telnet violates Logical Access Controls (CC6.1)","severity":"HIGH"},
        "open_rdp": {"rule":"CC6.6","description":"RDP exposure — boundary protection required (CC6.6)","severity":"HIGH"},
        "no_https": {"rule":"CC6.7","description":"Unencrypted transmission violates CC6.7","severity":"HIGH"},
        "open_smb": {"rule":"CC6.6","description":"SMB exposure violates network boundary controls (CC6.6)","severity":"MEDIUM"},
    },
    "CIS": {
        "open_telnet": {"rule":"CIS-4.1","description":"Disable all insecure services — telnet must be removed (CIS Control 4.1)","severity":"CRITICAL"},
        "open_rdp": {"rule":"CIS-12.8","description":"Limit access to remote access protocols (CIS Control 12.8)","severity":"HIGH"},
        "open_ftp": {"rule":"CIS-4.1","description":"FTP is an insecure service — disable or replace with SFTP (CIS Control 4.1)","severity":"HIGH"},
        "open_smb": {"rule":"CIS-9.2","description":"Disable unnecessary network services including SMB (CIS Control 9.2)","severity":"HIGH"},
        "no_https": {"rule":"CIS-3.10","description":"Encrypt sensitive data in transit (CIS Control 3.10)","severity":"HIGH"},
    },
}

HIGH_RISK_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb", 2375: "docker", 2376: "docker-tls",
}

REMEDIATION_DB = {
    "open_telnet": "Disable telnet immediately. Enable SSH with key-based authentication: `systemctl disable telnetd && systemctl stop telnetd`",
    "open_ftp": "Replace FTP with SFTP or FTPS. Disable vsftpd: `systemctl disable vsftpd`. Use `sftp` or `rsync over SSH`",
    "open_rdp": "Restrict RDP to VPN only. Enable NLA. Set firewall rule: `ufw deny 3389`. Enable MFA for all RDP sessions.",
    "open_smb": "Disable SMBv1: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`. Restrict SMB to internal network only.",
    "no_https": "Install SSL certificate (Let's Encrypt: `certbot --apache`). Redirect all HTTP to HTTPS. Enable HSTS header.",
    "open_redis": "Bind Redis to localhost: `bind 127.0.0.1` in redis.conf. Set requirepass. Disable Lua scripting if unused.",
    "open_mongodb": "Enable MongoDB auth: `security.authorization: enabled` in mongod.conf. Bind to localhost.",
    "open_elasticsearch": "Enable Elasticsearch security: `xpack.security.enabled: true`. Do not expose port 9200 publicly.",
    "open_docker": "Never expose Docker daemon on TCP. Use Unix socket only. Enable TLS if TCP is required.",
    "default_ssh_port": "Change SSH port from 22. Disable root login: `PermitRootLogin no`. Use fail2ban.",
    "weak_ssl": "Upgrade TLS to 1.2+. Disable SSLv3/TLS1.0/1.1. Use strong cipher suites (AES-256-GCM).",
}


class VulnerabilityScanner:
    def __init__(self):
        self.scan_results = {}
        self.lock = threading.Lock()

    # ── Port Scanner ──────────────────────────────────────────────────────
    def scan_ports(self, target: str, port_range: str = "1-1024", timeout: int = 1) -> dict:
        log.info(f"[VA] Port scanning {target} range={port_range}")
        open_ports = []
        try:
            parts = port_range.split("-")
            start, end = int(parts[0]), int(parts[1]) if len(parts) > 1 else int(parts[0])
        except Exception:
            start, end = 1, 1024

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    service = HIGH_RISK_PORTS.get(port, "unknown")
                    banner = self._grab_banner(target, port)
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "banner": banner,
                        "state": "open",
                        "risk": "HIGH" if port in HIGH_RISK_PORTS else "LOW"
                    })
            except Exception:
                pass

        threads = []
        for port in range(start, min(end + 1, start + 500)):
            t = threading.Thread(target=check_port, args=(port,))
            threads.append(t)
            t.start()
            if len(threads) >= 50:
                for th in threads:
                    th.join()
                threads = []
        for th in threads:
            th.join()

        open_ports.sort(key=lambda x: x["port"])
        log.info(f"[VA] Found {len(open_ports)} open ports on {target}")
        return {"target": target, "open_ports": open_ports, "total": len(open_ports)}

    def _grab_banner(self, host: str, port: int, timeout: float = 2) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            if port in [80, 8080, 8443]:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
            s.close()
            return banner
        except Exception:
            return ""

    # ── CVE Matching ─────────────────────────────────────────────────────
    def match_cves(self, open_ports: list) -> list:
        findings = []
        seen = set()
        for port_info in open_ports:
            service = port_info.get("service", "").lower()
            port = port_info.get("port")
            banner = port_info.get("banner", "")
            banner_lower = banner.lower()
            detected_version_str = _extract_banner_version(service, banner_lower)
            detected_version = _parse_version(detected_version_str) if detected_version_str else None
            cves = SERVICE_CVE_DB.get(service, [])
            for cve in cves:
                affected = cve.get("affected", "")
                key = (cve["cve"], port)
                if key in seen:
                    continue
                if detected_version:
                    vulnerable = _version_in_range(detected_version, affected)
                    if vulnerable is False:
                        continue
                    false_positive_risk = "LOW" if vulnerable is True else "MEDIUM"
                else:
                    false_positive_risk = "HIGH"
                finding = dict(cve)
                finding["port"] = port
                finding["service"] = service
                finding["banner"] = banner
                finding["detected_version"] = detected_version_str or "unknown"
                finding["false_positive_risk"] = false_positive_risk
                finding["remediation"] = REMEDIATION_DB.get(f"open_{service}", f"Update {service} to latest version and apply security hardening")
                finding["risk_score"] = self._calculate_risk_score(cve)
                if false_positive_risk == "HIGH":
                    finding["risk_score"] = round(finding["risk_score"] * 0.7, 1)
                findings.append(finding)
                seen.add(key)
        findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return findings


    def _calculate_risk_score(self, cve: dict) -> float:
        score = cve.get("cvss", 0)
        if cve.get("exploit_available"):
            score = min(10.0, score + 0.5)
        if cve.get("exploitable"):
            score = min(10.0, score + 0.2)
        return round(score, 1)

    # ── SSL/TLS Analysis ─────────────────────────────────────────────────
    def check_ssl_tls(self, host: str, port: int = 443) -> dict:
        result = {"issues": [], "grade": "A", "protocol": "", "cipher": ""}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host)
            result["protocol"] = conn.version()
            cipher = conn.cipher()
            if cipher:
                result["cipher"] = cipher[0]
                if any(w in cipher[0] for w in ["RC4","3DES","NULL","EXPORT","anon"]):
                    result["issues"].append({"check": "weak_ssl", "severity": "HIGH", "description": f"Weak cipher: {cipher[0]}", "remediation": REMEDIATION_DB["weak_ssl"]})
                    result["grade"] = "F"
            if result["protocol"] in ["TLSv1", "TLSv1.1", "SSLv3"]:
                result["issues"].append({"check": "weak_ssl", "severity": "HIGH", "description": f"Outdated protocol: {result['protocol']}", "remediation": REMEDIATION_DB["weak_ssl"]})
                result["grade"] = "C" if result["grade"] == "A" else result["grade"]
            conn.close()
        except Exception as e:
            result["issues"].append({"check": "ssl_error", "severity": "MEDIUM", "description": f"SSL check error: {str(e)[:100]}", "remediation": "Verify SSL configuration"})
        return result

    # ── Compliance Auditing ───────────────────────────────────────────────
    def run_compliance_check(self, open_ports: list, frameworks: list = None) -> dict:
        if frameworks is None:
            frameworks = ["PCI-DSS", "HIPAA", "GDPR", "SOC2", "CIS"]

        port_services = {p["port"]: p["service"] for p in open_ports}
        has_https = any(p["service"] in ["https","http-alt"] for p in open_ports)
        has_http = any(p["service"] == "http" for p in open_ports)

        results = {}
        for framework in frameworks:
            checks = COMPLIANCE_CHECKS.get(framework, {})
            violations = []
            passed = []

            for check_id, check in checks.items():
                violated = False
                if check_id == "open_telnet" and 23 in port_services:
                    violated = True
                elif check_id == "open_ftp" and 21 in port_services:
                    violated = True
                elif check_id == "no_https" and has_http and not has_https:
                    violated = True
                elif check_id == "open_rdp" and 3389 in port_services:
                    violated = True
                elif check_id == "open_smb" and 445 in port_services:
                    violated = True
                elif check_id == "no_ssh_version" and 22 in port_services:
                    violated = True

                if violated:
                    violations.append({**check, "check_id": check_id})
                else:
                    passed.append({"rule": check["rule"], "description": f"No {check_id.replace('_',' ')} detected", "check_id": check_id})

            total = len(checks)
            pass_count = len(passed)
            score = int((pass_count / total) * 100) if total else 100
            results[framework] = {
                "score": score,
                "status": "COMPLIANT" if score == 100 else "NON-COMPLIANT" if score < 70 else "PARTIAL",
                "violations": violations,
                "passed": passed,
                "total_checks": total,
                "pass_count": pass_count,
                "fail_count": len(violations)
            }
        return results

    # ── Credentialed Scan (SSH) ───────────────────────────────────────────
    def credentialed_scan_ssh(self, host: str, username: str, password: str = None, key_path: str = None) -> dict:
        result = {"success": False, "findings": [], "system_info": {}, "error": ""}
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if key_path:
                client.connect(host, username=username, key_filename=key_path, timeout=10)
            else:
                client.connect(host, username=username, password=password, timeout=10)

            result["success"] = True
            checks = [
                ("uname -a", "os_info"),
                ("cat /etc/os-release 2>/dev/null | head -5", "os_release"),
                ("ss -tlnp 2>/dev/null | head -20", "listening_services"),
                ("cat /etc/passwd | grep -v nologin | grep -v false", "users"),
                ("find / -perm -4000 -type f 2>/dev/null | head -20", "suid_binaries"),
                ("ls -la /etc/cron* 2>/dev/null", "cron_jobs"),
                ("cat /etc/ssh/sshd_config | grep -E 'PermitRoot|PasswordAuth|Port'", "ssh_config"),
                ("dpkg -l 2>/dev/null | grep -i 'openssh\\|apache\\|nginx\\|mysql' | head -10", "installed_packages"),
                ("last | head -10", "login_history"),
                ("w", "logged_in_users"),
            ]
            for cmd, key in checks:
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=5)
                    output = stdout.read().decode("utf-8", errors="ignore").strip()
                    result["system_info"][key] = output
                    self._analyze_credentialed_output(key, output, result["findings"])
                except Exception:
                    pass
            client.close()
        except ImportError:
            result["error"] = "paramiko not installed. Run: pip install paramiko --break-system-packages"
        except Exception as e:
            result["error"] = str(e)
        return result

    def _analyze_credentialed_output(self, key: str, output: str, findings: list):
        if key == "ssh_config":
            if "PermitRootLogin yes" in output:
                findings.append({"severity":"HIGH","check":"root_login_enabled","description":"SSH root login is enabled","remediation":"Set PermitRootLogin no in /etc/ssh/sshd_config"})
            if "PasswordAuthentication yes" in output:
                findings.append({"severity":"MEDIUM","check":"password_auth_enabled","description":"SSH password authentication enabled — prefer key-based auth","remediation":"Set PasswordAuthentication no, use SSH keys only"})
        if key == "suid_binaries" and output:
            lines = [l for l in output.splitlines() if l.strip()]
            if len(lines) > 5:
                findings.append({"severity":"MEDIUM","check":"excessive_suid","description":f"{len(lines)} SUID binaries found — review for privilege escalation","remediation":"Audit SUID binaries: chmod u-s <binary> for unnecessary ones"})
        if key == "users":
            lines = [l for l in output.splitlines() if l.strip()]
            if len(lines) > 3:
                findings.append({"severity":"INFO","check":"multiple_users","description":f"{len(lines)} shell users found — verify all are authorized","remediation":"Review /etc/passwd and disable unused accounts"})

    # ── Risk Prioritization ───────────────────────────────────────────────
    def prioritize_findings(self, findings: list, asset_criticality: str = "MEDIUM") -> list:
        criticality_multiplier = {"LOW": 0.8, "MEDIUM": 1.0, "HIGH": 1.2, "CRITICAL": 1.5}
        mult = criticality_multiplier.get(asset_criticality, 1.0)

        for f in findings:
            base = f.get("cvss", f.get("risk_score", 5.0))
            adjusted = min(10.0, base * mult)
            if f.get("exploit_available"):
                adjusted = min(10.0, adjusted + 0.5)
            f["adjusted_risk"] = round(adjusted, 1)
            f["priority"] = "PATCH_NOW" if adjusted >= 9.0 else "URGENT" if adjusted >= 7.0 else "SOON" if adjusted >= 4.0 else "MONITOR"
            f["false_positive_risk"] = "LOW" if f.get("exploit_available") else "MEDIUM"

        findings.sort(key=lambda x: x.get("adjusted_risk", 0), reverse=True)
        return findings

    # ── Attack Path Analysis ──────────────────────────────────────────────
    def analyze_attack_paths(self, findings: list, open_ports: list) -> list:
        paths = []
        port_services = {p["port"]: p["service"] for p in open_ports}

        # Path 1: External recon → SSH brute → privilege escalation
        if 22 in port_services:
            ssh_cves = [f for f in findings if f.get("service") == "ssh" and f.get("cvss", 0) >= 7]
            if ssh_cves:
                paths.append({
                    "id": "PATH-001",
                    "name": "External Access → SSH Exploitation → System Compromise",
                    "steps": [
                        {"step": 1, "technique": "T1595 - Active Scanning", "description": "Attacker scans for open SSH port 22"},
                        {"step": 2, "technique": "T1110 - Brute Force", "description": "Attacker attempts credential brute force against SSH"},
                        {"step": 3, "technique": f"{ssh_cves[0]['cve']} Exploitation", "description": ssh_cves[0]["description"]},
                        {"step": 4, "technique": "T1068 - Privilege Escalation", "description": "Attacker escalates to root using SUID or kernel exploit"},
                    ],
                    "risk": "CRITICAL",
                    "cvss_chain": ssh_cves[0].get("cvss", 0),
                    "likelihood": "HIGH",
                    "impact": "Full system compromise"
                })

        # Path 2: SMB lateral movement
        if 445 in port_services:
            smb_cves = [f for f in findings if f.get("service") == "smb"]
            if smb_cves:
                paths.append({
                    "id": "PATH-002",
                    "name": "SMB Exploitation → Lateral Movement → Data Exfiltration",
                    "steps": [
                        {"step": 1, "technique": "T1046 - Network Service Discovery", "description": "Attacker discovers SMB port 445"},
                        {"step": 2, "technique": f"{smb_cves[0]['cve']} (EternalBlue)", "description": smb_cves[0]["description"]},
                        {"step": 3, "technique": "T1021.002 - SMB/Windows Admin Shares", "description": "Attacker moves laterally via SMB shares"},
                        {"step": 4, "technique": "T1005 - Data from Local System", "description": "Attacker exfiltrates sensitive data"},
                    ],
                    "risk": "CRITICAL",
                    "cvss_chain": 9.8,
                    "likelihood": "HIGH",
                    "impact": "Full network compromise + data breach"
                })

        # Path 3: Web app exploitation
        if 80 in port_services or 8080 in port_services:
            web_cves = [f for f in findings if f.get("service") in ["http","http-alt"]]
            if web_cves:
                paths.append({
                    "id": "PATH-003",
                    "name": "Web Application Attack → Code Execution → Persistence",
                    "steps": [
                        {"step": 1, "technique": "T1190 - Exploit Public-Facing Application", "description": f"{web_cves[0].get('cve','N/A')}: {web_cves[0]['description'][:80]}"},
                        {"step": 2, "technique": "T1059 - Command Execution", "description": "Attacker executes OS commands via web shell"},
                        {"step": 3, "technique": "T1505.003 - Web Shell", "description": "Attacker installs persistent web shell"},
                        {"step": 4, "technique": "T1078 - Valid Accounts", "description": "Attacker harvests credentials from web application"},
                    ],
                    "risk": "HIGH",
                    "cvss_chain": web_cves[0].get("cvss", 7.0),
                    "likelihood": "MEDIUM",
                    "impact": "Web application compromise, data breach"
                })

        # Path 4: Unauthenticated database access
        db_ports = {3306: "mysql", 5432: "postgresql", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch"}
        for port, service in db_ports.items():
            if port in port_services:
                paths.append({
                    "id": f"PATH-DB-{port}",
                    "name": f"Unauthenticated {service.upper()} Access → Data Exfiltration",
                    "steps": [
                        {"step": 1, "technique": "T1046 - Network Service Discovery", "description": f"Attacker finds {service} on port {port}"},
                        {"step": 2, "technique": "T1078 - Default Credentials", "description": f"Attacker connects without credentials or using defaults"},
                        {"step": 3, "technique": "T1005 - Data from Local System", "description": "Attacker dumps entire database"},
                        {"step": 4, "technique": "T1041 - Exfiltration over C2", "description": "Data exfiltrated to attacker infrastructure"},
                    ],
                    "risk": "CRITICAL",
                    "cvss_chain": 9.5,
                    "likelihood": "HIGH",
                    "impact": f"Complete {service} database exfiltration"
                })

        return paths

    # ── Shadow IT Detection ───────────────────────────────────────────────
    def detect_shadow_it(self, target: str, open_ports: list) -> list:
        shadow_findings = []
        suspicious_ports = {
            4444: "Possible Metasploit handler or malware C2",
            5555: "Android Debug Bridge (ADB) — unauthorized device",
            8888: "Jupyter Notebook — unauthorized data science tool",
            9090: "Prometheus metrics — unauthorized monitoring",
            3000: "Grafana/Node.js app — possibly unauthorized",
            5984: "CouchDB — unauthorized database",
            7474: "Neo4j — unauthorized graph database",
            8161: "ActiveMQ admin — unauthorized message broker",
            61616: "ActiveMQ broker — unauthorized",
            15672: "RabbitMQ management — unauthorized",
        }
        for port_info in open_ports:
            port = port_info["port"]
            if port in suspicious_ports:
                shadow_findings.append({
                    "port": port,
                    "service": port_info.get("service","unknown"),
                    "description": suspicious_ports[port],
                    "severity": "HIGH",
                    "type": "SHADOW_IT",
                    "remediation": f"Investigate service on port {port}. If unauthorized, stop and remove it immediately."
                })
        return shadow_findings

    # ── Full Scan Orchestrator ────────────────────────────────────────────
    def run_full_scan(self, target: str, scan_type: str = "non_credentialed",
                      port_range: str = "1-1024", credentials: dict = None,
                      frameworks: list = None, asset_criticality: str = "MEDIUM",
                      scan_id: str = None) -> dict:
        if not scan_id:
            scan_id = datetime.now().strftime("VA-%Y%m%d-%H%M%S")

        log.info(f"[VA] Starting {scan_type} scan on {target} | scan_id={scan_id}")
        started_at = datetime.now(timezone.utc)
        result = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "started_at": started_at.isoformat(),
            "completed_at": "",
            "duration_seconds": 0,
            "status": "running",
            "open_ports": [],
            "vulnerabilities": [],
            "compliance": {},
            "attack_paths": [],
            "shadow_it": [],
            "ssl_analysis": {},
            "credentialed_findings": [],
            "risk_summary": {},
            "remediation_plan": [],
            "total_vulns": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "risk_score": 0,
            "asset_criticality": asset_criticality,
            "error": ""
        }

        try:
            # Phase 1: Port scanning
            port_result = self.scan_ports(target, port_range)
            result["open_ports"] = port_result["open_ports"]

            # Phase 2: CVE matching
            vulns = self.match_cves(result["open_ports"])
            vulns = self.prioritize_findings(vulns, asset_criticality)
            result["vulnerabilities"] = vulns

            # Phase 3: SSL analysis
            has_ssl = any(p["port"] in [443, 8443] for p in result["open_ports"])
            if has_ssl:
                result["ssl_analysis"] = self.check_ssl_tls(target)

            # Phase 4: Compliance
            result["compliance"] = self.run_compliance_check(result["open_ports"], frameworks)

            # Phase 5: Attack paths
            result["attack_paths"] = self.analyze_attack_paths(vulns, result["open_ports"])

            # Phase 6: Shadow IT
            result["shadow_it"] = self.detect_shadow_it(target, result["open_ports"])

            # Phase 7: Credentialed scan
            if scan_type == "credentialed" and credentials:
                cred_result = self.credentialed_scan_ssh(
                    target,
                    credentials.get("username",""),
                    credentials.get("password"),
                    credentials.get("key_path")
                )
                result["credentialed_findings"] = cred_result.get("findings", [])
                result["system_info"] = cred_result.get("system_info", {})
                result["credentialed_success"] = cred_result.get("success", False)

            # Phase 8: Risk summary
            all_findings = vulns + result["credentialed_findings"] + result["shadow_it"]
            result["critical_count"] = len([v for v in vulns if v.get("severity") == "CRITICAL"])
            result["high_count"] = len([v for v in vulns if v.get("severity") == "HIGH"])
            result["medium_count"] = len([v for v in vulns if v.get("severity") == "MEDIUM"])
            result["low_count"] = len([v for v in vulns if v.get("severity") == "LOW"])
            result["total_vulns"] = len(vulns)

            # Overall risk score
            if vulns:
                max_cvss = max(v.get("adjusted_risk", v.get("cvss", 0)) for v in vulns)
                result["risk_score"] = round(max_cvss, 1)
            else:
                result["risk_score"] = 0.0

            result["risk_level"] = (
                "CRITICAL" if result["risk_score"] >= 9.0 else
                "HIGH" if result["risk_score"] >= 7.0 else
                "MEDIUM" if result["risk_score"] >= 4.0 else
                "LOW"
            )

            # Remediation plan
            seen = set()
            for v in vulns[:10]:
                rem = v.get("remediation","")
                if rem and rem not in seen:
                    seen.add(rem)
                    result["remediation_plan"].append({
                        "priority": v.get("priority","SOON"),
                        "cve": v.get("cve",""),
                        "action": rem,
                        "severity": v.get("severity","MEDIUM")
                    })

            result["status"] = "complete"

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            log.error(f"[VA] Scan error: {e}")

        completed_at = datetime.now(timezone.utc)
        result["completed_at"] = completed_at.isoformat()
        result["duration_seconds"] = round((completed_at - started_at).total_seconds(), 1)

        # Save result
        self._save_result(scan_id, result)
        log.info(f"[VA] Scan complete: {scan_id} | {result['total_vulns']} vulns | risk={result['risk_score']}")
        return result

    def _save_result(self, scan_id: str, result: dict):
        try:
            save_dir = Path(__file__).parent.parent / "data" / "va_scans"
            save_dir.mkdir(parents=True, exist_ok=True)
            (save_dir / f"{scan_id}.json").write_text(
                json.dumps(result, indent=2, default=str)
            )
        except Exception as e:
            log.error(f"[VA] Save error: {e}")

    def get_scan_history(self, limit: int = 50) -> list:
        try:
            save_dir = Path(__file__).parent.parent / "data" / "va_scans"
            if not save_dir.exists():
                return []
            results = []
            for f in sorted(save_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                try:
                    d = json.loads(f.read_text())
                    results.append({
                        "scan_id": d.get("scan_id",""),
                        "target": d.get("target",""),
                        "scan_type": d.get("scan_type",""),
                        "status": d.get("status",""),
                        "risk_score": d.get("risk_score",0),
                        "risk_level": d.get("risk_level",""),
                        "total_vulns": d.get("total_vulns",0),
                        "critical_count": d.get("critical_count",0),
                        "started_at": d.get("started_at",""),
                        "duration_seconds": d.get("duration_seconds",0),
                    })
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def get_scan_result(self, scan_id: str) -> dict:
        try:
            save_dir = Path(__file__).parent.parent / "data" / "va_scans"
            f = save_dir / f"{scan_id}.json"
            if f.exists():
                return json.loads(f.read_text())
        except Exception:
            pass
        return {}


# Singleton
_va_scanner = None
def get_va_scanner() -> VulnerabilityScanner:
    global _va_scanner
    if _va_scanner is None:
        _va_scanner = VulnerabilityScanner()
    return _va_scanner
