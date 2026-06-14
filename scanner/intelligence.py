"""
VoraGuard Intelligence Enrichment
API integrations: VirusTotal, DNS health, SSL/TLS analysis.
All functions return structured dicts — never raw API responses.
"""

import hashlib
import socket
import ssl
import re
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import requests

from utils.logger import get_logger
from config.settings import settings

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def vt_check_domain(domain: str) -> dict:
    """Query VirusTotal for domain reputation."""
    if not settings.VT_API_KEY:
        return {"available": False, "reason": "VT_API_KEY not configured"}

    log.info(f"[VT] Checking domain reputation: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=settings.VT_TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            categories = data.get("categories", {})
            reputation = data.get("reputation", 0)

            return {
                "available": True,
                "domain": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "total_engines": total,
                "reputation_score": reputation,
                "categories": list(set(categories.values())),
                "risk_level": _vt_risk_level(malicious, suspicious, total),
                "last_analysis_date": data.get("last_analysis_date", "Unknown")
            }

        elif resp.status_code == 404:
            return {"available": True, "domain": domain, "risk_level": "unknown",
                    "reason": "Domain not in VirusTotal database"}
        elif resp.status_code == 401:
            return {"available": False, "reason": "Invalid VirusTotal API key"}
        elif resp.status_code == 429:
            return {"available": False, "reason": "VirusTotal rate limit hit (free tier: 4 req/min)"}
        else:
            return {"available": False, "reason": f"VT API error: HTTP {resp.status_code}"}

    except requests.Timeout:
        return {"available": False, "reason": "VirusTotal request timed out"}
    except requests.RequestException as e:
        log.error(f"[VT] Request error: {e}")
        return {"available": False, "reason": str(e)}


def vt_check_ip(ip: str) -> dict:
    """Query VirusTotal for IP reputation — full enrichment."""
    if not settings.VT_API_KEY:
        return {"available": False, "reason": "VT_API_KEY not configured"}

    log.info(f"[VT] Checking IP: {ip}")
    headers = {"x-apikey": settings.VT_API_KEY}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers, timeout=settings.VT_TIMEOUT
        )
        if resp.status_code != 200:
            return {"available": False, "ip": ip, "reason": f"HTTP {resp.status_code}"}

        raw = resp.json()["data"]
        data = raw.get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values())

        # Get top malicious engine detections
        analysis_results = data.get("last_analysis_results", {})
        detections = []
        for engine, result in analysis_results.items():
            if result.get("category") in ("malicious", "suspicious"):
                detections.append({
                    "engine": engine,
                    "category": result.get("category"),
                    "result": result.get("result", "")
                })
        detections = detections[:10]

        # Categories from engines
        cats = data.get("categories", {})
        cat_list = list(set(cats.values()))[:6] if cats else []

        # Get communicating files (malware that phones home to this IP)
        comm_files = []
        try:
            cr = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/communicating_files",
                headers=headers, timeout=8, params={"limit": 5}
            )
            if cr.status_code == 200:
                for f in cr.json().get("data", [])[:5]:
                    fa = f.get("attributes", {})
                    fs = fa.get("last_analysis_stats", {})
                    comm_files.append({
                        "sha256": fa.get("sha256","")[:16] + "...",
                        "name": (fa.get("meaningful_name") or fa.get("name","Unknown"))[:40],
                        "malicious": fs.get("malicious", 0),
                        "type": fa.get("type_description",""),
                    })
        except Exception:
            pass

        # Get detected URLs
        detected_urls = []
        try:
            ur = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/urls",
                headers=headers, timeout=8, params={"limit": 5}
            )
            if ur.status_code == 200:
                for u in ur.json().get("data", [])[:5]:
                    ua = u.get("attributes", {})
                    us = ua.get("last_analysis_stats", {})
                    if us.get("malicious", 0) > 0:
                        detected_urls.append({
                            "url": ua.get("url","")[:60],
                            "malicious": us.get("malicious", 0),
                            "last_seen": ua.get("last_analysis_date","")
                        })
        except Exception:
            pass

        return {
            "available": True,
            "ip": ip,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "asn": data.get("asn", "Unknown"),
            "as_owner": data.get("as_owner", "Unknown"),
            "country": data.get("country", "Unknown"),
            "network": data.get("network", "Unknown"),
            "reputation": data.get("reputation", 0),
            "tags": data.get("tags", []),
            "categories": cat_list,
            "last_analysis_date": data.get("last_analysis_date", ""),
            "risk_level": _vt_risk_level(malicious, suspicious, total),
            "detections": detections,
            "communicating_files": comm_files,
            "detected_urls": detected_urls,
            "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }

    except Exception as e:
        return {"available": False, "reason": str(e)}


def _vt_risk_level(malicious: int, suspicious: int, total: int) -> str:
    if total == 0:
        return "unknown"
    ratio = malicious / total
    if malicious >= 5 or ratio > 0.1:
        return "high"
    elif malicious > 0 or suspicious >= 3:
        return "medium"
    return "clean"


# ---------------------------------------------------------------------------
# DNS Health
# ---------------------------------------------------------------------------

def check_dns_health(domain: str) -> dict:
    """Check SPF, DMARC, DKIM presence and DNS resolution."""
    log.info(f"[DNS] Checking DNS health for {domain}")
    result = {
        "domain": domain,
        "resolves": False,
        "ip_addresses": [],
        "spf": {"present": False, "record": ""},
        "dmarc": {"present": False, "record": ""},
        "mx_records": [],
        "issues": []
    }

    # A record
    try:
        ips = socket.getaddrinfo(domain, None)
        result["ip_addresses"] = list(set(i[4][0] for i in ips))
        result["resolves"] = True
    except socket.gaierror:
        result["issues"].append("Domain does not resolve to any IP address")
        return result

    # SPF, DMARC, MX — use nslookup/dig via subprocess for reliability
    import subprocess

    # SPF (TXT record on root domain)
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.splitlines():
            if "v=spf1" in line:
                result["spf"]["present"] = True
                result["spf"]["record"] = line.strip().strip('"')
                break
        if not result["spf"]["present"]:
            result["issues"].append("No SPF record found — email spoofing risk")
    except Exception:
        result["issues"].append("Could not check SPF record")

    # DMARC
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.splitlines():
            if "v=DMARC1" in line:
                result["dmarc"]["present"] = True
                result["dmarc"]["record"] = line.strip().strip('"')
                break
        if not result["dmarc"]["present"]:
            result["issues"].append("No DMARC record found — phishing risk")
    except Exception:
        result["issues"].append("Could not check DMARC record")

    # MX
    try:
        r = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10
        )
        mx = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        result["mx_records"] = mx
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# SSL / TLS Analysis
# ---------------------------------------------------------------------------

def check_ssl(domain: str, port: int = 443) -> dict:
    """Inspect SSL certificate — expiry, issuer, weak config."""
    log.info(f"[SSL] Checking certificate for {domain}:{port}")
    result = {
        "domain": domain,
        "port": port,
        "has_ssl": False,
        "valid": False,
        "expires_in_days": None,
        "issuer": "",
        "subject": "",
        "protocol": "",
        "issues": []
    }

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, port), timeout=10),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        conn.close()

        result["has_ssl"] = True
        result["valid"] = True
        result["protocol"] = conn.version() if hasattr(conn, "version") else "TLS"

        # Expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expire_dt - datetime.now(timezone.utc)).days
            result["expires_in_days"] = days_left
            if days_left < 0:
                result["issues"].append("Certificate has EXPIRED")
                result["valid"] = False
            elif days_left < 30:
                result["issues"].append(f"Certificate expires in {days_left} days — renew soon")

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "Unknown")

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject.get("commonName", domain)

    except ssl.SSLCertVerificationError as e:
        result["has_ssl"] = True
        result["valid"] = False
        result["issues"].append(f"Certificate verification failed: {e.reason}")
    except ConnectionRefusedError:
        result["issues"].append(f"Port {port} is closed — no HTTPS")
    except socket.timeout:
        result["issues"].append("SSL check timed out")
    except Exception as e:
        result["issues"].append(f"SSL check error: {str(e)}")

    return result


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

def calculate_risk_score(
    nmap_result,
    dnstwist_result,
    vt_domain: dict,
    dns_health: dict,
    ssl_info: dict
) -> dict:
    """
    Weighted risk scoring:
      Port exposure        25%
      VT reputation        30%
      Typosquatting        15%
      DNS health           20%
      SSL/TLS              10%
    """
    score = 100
    breakdown = {}
    findings = []

    # --- Port exposure (25 points max) ---
    port_deduction = 0
    if nmap_result and nmap_result.success:
        n_ports = len(nmap_result.open_ports)
        high_risk_ports = {21, 22, 23, 25, 3306, 3389, 5900, 6379, 27017}
        exposed_risky = [p for p in nmap_result.open_ports if p.port in high_risk_ports]

        if n_ports > 10:
            port_deduction += 15
        elif n_ports > 5:
            port_deduction += 8

        for p in exposed_risky:
            port_deduction += 5
            findings.append(f"High-risk port exposed: {p.port}/{p.service}")

        port_deduction = min(25, port_deduction)

    breakdown["port_exposure"] = {"deduction": port_deduction, "max": 25}
    score -= port_deduction

    # --- VirusTotal (30 points max) ---
    vt_deduction = 0
    if vt_domain.get("available"):
        risk = vt_domain.get("risk_level", "unknown")
        if risk == "high":
            vt_deduction = 30
            findings.append(f"VirusTotal: {vt_domain.get('malicious', 0)} engines flagged as malicious")
        elif risk == "medium":
            vt_deduction = 15
            findings.append("VirusTotal: Suspicious activity detected")
        elif risk == "clean":
            vt_deduction = 0

    breakdown["vt_reputation"] = {"deduction": vt_deduction, "max": 30}
    score -= vt_deduction

    # --- Typosquatting (15 points max) ---
    typo_deduction = 0
    if dnstwist_result and dnstwist_result.success:
        count = dnstwist_result.registered_count
        if count > 20:
            typo_deduction = 15
            findings.append(f"Severe typosquatting: {count} registered lookalike domains")
        elif count > 10:
            typo_deduction = 10
            findings.append(f"High typosquatting: {count} registered lookalike domains")
        elif count > 3:
            typo_deduction = 5
            findings.append(f"Moderate typosquatting: {count} registered lookalike domains")

    breakdown["typosquatting"] = {"deduction": typo_deduction, "max": 15}
    score -= typo_deduction

    # --- DNS health (20 points max) ---
    dns_deduction = 0
    if dns_health:
        if not dns_health.get("spf", {}).get("present"):
            dns_deduction += 8
        if not dns_health.get("dmarc", {}).get("present"):
            dns_deduction += 8
        if not dns_health.get("resolves"):
            dns_deduction += 4
        dns_deduction = min(20, dns_deduction)

    breakdown["dns_health"] = {"deduction": dns_deduction, "max": 20}
    score -= dns_deduction

    # --- SSL (10 points max) ---
    ssl_deduction = 0
    if ssl_info:
        if not ssl_info.get("has_ssl"):
            ssl_deduction = 10
            findings.append("No HTTPS/SSL detected")
        elif not ssl_info.get("valid"):
            ssl_deduction = 8
            findings.append("SSL certificate is invalid or expired")
        elif ssl_info.get("expires_in_days", 999) < 30:
            ssl_deduction = 4
            findings.append(f"SSL expires in {ssl_info['expires_in_days']} days")

    breakdown["ssl_tls"] = {"deduction": ssl_deduction, "max": 10}
    score -= ssl_deduction

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "LOW"
        risk_color = "#22c55e"
    elif score >= 60:
        risk_level = "MODERATE"
        risk_color = "#f59e0b"
    elif score >= 40:
        risk_level = "HIGH"
        risk_color = "#ef4444"
    else:
        risk_level = "CRITICAL"
        risk_color = "#dc2626"

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "breakdown": breakdown,
        "key_findings": findings
    }
