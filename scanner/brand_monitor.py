"""
VoraGuard Brand Monitoring Engine
Real-time brand threat intelligence across 10+ sources.

Monitors:
  - Phishing & typosquat sites (crt.sh, dnstwist, VT, PhishTank, URLhaus)
  - Data breaches & credential leaks (HIBP, LeakIX, DeHashed)
  - Dark web & paste mentions (OTX, URLhaus)
  - GitHub secret leaks (GitHub search API)
  - Fake mobile apps & impersonation (OTX, VT)
  - Infrastructure changes (DNS, SSL, ports, AbuseIPDB, Shodan, CriminalIP)

Usage:
  from scanner.brand_monitor import run_brand_scan
  result = run_brand_scan("flipkart", domain="flipkart.com")
"""

import os
import re
import sys
import json
import time
import socket
import hashlib
import logging
import requests
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Setup ──────────────────────────────────────────────────────────────────────
VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
sys.path.insert(0, str(VORAG_HOME))

log = logging.getLogger("vorag.brand")

# ── Helpers ────────────────────────────────────────────────────────────────────
def _key(env_var: str) -> str:
    """Load API key from environment, strip inline comments."""
    return (os.environ.get(env_var, "") or "").split("#")[0].strip()

def _get(url: str, headers: dict = None, params: dict = None,
         timeout: int = 12) -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers=headers or {}, params=params or {},
                        timeout=timeout)
        return r
    except Exception as e:
        log.debug(f"GET {url} failed: {e}")
        return None

def _post(url: str, json_data: dict = None, timeout: int = 12) -> Optional[requests.Response]:
    try:
        r = requests.post(url, json=json_data or {}, timeout=timeout)
        return r
    except Exception as e:
        log.debug(f"POST {url} failed: {e}")
        return None

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _severity(findings_count: int, critical: int = 0, high: int = 0) -> str:
    if critical > 0:   return "CRITICAL"
    if high > 0:       return "HIGH"
    if findings_count > 5: return "HIGH"
    if findings_count > 2: return "MEDIUM"
    if findings_count > 0: return "LOW"
    return "CLEAN"


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 1: crt.sh — Certificate Transparency Log
# Finds newly issued SSL certs for domains containing the brand name
# This is how attackers register phishing domains — they need a cert first
# ══════════════════════════════════════════════════════════════════════════════
def check_crtsh(brand: str) -> dict:
    """
    Query certificate transparency logs for domains containing brand name.
    crt.sh indexes all publicly issued SSL certs — real-time, no API key needed.
    """
    log.info(f"[crt.sh] Searching certificate transparency for '{brand}'...")
    result = {
        "source": "crt.sh",
        "source_label": "Certificate Transparency (crt.sh)",
        "brand": brand,
        "checked_at": _now(),
        "total_certs": 0,
        "suspicious_domains": [],
        "all_domains": [],
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    r = _get(
        "https://crt.sh/",
        params={"q": f"%.{brand}.%", "output": "json"},
        timeout=15
    )
    if not r or r.status_code != 200:
        # Try simpler query
        r = _get(f"https://crt.sh/?q={brand}&output=json", timeout=15)
    if not r or r.status_code != 200:
        result["error"] = "crt.sh unreachable"
        return result

    try:
        certs = r.json() if r.content else []
    except Exception:
        result["error"] = "crt.sh invalid JSON"
        return result

    result["available"] = True
    result["total_certs"] = len(certs)

    # Extract unique domains
    domains_seen = set()
    suspicious = []
    all_domains = []

    # Suspicious patterns — brand name combined with deceptive keywords
    phish_keywords = [
        "login", "secure", "account", "verify", "update", "confirm",
        "support", "help", "wallet", "pay", "payment", "bank", "signin",
        "auth", "password", "reset", "unlock", "suspend", "alert",
        "official", "admin", "free", "offer", "prize", "winner",
        "india", "app", "mobile", "download", "apk", "customer"
    ]

    for cert in certs[:500]:  # limit to 500 most recent
        name = (cert.get("name_value") or "").lower().replace("\\n", "\n")
        for domain in name.split("\n"):
            domain = domain.strip().lstrip("*.")
            if not domain or domain in domains_seen:
                continue
            domains_seen.add(domain)

            # Skip the legitimate brand domain itself
            if domain == f"{brand}.com" or domain == f"www.{brand}.com":
                continue
            if brand.lower() not in domain:
                continue

            all_domains.append({
                "domain": domain,
                "issued_at": cert.get("not_before", ""),
                "issuer": cert.get("issuer_name", ""),
                "cert_id": cert.get("id", ""),
            })

            # Check if suspicious
            for kw in phish_keywords:
                if kw in domain:
                    suspicious.append({
                        "domain": domain,
                        "reason": f"Brand + suspicious keyword '{kw}'",
                        "issued_at": cert.get("not_before", "")[:10],
                        "issuer": cert.get("issuer_name", "")[:60],
                        "risk": "HIGH",
                        "cert_url": f"https://crt.sh/?id={cert.get('id','')}",
                    })
                    result["findings"].append({
                        "title": f"Suspicious cert issued: {domain}",
                        "detail": f"SSL certificate issued for domain containing '{brand}' + '{kw}' — potential phishing setup",
                        "severity": "HIGH",
                        "source": "crt.sh",
                        "indicator": domain,
                        "action": f"Investigate {domain} — request takedown if phishing confirmed",
                    })
                    break

    result["suspicious_domains"] = suspicious[:50]
    result["all_domains"] = all_domains[:100]
    result["severity"] = _severity(len(suspicious), high=len(suspicious))

    log.info(f"[crt.sh] {len(all_domains)} domains found | {len(suspicious)} suspicious")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 2: VirusTotal — Brand URL / Domain Reputation
# ══════════════════════════════════════════════════════════════════════════════
def check_vt_brand(brand: str, domain: str) -> dict:
    """Check VirusTotal for brand-related phishing URLs and domain reputation."""
    log.info(f"[VT] Checking VirusTotal for brand '{brand}'...")
    result = {
        "source": "virustotal",
        "source_label": "VirusTotal",
        "brand": brand,
        "checked_at": _now(),
        "domain_malicious": 0,
        "domain_suspicious": 0,
        "domain_clean": True,
        "phishing_urls": [],
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    api_key = _key("VT_API_KEY")
    if not api_key:
        result["error"] = "VT_API_KEY not configured"
        return result

    headers = {"x-apikey": api_key}

    # Check primary domain
    r = _get(f"https://www.virustotal.com/api/v3/domains/{domain}",
             headers=headers, timeout=15)
    if r and r.status_code == 200:
        result["available"] = True
        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        result["domain_malicious"] = malicious
        result["domain_suspicious"] = suspicious
        result["domain_clean"] = malicious == 0

        if malicious > 0:
            result["findings"].append({
                "title": f"VT: {malicious} engines flag {domain} as MALICIOUS",
                "detail": f"Malicious: {malicious} | Suspicious: {suspicious} | Total engines: {stats.get('harmless',0)+malicious+suspicious}",
                "severity": "CRITICAL",
                "source": "VirusTotal",
                "indicator": domain,
                "action": "Immediate investigation required — domain flagged as malicious by AV engines",
            })

    # Search VT for brand-related phishing URLs
    r2 = _get(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        params={"filter": f"tag:phishing url:{brand}"},
        timeout=15
    )
    # Note: VT URL search requires premium. We use domain search instead.
    # Check known phishing variants
    phish_variants = [
        f"{brand}-login.com", f"{brand}-secure.com", f"secure-{brand}.com",
        f"{brand}-verify.com", f"{brand}account.com", f"{brand}-support.com",
        f"{brand}-pay.com", f"pay{brand}.com", f"{brand}wallet.com",
    ]

    for variant in phish_variants[:5]:  # limit API calls
        rv = _get(f"https://www.virustotal.com/api/v3/domains/{variant}",
                  headers=headers, timeout=10)
        if rv and rv.status_code == 200:
            dv = rv.json().get("data", {}).get("attributes", {})
            sv = dv.get("last_analysis_stats", {})
            mal = sv.get("malicious", 0)
            if mal > 0:
                result["phishing_urls"].append({
                    "domain": variant,
                    "malicious_engines": mal,
                    "risk": "CRITICAL" if mal > 5 else "HIGH",
                })
                result["findings"].append({
                    "title": f"Phishing domain confirmed: {variant}",
                    "detail": f"{mal} AV engines confirm this is a phishing domain impersonating {brand}",
                    "severity": "CRITICAL",
                    "source": "VirusTotal",
                    "indicator": variant,
                    "action": f"File DMCA/abuse report. Request takedown via registrar and hosting provider.",
                })
        time.sleep(0.3)  # VT rate limit: 4 req/min free

    result["severity"] = _severity(
        len(result["findings"]),
        critical=result["domain_malicious"]
    )
    log.info(f"[VT] Domain: {'MALICIOUS' if not result['domain_clean'] else 'clean'} | {len(result['phishing_urls'])} phishing variants")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 3: AlienVault OTX — Threat Intelligence Pulses
# ══════════════════════════════════════════════════════════════════════════════
def check_otx_brand(brand: str, domain: str) -> dict:
    """Search OTX for brand-related threat pulses, malware, IOCs."""
    log.info(f"[OTX] Searching AlienVault OTX for brand '{brand}'...")
    result = {
        "source": "otx",
        "source_label": "AlienVault OTX",
        "brand": brand,
        "checked_at": _now(),
        "pulse_count": 0,
        "malware_families": [],
        "threat_actors": [],
        "iocs": [],
        "pulses": [],
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    api_key = _key("OTX_API_KEY")
    if not api_key:
        result["error"] = "OTX_API_KEY not configured"
        return result

    headers = {"X-OTX-API-KEY": api_key}

    # Search pulses mentioning brand
    r = _get(
        "https://otx.alienvault.com/api/v1/search/pulses",
        headers=headers,
        params={"q": brand, "limit": 10, "page": 1},
        timeout=15
    )

    pulses = []
    if r and r.status_code == 200:
        result["available"] = True
        data = r.json()
        pulses = data.get("results", [])
        result["pulse_count"] = data.get("count", len(pulses))

        malware_set = set()
        actor_set = set()
        ioc_list = []

        for pulse in pulses[:10]:
            pulse_info = {
                "name": pulse.get("name", ""),
                "description": (pulse.get("description", "") or "")[:200],
                "created": pulse.get("created", "")[:10],
                "author": pulse.get("author_name", ""),
                "tags": pulse.get("tags", [])[:5],
                "tlp": pulse.get("tlp", "white"),
                "targeted_countries": pulse.get("targeted_countries", []),
                "malware_families": pulse.get("malware_families", []),
            }
            pulses_info_list = result.get("pulses", [])
            pulses_info_list.append(pulse_info)
            result["pulses"] = pulses_info_list

            for mf in pulse.get("malware_families", []):
                malware_set.add(mf)

            # Extract IOCs
            for indicator in pulse.get("indicators", [])[:5]:
                ioc_list.append({
                    "type":  indicator.get("type", ""),
                    "value": indicator.get("indicator", ""),
                    "pulse": pulse.get("name", ""),
                })

            if result["pulse_count"] > 0:
                result["findings"].append({
                    "title": f"OTX: {result['pulse_count']} threat pulse(s) mentioning '{brand}'",
                    "detail": f"Latest: '{pulse.get('name','')}' by {pulse.get('author_name','')} on {pulse.get('created','')[:10]}",
                    "severity": "HIGH" if result["pulse_count"] > 3 else "MEDIUM",
                    "source": "AlienVault OTX",
                    "indicator": brand,
                    "action": "Review OTX pulses for IOCs — block flagged IPs/domains at perimeter",
                })
                break  # one finding for all pulses

        result["malware_families"] = list(malware_set)
        result["iocs"] = ioc_list[:20]

    # Also check domain directly
    r2 = _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers=headers, timeout=12
    )
    if r2 and r2.status_code == 200:
        result["available"] = True
        d2 = r2.json()
        domain_pulses = d2.get("pulse_info", {}).get("count", 0)
        if domain_pulses > 0 and domain_pulses > result["pulse_count"]:
            result["findings"].append({
                "title": f"OTX: Domain {domain} appears in {domain_pulses} threat pulse(s)",
                "detail": "Your primary domain is referenced in threat intelligence feeds",
                "severity": "HIGH",
                "source": "AlienVault OTX",
                "indicator": domain,
                "action": "Investigate why your domain appears in threat feeds — check for compromise",
            })

    result["severity"] = _severity(
        len(result["findings"]),
        high=len(result["findings"])
    )
    log.info(f"[OTX] {result['pulse_count']} pulses | {len(result['malware_families'])} malware families")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 4: URLhaus + PhishTank — Live Phishing & Malware URL Feeds
# ══════════════════════════════════════════════════════════════════════════════
def check_urlhaus_phishtank(brand: str, domain: str) -> dict:
    """Check URLhaus and PhishTank for brand-related malicious URLs."""
    log.info(f"[URLhaus/PhishTank] Checking live phishing feeds for '{brand}'...")
    result = {
        "source": "urlhaus_phishtank",
        "source_label": "URLhaus + PhishTank",
        "brand": brand,
        "checked_at": _now(),
        "urlhaus_hits": [],
        "phishtank_hits": [],
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    # URLhaus — check domain
    r = _post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        json_data={"host": domain},
        timeout=12
    )
    if r and r.status_code == 200:
        result["available"] = True
        d = r.json()
        if d.get("query_status") == "is_host":
            urls = d.get("urls", [])
            active = [u for u in urls if u.get("url_status") == "online"]
            result["urlhaus_hits"] = [{
                "url": u.get("url", ""),
                "status": u.get("url_status", ""),
                "tags": u.get("tags", []),
                "threat": u.get("threat", ""),
                "date_added": u.get("date_added", "")[:10],
            } for u in urls[:10]]

            if urls:
                result["findings"].append({
                    "title": f"URLhaus: {len(urls)} malicious URL(s) on {domain} ({len(active)} active)",
                    "detail": f"Your domain is serving malware/phishing URLs. Active: {len(active)}",
                    "severity": "CRITICAL" if active else "HIGH",
                    "source": "URLhaus",
                    "indicator": domain,
                    "action": "IMMEDIATE: Domain is serving malware. Contact hosting provider. Take domain offline if compromised.",
                })

    # PhishTank — check domain
    r2 = _post(
        "https://checkurl.phishtank.com/checkurl/",
        json_data={
            "url": f"https://{domain}",
            "format": "json",
            "app_key": "",  # PhishTank allows anonymous but limited
        },
        timeout=12
    )
    if r2 and r2.status_code == 200:
        try:
            d2 = r2.json()
            if d2.get("results", {}).get("in_database"):
                is_phish = d2["results"].get("valid")
                result["phishtank_hits"].append({
                    "url": f"https://{domain}",
                    "is_phishing": is_phish,
                    "verified": d2["results"].get("verified"),
                })
                if is_phish:
                    result["findings"].append({
                        "title": f"PhishTank: {domain} confirmed as PHISHING site",
                        "detail": "Domain is in PhishTank database and verified as a phishing page",
                        "severity": "CRITICAL",
                        "source": "PhishTank",
                        "indicator": domain,
                        "action": "CRITICAL: Report to registrar, Google Safe Browsing, and hosting provider immediately",
                    })
        except Exception:
            pass

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL")
    )
    log.info(f"[URLhaus/PhishTank] {len(result['urlhaus_hits'])} URLhaus | {len(result['phishtank_hits'])} PhishTank")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 5: HIBP + LeakIX + DeHashed — Breach & Credential Intelligence
# ══════════════════════════════════════════════════════════════════════════════
def check_breach_intel(brand: str, domain: str) -> dict:
    """Check HIBP, LeakIX and DeHashed for brand credential leaks."""
    log.info(f"[BreachIntel] Checking breach databases for '{brand}'...")
    result = {
        "source": "breach_intel",
        "source_label": "HIBP + LeakIX + DeHashed",
        "brand": brand,
        "checked_at": _now(),
        "hibp_breaches": [],
        "leakix_leaks": [],
        "dehashed_hits": 0,
        "total_exposed_accounts": 0,
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    # ── HIBP ──────────────────────────────────────────────────────────────────
    hibp_key = _key("HIBP_API_KEY")
    if hibp_key:
        r = _get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers={"hibp-api-key": hibp_key, "user-agent": "VoraGuard-v3"},
            timeout=15
        )
        if r and r.status_code == 200:
            result["available"] = True
            all_breaches = r.json()
            # Filter breaches mentioning the brand or domain
            brand_breaches = [
                b for b in all_breaches
                if brand.lower() in b.get("Name", "").lower()
                or brand.lower() in b.get("Domain", "").lower()
                or domain.lower() in b.get("Domain", "").lower()
            ]
            for b in brand_breaches:
                result["hibp_breaches"].append({
                    "name": b.get("Name", ""),
                    "domain": b.get("Domain", ""),
                    "breach_date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                    "description": (b.get("Description", "") or "")[:200],
                })
                result["total_exposed_accounts"] += b.get("PwnCount", 0)

            if brand_breaches:
                result["findings"].append({
                    "title": f"HIBP: {len(brand_breaches)} data breach(es) linked to '{brand}'",
                    "detail": f"Total exposed accounts: {result['total_exposed_accounts']:,} | Breaches: {', '.join(b['name'] for b in brand_breaches[:3])}",
                    "severity": "CRITICAL" if result["total_exposed_accounts"] > 10000 else "HIGH",
                    "source": "HaveIBeenPwned",
                    "indicator": domain,
                    "action": "Notify affected users. Force password resets. Investigate breach scope.",
                })
    else:
        result["hibp_note"] = "HIBP_API_KEY not set ($3.50/mo at haveibeenpwned.com)"

    # ── LeakIX ────────────────────────────────────────────────────────────────
    leakix_key = _key("LEAKIX_API_KEY")
    if leakix_key:
        r2 = _get(
            "https://leakix.net/search",
            headers={"api-key": leakix_key, "Accept": "application/json"},
            params={"scope": "leak", "q": f"host:{domain}"},
            timeout=15
        )
        if r2 and r2.status_code in (200, 206):
            result["available"] = True
            leaks = r2.json() or []
            if isinstance(leaks, list):
                result["leakix_leaks"] = [{
                    "host": lk.get("host", ""),
                    "port": lk.get("port", ""),
                    "plugin": lk.get("event_source", ""),
                    "severity": lk.get("severity", ""),
                    "summary": (lk.get("summary", "") or "")[:150],
                    "date": (lk.get("time", "") or "")[:10],
                } for lk in leaks[:10]]

                if leaks:
                    result["findings"].append({
                        "title": f"LeakIX: {len(leaks)} exposed service(s) detected on {domain}",
                        "detail": f"LeakIX found exposed/misconfigured services. Services: {', '.join(set(lk.get('event_source','') for lk in leaks[:5]))}",
                        "severity": "HIGH",
                        "source": "LeakIX",
                        "indicator": domain,
                        "action": "Investigate and remediate exposed services immediately",
                    })

    # ── DeHashed ──────────────────────────────────────────────────────────────
    dh_email = _key("DEHASHED_EMAIL")
    dh_key   = _key("DEHASHED_API_KEY")
    if dh_email and dh_key:
        r3 = _get(
            "https://api.dehashed.com/search",
            headers={"Accept": "application/json"},
            params={"query": f"domain:{domain}", "size": 10},
            timeout=15
        )
        if r3 and r3.status_code == 200:
            result["available"] = True
            dh_data = r3.json()
            total = dh_data.get("total", 0)
            result["dehashed_hits"] = total
            if total > 0:
                result["total_exposed_accounts"] += total
                result["findings"].append({
                    "title": f"DeHashed: {total:,} credential records found for {domain}",
                    "detail": f"Leaked credentials matching your domain found in breach databases",
                    "severity": "CRITICAL" if total > 100 else "HIGH",
                    "source": "DeHashed",
                    "indicator": domain,
                    "action": "Force password resets for all affected accounts. Enable MFA.",
                })

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
        high=sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
    )
    log.info(f"[BreachIntel] {len(result['hibp_breaches'])} HIBP | {len(result['leakix_leaks'])} LeakIX | {result['dehashed_hits']} DeHashed")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 6: GitHub — Secret & Code Leak Detection
# ══════════════════════════════════════════════════════════════════════════════
def check_github_leaks(brand: str, domain: str) -> dict:
    """Search GitHub public repos for leaked secrets, API keys, credentials."""
    log.info(f"[GitHub] Searching for leaked code/secrets for '{brand}'...")
    result = {
        "source": "github",
        "source_label": "GitHub Public Search",
        "brand": brand,
        "checked_at": _now(),
        "leaked_repos": [],
        "secret_hits": [],
        "total_hits": 0,
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    gh_token = _key("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "VoraGuard-BrandMonitor",
    }
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    # Search patterns that indicate leaked secrets
    search_queries = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{brand}" leaked',
        f'"{brand}" credentials',
    ]

    all_hits = []
    for query in search_queries[:3]:  # limit to 3 to avoid rate limit
        r = _get(
            "https://api.github.com/search/code",
            headers=headers,
            params={"q": query, "per_page": 5, "sort": "indexed"},
            timeout=15
        )
        if not r:
            continue
        if r.status_code == 403:
            result["error"] = "GitHub rate limited — add GITHUB_TOKEN for higher limits"
            break
        if r.status_code == 200:
            result["available"] = True
            items = r.json().get("items", [])
            for item in items:
                repo = item.get("repository", {})
                hit = {
                    "file": item.get("name", ""),
                    "path": item.get("path", ""),
                    "repo": repo.get("full_name", ""),
                    "repo_url": repo.get("html_url", ""),
                    "file_url": item.get("html_url", ""),
                    "query_matched": query,
                    "repo_private": repo.get("private", False),
                    "pushed_at": repo.get("pushed_at", "")[:10],
                }
                if hit["repo"] not in [h["repo"] for h in all_hits]:
                    all_hits.append(hit)

        time.sleep(1)  # GitHub rate limit: 10 req/min unauthenticated

    result["total_hits"] = len(all_hits)
    result["leaked_repos"] = all_hits[:20]

    if all_hits:
        severity = "HIGH" if len(all_hits) > 3 else "MEDIUM"
        result["findings"].append({
            "title": f"GitHub: {len(all_hits)} public repo(s) contain references to '{brand}'/'{domain}'",
            "detail": f"Repos: {', '.join(h['repo'] for h in all_hits[:3])}",
            "severity": severity,
            "source": "GitHub",
            "indicator": brand,
            "action": "Review each repo for leaked API keys, passwords, internal endpoints. Request removal via GitHub DMCA.",
        })

    # Check for brand-specific secret patterns
    secret_queries = [
        f'"{brand}" "api_key" OR "apikey" OR "access_token"',
    ]
    r2 = _get(
        "https://api.github.com/search/code",
        headers=headers,
        params={"q": secret_queries[0], "per_page": 5},
        timeout=15
    )
    if r2 and r2.status_code == 200:
        result["available"] = True
        secret_items = r2.json().get("items", [])
        result["secret_hits"] = [{
            "repo": i.get("repository", {}).get("full_name", ""),
            "file": i.get("name", ""),
            "url": i.get("html_url", ""),
        } for i in secret_items]

        if secret_items:
            result["findings"].append({
                "title": f"GitHub: Possible API key/secret leaks in {len(secret_items)} public repo(s)",
                "detail": f"Code containing '{brand}' + credential keywords found publicly",
                "severity": "CRITICAL",
                "source": "GitHub",
                "indicator": brand,
                "action": "IMMEDIATE: Rotate all exposed API keys. Request GitHub content removal.",
            })

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
        high=sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
    )
    log.info(f"[GitHub] {result['total_hits']} repos | {len(result['secret_hits'])} secret hits")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 7: Shodan + AbuseIPDB + CriminalIP — Infrastructure Intel
# ══════════════════════════════════════════════════════════════════════════════
def check_infra_intel(brand: str, domain: str) -> dict:
    """Check infrastructure threat intelligence for brand domain IPs."""
    log.info(f"[InfraIntel] Checking infrastructure intel for '{domain}'...")
    result = {
        "source": "infra_intel",
        "source_label": "Shodan + AbuseIPDB + CriminalIP",
        "brand": brand,
        "checked_at": _now(),
        "resolved_ips": [],
        "shodan_data": {},
        "abuseipdb_data": {},
        "criminalip_data": {},
        "open_ports": [],
        "cves": [],
        "severity": "CLEAN",
        "available": False,
        "findings": [],
    }

    # Resolve domain to IPs
    try:
        ip = socket.gethostbyname(domain)
        result["resolved_ips"] = [ip]
    except Exception:
        result["error"] = f"Could not resolve {domain}"
        return result

    # ── Shodan ────────────────────────────────────────────────────────────────
    shodan_key = _key("SHODAN_API_KEY")
    if shodan_key and result["resolved_ips"]:
        r = _get(
            f"https://api.shodan.io/shodan/host/{result['resolved_ips'][0]}",
            params={"key": shodan_key},
            timeout=15
        )
        if r and r.status_code == 200:
            result["available"] = True
            sd = r.json()
            ports = sd.get("ports", [])
            vulns = list(sd.get("vulns", {}).keys())
            org = sd.get("org", "")
            result["shodan_data"] = {
                "ports": ports,
                "org": org,
                "os": sd.get("os", ""),
                "cves": vulns[:10],
                "tags": sd.get("tags", []),
            }
            result["open_ports"] = ports
            result["cves"] = vulns

            dangerous_ports = [p for p in ports if p in [21,23,25,3306,5432,27017,6379,9200,2375,4243,5900,3389]]
            if dangerous_ports:
                result["findings"].append({
                    "title": f"Shodan: Dangerous ports exposed: {dangerous_ports}",
                    "detail": f"Org: {org} | Total ports: {len(ports)} | Dangerous: {dangerous_ports}",
                    "severity": "CRITICAL",
                    "source": "Shodan",
                    "indicator": result["resolved_ips"][0],
                    "action": f"Close ports {dangerous_ports} immediately — database/admin ports must not be internet-facing",
                })
            if vulns:
                result["findings"].append({
                    "title": f"Shodan: {len(vulns)} CVE(s) on infrastructure IP",
                    "detail": f"CVEs: {', '.join(vulns[:5])}",
                    "severity": "HIGH" if len(vulns) > 5 else "MEDIUM",
                    "source": "Shodan",
                    "indicator": result["resolved_ips"][0],
                    "action": "Patch vulnerable services. Apply security updates immediately.",
                })

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse_key = _key("ABUSEIPDB_API_KEY")
    if abuse_key and result["resolved_ips"]:
        r2 = _get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": abuse_key, "Accept": "application/json"},
            params={"ipAddress": result["resolved_ips"][0], "maxAgeInDays": 90},
            timeout=12
        )
        if r2 and r2.status_code == 200:
            result["available"] = True
            ad = r2.json().get("data", {})
            confidence = ad.get("abuseConfidenceScore", 0)
            reports = ad.get("totalReports", 0)
            result["abuseipdb_data"] = {
                "confidence": confidence,
                "reports": reports,
                "last_reported": (ad.get("lastReportedAt") or "")[:10] or "Never",
                "categories": ad.get("usageType", ""),
            }
            if confidence > 25:
                result["findings"].append({
                    "title": f"AbuseIPDB: Brand IP {result['resolved_ips'][0]} has {confidence}% abuse confidence",
                    "detail": f"Total reports: {reports} | Last reported: {result['abuseipdb_data']['last_reported']}",
                    "severity": "HIGH" if confidence > 50 else "MEDIUM",
                    "source": "AbuseIPDB",
                    "indicator": result["resolved_ips"][0],
                    "action": "Investigate abuse reports. Check for compromised server or malware.",
                })

    # ── CriminalIP ────────────────────────────────────────────────────────────
    cip_key = _key("CRIMINALIP_API_KEY")
    if cip_key and result["resolved_ips"]:
        r3 = _get(
            f"https://api.criminalip.io/v1/asset/ip/report",
            headers={"x-api-key": cip_key},
            params={"ip": result["resolved_ips"][0]},
            timeout=12
        )
        if r3 and r3.status_code == 200:
            result["available"] = True
            cd = r3.json()
            score = cd.get("score", {})
            attack = score.get("inbound", 0) if isinstance(score, dict) else 0
            result["criminalip_data"] = {
                "attack_score": attack,
                "issues": cd.get("issues", {}),
            }
            if attack > 50:
                result["findings"].append({
                    "title": f"CriminalIP: High inbound attack score ({attack}) on brand IP",
                    "detail": "IP is being actively targeted or involved in malicious activity",
                    "severity": "HIGH",
                    "source": "CriminalIP",
                    "indicator": result["resolved_ips"][0],
                    "action": "Review server security. Check for active intrusion attempts.",
                })

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
        high=sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
    )
    log.info(f"[InfraIntel] {len(result['open_ports'])} ports | {len(result['cves'])} CVEs | {len(result['findings'])} findings")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 8: DNS + SSL Infrastructure Health
# ══════════════════════════════════════════════════════════════════════════════
def check_dns_ssl_health(brand: str, domain: str) -> dict:
    """Check DNS and SSL health of brand infrastructure."""
    log.info(f"[DNS/SSL] Checking infrastructure health for '{domain}'...")
    result = {
        "source": "dns_ssl",
        "source_label": "DNS + SSL Infrastructure",
        "brand": brand,
        "checked_at": _now(),
        "dns": {},
        "ssl": {},
        "severity": "CLEAN",
        "available": True,
        "findings": [],
    }

    try:
        from scanner.intelligence import check_dns_health, check_ssl
        dns = check_dns_health(domain)
        ssl = check_ssl(domain)

        result["dns"] = {
            "ips": dns.get("ip_addresses", []),
            "spf_present": dns.get("spf", {}).get("present", False),
            "spf_record": dns.get("spf", {}).get("record", ""),
            "dmarc_present": dns.get("dmarc", {}).get("present", False),
            "dmarc_record": dns.get("dmarc", {}).get("record", ""),
            "mx_records": dns.get("mx", {}).get("records", []),
        }
        result["ssl"] = {
            "valid": ssl.get("valid", False),
            "expires_in_days": ssl.get("expires_in_days"),
            "issuer": ssl.get("issuer", ""),
            "protocol": ssl.get("protocol", ""),
        }

        if not result["dns"]["spf_present"]:
            result["findings"].append({
                "title": f"SPF record missing on {domain}",
                "detail": "Anyone can send spoofed emails from your domain — phishing risk",
                "severity": "HIGH",
                "source": "DNS Check",
                "indicator": domain,
                "action": "Add SPF TXT record: v=spf1 include:_spf.yourmailprovider.com ~all",
            })
        if not result["dns"]["dmarc_present"]:
            result["findings"].append({
                "title": f"DMARC record missing on {domain}",
                "detail": "Email spoofing attacks are undetectable without DMARC",
                "severity": "HIGH",
                "source": "DNS Check",
                "indicator": domain,
                "action": "Add DMARC TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
            })
        if not result["ssl"]["valid"]:
            result["findings"].append({
                "title": f"SSL certificate invalid or missing on {domain}",
                "detail": "Traffic to your domain is unencrypted or certificate is untrusted",
                "severity": "CRITICAL",
                "source": "SSL Check",
                "indicator": domain,
                "action": "Install valid SSL certificate immediately. Use Let's Encrypt (free).",
            })
        elif result["ssl"]["expires_in_days"] and result["ssl"]["expires_in_days"] < 30:
            days = result["ssl"]["expires_in_days"]
            result["findings"].append({
                "title": f"SSL certificate expires in {days} days on {domain}",
                "detail": f"Issuer: {result['ssl']['issuer']}",
                "severity": "CRITICAL" if days < 7 else "WARNING",
                "source": "SSL Check",
                "indicator": domain,
                "action": "Renew SSL certificate immediately to avoid service disruption",
            })

    except Exception as e:
        result["error"] = str(e)

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
        high=sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
    )
    log.info(f"[DNS/SSL] {len(result['findings'])} findings")
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 9: Fake App & Social Impersonation Detection
# ══════════════════════════════════════════════════════════════════════════════
def check_fake_apps_impersonation(brand: str, domain: str) -> dict:
    """
    Detect fake mobile apps and social media impersonation via OTX + VT + crt.sh.
    True fake app store detection requires paid services (Recorded Future, etc).
    This uses available free sources intelligently.
    """
    log.info(f"[FakeApps] Checking for fake apps/impersonation of '{brand}'...")
    result = {
        "source": "fake_apps",
        "source_label": "Fake Apps & Impersonation Detection",
        "brand": brand,
        "checked_at": _now(),
        "suspicious_apk_domains": [],
        "impersonation_indicators": [],
        "severity": "CLEAN",
        "available": True,
        "findings": [],
        "note": "Checks crt.sh + VT for app-distribution domains. Full app store monitoring requires Recorded Future/Flashpoint.",
    }

    api_key = _key("VT_API_KEY")
    headers = {"x-apikey": api_key} if api_key else {}

    # APK / fake app distribution patterns
    app_patterns = [
        f"{brand}-app.com", f"{brand}app.com", f"{brand}-apk.com",
        f"download-{brand}.com", f"{brand}-download.com",
        f"{brand}-android.com", f"{brand}-ios.com",
        f"get{brand}.com", f"{brand}official.com",
        f"{brand}-update.com", f"{brand}mod.com",
    ]

    # Check these domains in VT
    suspicious_found = []
    for app_domain in app_patterns[:6]:
        if api_key:
            r = _get(
                f"https://www.virustotal.com/api/v3/domains/{app_domain}",
                headers=headers, timeout=10
            )
            if r and r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                if mal > 0 or d.get("last_dns_records"):
                    # Domain is registered
                    suspicious_found.append({
                        "domain": app_domain,
                        "malicious_engines": mal,
                        "registered": bool(d.get("last_dns_records")),
                        "risk": "CRITICAL" if mal > 3 else "HIGH" if mal > 0 else "MEDIUM",
                    })
            time.sleep(0.4)

    result["suspicious_apk_domains"] = suspicious_found

    if suspicious_found:
        critical_count = sum(1 for s in suspicious_found if s["risk"] == "CRITICAL")
        result["findings"].append({
            "title": f"Fake app distribution domains found: {len(suspicious_found)} domain(s) impersonating '{brand}'",
            "detail": f"Domains: {', '.join(s['domain'] for s in suspicious_found[:5])}",
            "severity": "CRITICAL" if critical_count > 0 else "HIGH",
            "source": "Fake App Detection",
            "indicator": brand,
            "action": "File abuse reports with registrars. Alert users via official channels. Submit to Google Safe Browsing.",
        })

    # Check crt.sh for app-related certificates
    r_crt = _get(
        "https://crt.sh/",
        params={"q": f"%{brand}%app%", "output": "json"},
        timeout=12
    )
    if r_crt and r_crt.status_code == 200:
        try:
            certs = r_crt.json() or []
            app_certs = [c for c in certs if any(
                kw in (c.get("name_value") or "").lower()
                for kw in ["apk", "app", "android", "download", "install"]
            )]
            if app_certs:
                result["impersonation_indicators"].append({
                    "type": "ssl_cert",
                    "count": len(app_certs),
                    "note": f"{len(app_certs)} SSL certs issued for app-themed domains containing '{brand}'",
                })
                result["findings"].append({
                    "title": f"crt.sh: {len(app_certs)} SSL cert(s) for fake '{brand}' app domains",
                    "detail": "Attackers registered app-themed domains and obtained SSL certs — likely fake app distribution",
                    "severity": "HIGH",
                    "source": "Certificate Transparency",
                    "indicator": brand,
                    "action": "Monitor these domains. Report to Google Play Protect and Apple App Store.",
                })
        except Exception:
            pass

    result["severity"] = _severity(
        len(result["findings"]),
        critical=sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
        high=sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
    )
    log.info(f"[FakeApps] {len(suspicious_found)} suspicious | {len(result['impersonation_indicators'])} indicators")
    return result



# ══════════════════════════════════════════════════════════════════════════════
# SOURCE 10: Google Safe Browsing API
# Real-time check if URLs/domains are flagged as phishing, malware, unwanted
# The same database Google Chrome uses to warn users
# ══════════════════════════════════════════════════════════════════════════════
def check_google_safe_browsing(brand: str, domain: str) -> dict:
    """
    Query Google Safe Browsing API v4 for brand domain + phishing variants.
    Returns REAL-TIME threat assessment from Google's threat database.
    Used by Chrome, Firefox, Safari to protect 4 billion users.

    Free tier: 10,000 requests/day
    Get key: console.cloud.google.com → APIs → Safe Browsing API
    """
    log.info(f"[GSB] Checking Google Safe Browsing for \'{brand}\'...")
    result = {
        "source":       "google_safe_browsing",
        "source_label": "Google Safe Browsing",
        "brand":        brand,
        "checked_at":   _now(),
        "urls_checked": 0,
        "threats_found": [],
        "severity":     "CLEAN",
        "available":    False,
        "findings":     [],
    }

    api_key = _key("GOOGLE_SAFE_BROWSING_KEY")
    if not api_key:
        result["error"] = (
            "GOOGLE_SAFE_BROWSING_KEY not set.\n"
            "Get free key: console.cloud.google.com → APIs & Services → "
            "Enable Safe Browsing API → Credentials → Create API Key.\n"
            "Then: vorag keys set GOOGLE_SAFE_BROWSING_KEY YOUR_KEY"
        )
        return result

    # Build list of URLs to check:
    # 1. The brand's own domain (check if it's been flagged/compromised)
    # 2. Known phishing patterns using brand name
    # 3. Suspicious domains found by crt.sh (passed via brand name patterns)
    urls_to_check = [
        f"https://{domain}",
        f"http://{domain}",
        f"https://www.{domain}",
        # Common phishing patterns
        f"https://{brand}-login.com",
        f"https://{brand}-secure.com",
        f"https://secure-{brand}.com",
        f"https://{brand}-verify.com",
        f"https://{brand}account.com",
        f"https://{brand}-support.com",
        f"https://{brand}-pay.com",
        f"https://pay{brand}.com",
        f"https://{brand}wallet.com",
        f"https://{brand}-india.com",
        f"https://{brand}-official.com",
        f"https://login-{brand}.com",
        f"https://{brand}-update.com",
        f"https://{brand}signin.com",
        f"https://{brand}-app.com",
        f"https://download{brand}.com",
        f"https://{brand}apk.com",
        f"https://{brand}-customer.com",
    ]

    result["urls_checked"] = len(urls_to_check)

    # GSB API v4 — threatMatches.find
    # Checks up to 500 URLs per request
    payload = {
        "client": {
            "clientId":      "voraguard",
            "clientVersion": "3.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",   # phishing
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls_to_check],
        }
    }

    r = _post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
        json_data=payload,
        timeout=15
    )

    if not r:
        result["error"] = "Google Safe Browsing API unreachable"
        return result

    if r.status_code == 400:
        result["error"] = f"GSB API error 400 — check API key is valid and Safe Browsing API is enabled"
        return result

    if r.status_code == 403:
        result["error"] = "GSB API key invalid or quota exceeded"
        return result

    if r.status_code != 200:
        result["error"] = f"GSB API returned HTTP {r.status_code}"
        return result

    result["available"] = True
    data = r.json()
    matches = data.get("matches", [])  # empty list = all URLs are SAFE

    if not matches:
        # All clean — this is good news
        log.info(f"[GSB] All {len(urls_to_check)} URLs clean in Google Safe Browsing")
        result["severity"] = "CLEAN"
        return result

    # Process matches
    threat_map = {
        "MALWARE":                      ("CRITICAL", "Malware distribution"),
        "SOCIAL_ENGINEERING":           ("CRITICAL", "Phishing / social engineering"),
        "UNWANTED_SOFTWARE":            ("HIGH",     "Unwanted software distribution"),
        "POTENTIALLY_HARMFUL_APPLICATION": ("HIGH",  "Potentially harmful app"),
    }

    for match in matches:
        url        = match.get("threat", {}).get("url", "")
        threat_type = match.get("threatType", "")
        platform   = match.get("platformType", "")
        sev, label = threat_map.get(threat_type, ("HIGH", threat_type))

        result["threats_found"].append({
            "url":          url,
            "threat_type":  threat_type,
            "threat_label": label,
            "platform":     platform,
            "severity":     sev,
        })

        # Is it the brand's OWN domain flagged?
        own_domain_hit = domain in url

        result["findings"].append({
            "title": (
                f"GSB: YOUR domain {domain} is FLAGGED by Google Safe Browsing as {label}"
                if own_domain_hit else
                f"GSB: Phishing domain flagged — {url}"
            ),
            "detail": (
                f"Google Chrome is currently warning users about this URL. "
                f"Threat: {label} | Platform: {platform} | URL: {url}"
            ),
            "severity": "CRITICAL" if own_domain_hit else sev,
            "source":   "Google Safe Browsing",
            "indicator": url,
            "action": (
                "CRITICAL: Your domain is blacklisted by Google. "
                "Submit removal request: search.google.com/search-console/security-issues"
                if own_domain_hit else
                f"Report phishing domain to registrar and Google. "
                f"Alert users: do not visit {url}"
            ),
        })

    result["severity"] = _severity(
        len(result["threats_found"]),
        critical=sum(1 for t in result["threats_found"] if t["severity"] == "CRITICAL"),
        high=sum(1 for t in result["threats_found"] if t["severity"] == "HIGH"),
    )

    log.info(
        f"[GSB] {len(urls_to_check)} URLs checked | "
        f"{len(matches)} threats found | severity={result['severity']}"
    )
    return result

# ══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR — run_brand_scan()
# ══════════════════════════════════════════════════════════════════════════════
def run_brand_scan(brand: str, domain: str = None, output_dir: str = None) -> dict:
    """
    Run complete brand monitoring scan across all intelligence sources.

    Args:
        brand:      Brand name (e.g. "flipkart", "techbyheartacademy")
        domain:     Primary domain (e.g. "flipkart.com") — auto-derived if not given
        output_dir: Where to save results (auto-created if not given)

    Returns:
        Complete brand intelligence report dict
    """
    brand = brand.lower().strip()
    if not domain:
        domain = f"{brand}.com"
    domain = domain.lower().strip()

    scan_id   = datetime.now().strftime("%Y%m%d_%H%M%S")
    started   = datetime.now(timezone.utc)

    if not output_dir:
        base = VORAG_HOME / "scans"
        base.mkdir(parents=True, exist_ok=True)
        output_dir = str(base / f"brand_{brand}_{scan_id}")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    log.info(f"[BrandScan] Starting brand monitoring for '{brand}' ({domain})")

    report = {
        "scan_type":    "brand_monitor",
        "brand":        brand,
        "domain":       domain,
        "scan_id":      scan_id,
        "started_at":   started.isoformat(),
        "completed_at": None,
        "duration_s":   0,
        "output_dir":   output_dir,
        "overall_severity": "CLEAN",
        "overall_score": 0,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "sources_checked": 0,
        "sources_with_findings": 0,
        "executive_summary": "",
        "all_findings": [],
        "sources": {},
    }

    # ── Run all sources ───────────────────────────────────────────────────────
    source_runners = [
        ("crt_sh",        lambda: check_crtsh(brand)),
        ("virustotal",    lambda: check_vt_brand(brand, domain)),
        ("otx",           lambda: check_otx_brand(brand, domain)),
        ("urlhaus",       lambda: check_urlhaus_phishtank(brand, domain)),
        ("breach_intel",  lambda: check_breach_intel(brand, domain)),
        ("github",        lambda: check_github_leaks(brand, domain)),
        ("infra_intel",   lambda: check_infra_intel(brand, domain)),
        ("dns_ssl",       lambda: check_dns_ssl_health(brand, domain)),
        ("fake_apps",     lambda: check_fake_apps_impersonation(brand, domain)),
        ("google_safebrowsing", lambda: check_google_safe_browsing(brand, domain)),
    ]

    for source_key, runner in source_runners:
        try:
            src_result = runner()
            report["sources"][source_key] = src_result
            findings = src_result.get("findings", [])
            report["all_findings"].extend(findings)
            if findings:
                report["sources_with_findings"] += 1
            if src_result.get("available"):
                report["sources_checked"] += 1
        except Exception as e:
            log.error(f"[BrandScan] Source {source_key} failed: {e}")
            report["sources"][source_key] = {
                "error": str(e), "findings": [], "available": False
            }

    # ── Aggregate scoring ─────────────────────────────────────────────────────
    all_findings = report["all_findings"]
    crit  = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high  = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    med   = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    low   = sum(1 for f in all_findings if f.get("severity") == "LOW")

    report["critical_count"] = crit
    report["high_count"]     = high
    report["medium_count"]   = med
    report["total_findings"] = len(all_findings)

    # Score: 100 = clean, 0 = everything on fire
    score = 100
    score -= crit  * 20
    score -= high  * 10
    score -= med   * 5
    score -= low   * 2
    score = max(0, min(100, score))
    report["overall_score"] = score

    if crit > 0:      sev = "CRITICAL"
    elif high > 0:    sev = "HIGH"
    elif med > 0:     sev = "MEDIUM"
    elif low > 0:     sev = "LOW"
    else:             sev = "CLEAN"
    report["overall_severity"] = sev

    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    report["all_findings"].sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

    # Executive summary
    report["executive_summary"] = _build_brand_summary(report)

    # Timing
    completed = datetime.now(timezone.utc)
    report["completed_at"]  = completed.isoformat()
    report["duration_s"]    = round((completed - started).total_seconds(), 1)

    # Save JSON
    json_path = Path(output_dir) / "brand-report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str))
    report["json_path"] = str(json_path)

    log.info(
        f"[BrandScan] Complete | score={score}/100 | severity={sev} | "
        f"findings={len(all_findings)} ({crit}C {high}H {med}M) | "
        f"{report['duration_s']}s"
    )
    return report


def _build_brand_summary(report: dict) -> str:
    brand  = report["brand"]
    domain = report["domain"]
    crit   = report["critical_count"]
    high   = report["high_count"]
    total  = report["total_findings"]
    sev    = report["overall_severity"]
    score  = report["overall_score"]
    sources = report["sources_checked"]

    if total == 0:
        return (
            f"Brand '{brand}' ({domain}) shows no detected threats across {sources} intelligence sources. "
            f"Brand posture: CLEAN with a score of {score}/100. "
            f"Continue monitoring — brand threats can emerge rapidly."
        )

    summary = (
        f"Brand monitoring for '{brand}' ({domain}) detected {total} threat indicator(s) "
        f"across {sources} intelligence sources. "
    )
    if crit > 0:
        summary += f"CRITICAL: {crit} issue(s) require immediate action. "
    if high > 0:
        summary += f"{high} HIGH severity finding(s) need urgent attention. "

    # Highlight top threats
    top = [f for f in report["all_findings"] if f.get("severity") in ("CRITICAL", "HIGH")][:3]
    if top:
        summary += f"Key threats: {'; '.join(t['title'] for t in top)}. "

    summary += f"Overall brand risk score: {score}/100 [{sev}]."
    return summary
