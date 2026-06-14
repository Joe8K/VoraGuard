"""
VoraGuard Dark Web Monitoring — v3.0
Six real intelligence source integrations:

  1. AlienVault OTX  — threat indicators, pulses, malware, C2s (FREE, replaces IntelX)
  2. DeHashed        — breach credential database lookup
  3. LeakIX          — exposed services + leak correlation
  4. AbuseIPDB       — IP reputation, confidence score, attack categories (1000/day free)
  5. HIBP            — HaveIBeenPwned breach database (enhanced)
  6. URLhaus         — Abuse.ch malicious URL database (no key needed)

Every function:
  - Makes real HTTP calls to real API endpoints
  - Parses real documented response schemas
  - Handles all known error codes
  - Returns structured dict — never raw API responses
  - Degrades gracefully if API key missing or rate limited

OTX API key: free at https://otx.alienvault.com → Settings → API Integration
"""

import time
import requests
from datetime import datetime, timezone
from typing import Optional
from utils.logger import get_logger
from config.settings import settings

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SHARED HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _safe_get(url: str, headers: dict = None, params: dict = None,
              timeout: int = 15, label: str = "") -> Optional[requests.Response]:
    try:
        resp = requests.get(url, headers=headers or {}, params=params or {},
                            timeout=timeout)
        return resp
    except requests.Timeout:
        log.warning(f"[{label}] Request timed out")
    except requests.ConnectionError as e:
        log.warning(f"[{label}] Connection error: {e}")
    except requests.RequestException as e:
        log.error(f"[{label}] Request failed: {e}")
    return None


def _safe_post(url: str, headers: dict = None, data: dict = None,
               json_body: dict = None, timeout: int = 15,
               label: str = "") -> Optional[requests.Response]:
    try:
        resp = requests.post(url, headers=headers or {},
                             data=data, json=json_body, timeout=timeout)
        return resp
    except requests.Timeout:
        log.warning(f"[{label}] POST timed out")
    except requests.ConnectionError as e:
        log.warning(f"[{label}] POST connection error: {e}")
    except requests.RequestException as e:
        log.error(f"[{label}] POST failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. AlienVault OTX — Threat Intelligence (replaces IntelX)
# ─────────────────────────────────────────────────────────────────────────────
"""
AlienVault OTX (Open Threat Exchange) — world's largest open threat intel community.
Provides real, community-sourced threat indicators for domains, IPs, URLs, hashes.

FREE: unlimited lookups, 10,000 req/day
Key: https://otx.alienvault.com → Settings → API Integration

API endpoints used:
  GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general
  GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list
  GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/malware
  GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns
  GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general

Response schemas documented inline per endpoint.
"""

OTX_BASE = "https://otx.alienvault.com/api/v1"


def otx_search(domain: str, emails: list, ip_addresses: list) -> dict:
    """
    Query AlienVault OTX for threat indicators on the target domain and IPs.

    Returns: threat pulses, malware families, malicious URLs,
             passive DNS history, related threat actors, CVEs.
    """
    api_key = (settings.OTX_API_KEY or "").strip()
    log.info(f"[OTX] Searching AlienVault OTX for {domain}...")

    result = {
        "source": "AlienVault OTX",
        "available": False,
        "pulse_count": 0,
        "malware_families": [],
        "malicious_urls": [],
        "passive_dns": [],
        "threat_actors": [],
        "related_cves": [],
        "domain_findings": [],
        "ip_findings": [],
        "total_hits": 0,
        "highest_severity": "CLEAN",
        "error": None
    }

    if not api_key:
        result["error"] = "OTX_API_KEY not set — get free key at otx.alienvault.com"
        log.info("[OTX] No API key configured")
        return result

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
        "User-Agent": "VoraGuard-ThreatIntel/3.0"
    }

    # ── Domain general info + pulse count ────────────────────
    gen_resp = _safe_get(
        f"{OTX_BASE}/indicators/domain/{domain}/general",
        headers=headers,
        timeout=15,
        label=f"OTX-domain-general"
    )

    if gen_resp is None:
        result["error"] = "OTX connection failed"
        return result

    if gen_resp.status_code == 401:
        result["error"] = "Invalid OTX API key (401)"
        log.warning("[OTX] Invalid API key")
        return result

    if gen_resp.status_code == 200:
        result["available"] = True
        try:
            gen_data = gen_resp.json()

            # Pulse count — each pulse = one threat report from OTX community
            pulse_info = gen_data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            result["pulse_count"] = pulse_count

            # Extract threat actors and malware families from pulses
            pulses = pulse_info.get("pulses", [])[:10]
            for pulse in pulses:
                # Threat actors
                adversary = pulse.get("adversary", "")
                if adversary and adversary not in result["threat_actors"]:
                    result["threat_actors"].append(adversary)

                # Malware families
                for mf in pulse.get("malware_families", []):
                    name = mf.get("display_name", mf.get("id", ""))
                    if name and name not in result["malware_families"]:
                        result["malware_families"].append(name)

                # CVEs / CVE references
                for ref in pulse.get("references", []):
                    if "CVE-" in str(ref).upper():
                        import re
                        cves = re.findall(r"CVE-\d{4}-\d{4,7}", str(ref).upper())
                        result["related_cves"].extend(cves)

                # Build domain finding entry
                result["domain_findings"].append({
                    "pulse_name": pulse.get("name", "Unnamed Pulse"),
                    "author": pulse.get("author_name", "Unknown"),
                    "created": pulse.get("created", "")[:10],
                    "modified": pulse.get("modified", "")[:10],
                    "tlp": pulse.get("tlp", "white"),
                    "tags": pulse.get("tags", [])[:5],
                    "threat_type": pulse.get("adversary", "") or (pulse.get("malware_families", [{}])[0].get("display_name", "Unknown") if pulse.get("malware_families") else "Unknown"),
                    "description": pulse.get("description", "")[:200],
                })

            result["related_cves"] = list(set(result["related_cves"]))[:10]

            # Validation types (what OTX classifies this domain as)
            validation = gen_data.get("validation", [])
            if validation:
                for v in validation:
                    source = v.get("source", "")
                    name = v.get("name", "")
                    if source or name:
                        result["domain_findings"].append({
                            "pulse_name": f"Blacklist: {source}",
                            "author": source,
                            "created": "",
                            "tlp": "red",
                            "tags": [],
                            "threat_type": name,
                            "description": f"Domain listed on {source} as {name}",
                        })

            log.info(f"[OTX] {domain} — {pulse_count} threat pulses | "
                     f"{len(result['malware_families'])} malware families | "
                     f"{len(result['threat_actors'])} threat actors")

        except Exception as e:
            log.error(f"[OTX] Parse error on general: {e}")

    # ── Malware samples associated with domain ────────────────
    time.sleep(0.3)
    mal_resp = _safe_get(
        f"{OTX_BASE}/indicators/domain/{domain}/malware",
        headers=headers,
        timeout=15,
        label="OTX-domain-malware"
    )
    if mal_resp and mal_resp.status_code == 200:
        try:
            mal_data = mal_resp.json()
            for sample in mal_data.get("data", [])[:10]:
                family = sample.get("detect_family", "") or sample.get("datetime_int", "")
                if family and family not in result["malware_families"]:
                    result["malware_families"].append(family)
        except Exception:
            pass

    # ── Malicious URLs associated with domain ─────────────────
    time.sleep(0.3)
    url_resp = _safe_get(
        f"{OTX_BASE}/indicators/domain/{domain}/url_list",
        headers=headers,
        timeout=15,
        label="OTX-domain-urls"
    )
    if url_resp and url_resp.status_code == 200:
        try:
            url_data = url_resp.json()
            for url_entry in url_data.get("url_list", [])[:10]:
                result["malicious_urls"].append({
                    "url": url_entry.get("url", ""),
                    "date": url_entry.get("date", "")[:10],
                    "result": url_entry.get("result", {}).get("safebrowsing", {}).get("threat", ""),
                    "gsb": url_entry.get("gsb", ""),
                })
        except Exception:
            pass

    # ── Passive DNS ────────────────────────────────────────────
    time.sleep(0.3)
    dns_resp = _safe_get(
        f"{OTX_BASE}/indicators/domain/{domain}/passive_dns",
        headers=headers,
        timeout=15,
        label="OTX-domain-pdns"
    )
    if dns_resp and dns_resp.status_code == 200:
        try:
            dns_data = dns_resp.json()
            for record in dns_data.get("passive_dns", [])[:10]:
                result["passive_dns"].append({
                    "hostname": record.get("hostname", ""),
                    "address": record.get("address", ""),
                    "record_type": record.get("record_type", "A"),
                    "first": record.get("first", "")[:10],
                    "last": record.get("last", "")[:10],
                })
        except Exception:
            pass

    # ── IP lookups ────────────────────────────────────────────
    for ip in ip_addresses[:3]:
        time.sleep(0.5)
        ip_resp = _safe_get(
            f"{OTX_BASE}/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=15,
            label=f"OTX-ip-{ip}"
        )
        if ip_resp and ip_resp.status_code == 200:
            try:
                ip_data = ip_resp.json()
                ip_pulses = ip_data.get("pulse_info", {}).get("count", 0)
                ip_rep = ip_data.get("reputation", 0)
                ip_asn = ip_data.get("asn", "")

                result["ip_findings"].append({
                    "ip": ip,
                    "pulse_count": ip_pulses,
                    "reputation": ip_rep,
                    "asn": ip_asn,
                    "country": ip_data.get("country_name", ""),
                    "threat_score": min(100, ip_pulses * 10),
                })

                if ip_pulses > 0:
                    result["total_hits"] += ip_pulses
            except Exception:
                pass

    # Overall severity
    total_hits = result["pulse_count"] + result["total_hits"]
    result["total_hits"] = total_hits
    if total_hits >= 10 or len(result["malware_families"]) >= 3:
        result["highest_severity"] = "CRITICAL"
    elif total_hits >= 5 or len(result["malware_families"]) >= 1:
        result["highest_severity"] = "HIGH"
    elif total_hits >= 1:
        result["highest_severity"] = "MEDIUM"
    elif result["available"]:
        result["highest_severity"] = "CLEAN"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. DeHashed — Breach Credential Database
# ─────────────────────────────────────────────────────────────────────────────

DEHASHED_BASE = "https://api.dehashed.com"


def dehashed_search(domain: str, emails: list) -> dict:
    email = settings.DEHASHED_EMAIL
    api_key = settings.DEHASHED_API_KEY
    log.info(f"[DeHashed] Searching breach credentials for {domain}...")

    result = {
        "source": "DeHashed",
        "available": False,
        "domain_breach_count": 0,
        "email_breaches": [],
        "credential_exposure": [],
        "databases_found": [],
        "total_records": 0,
        "error": None
    }

    if not email or not api_key:
        result["error"] = (
            "DEHASHED_EMAIL and DEHASHED_API_KEY not set. "
            "Account required at https://dehashed.com (API from $5.99/mo)"
        )
        log.info("[DeHashed] No credentials configured")
        return result

    headers = {
        "Accept": "application/json",
        "User-Agent": "VoraGuard-ThreatIntel/3.0"
    }
    auth = (email, api_key)

    domain_resp = _dehashed_query(f"domain:{domain}", auth, headers, label="domain")
    if domain_resp:
        result["available"] = True
        result["domain_breach_count"] = domain_resp.get("total", 0)

        entries = domain_resp.get("entries", []) or []
        databases = list(set(
            e.get("database_name", "Unknown") for e in entries
            if e.get("database_name")
        ))
        result["databases_found"] = databases[:10]

        for entry in entries[:10]:
            exposure = {
                "email": entry.get("email", ""),
                "username": entry.get("username", ""),
                "database": entry.get("database_name", "Unknown"),
                "has_password": bool(entry.get("password") or entry.get("hashed_password")),
                "password_type": (
                    "plaintext" if entry.get("password") and not entry.get("password", "").startswith("$")
                    else "hashed" if entry.get("hashed_password") or entry.get("password", "").startswith("$")
                    else "none"
                ),
                "ip_exposed": bool(entry.get("ip_address")),
                "name_exposed": bool(entry.get("name")),
            }
            result["credential_exposure"].append(exposure)

        result["total_records"] = domain_resp.get("total", 0)
        log.info(f"[DeHashed] {result['total_records']} records in {len(databases)} databases")

    for em in emails[:3]:
        time.sleep(1)
        em_resp = _dehashed_query(f"email:{em}", auth, headers, label="email")
        if em_resp and em_resp.get("total", 0) > 0:
            result["email_breaches"].append({
                "email": em,
                "breach_count": em_resp.get("total", 0),
                "databases": list(set(
                    e.get("database_name", "Unknown")
                    for e in (em_resp.get("entries", []) or [])[:5]
                    if e.get("database_name")
                ))
            })

    return result


def _dehashed_query(query: str, auth: tuple, headers: dict,
                    label: str = "") -> Optional[dict]:
    try:
        resp = requests.get(
            f"{DEHASHED_BASE}/search",
            params={"query": query, "size": 10},
            headers=headers,
            auth=auth,
            timeout=15
        )
    except Exception as e:
        log.warning(f"[DeHashed-{label}] Request error: {e}")
        return None

    if resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            return None
    elif resp.status_code == 400:
        log.warning(f"[DeHashed] Bad query: {query}")
    elif resp.status_code == 401:
        log.warning("[DeHashed] Invalid credentials (401)")
    elif resp.status_code == 302:
        log.warning("[DeHashed] Auth redirect — check API key")
    elif resp.status_code == 429:
        log.warning("[DeHashed] Rate limited (429)")
    else:
        log.warning(f"[DeHashed] HTTP {resp.status_code}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 3. LeakIX — Exposed Services + Leak Correlation
# ─────────────────────────────────────────────────────────────────────────────

LEAKIX_BASE = "https://leakix.net"


def leakix_search(domain: str, ip_addresses: list) -> dict:
    api_key = settings.LEAKIX_API_KEY
    log.info(f"[LeakIX] Searching for exposed services on {domain}...")

    result = {
        "source": "LeakIX",
        "available": False,
        "leak_events": [],
        "service_events": [],
        "total_leaks": 0,
        "total_services": 0,
        "critical_leaks": 0,
        "data_exposed_bytes": 0,
        "error": None
    }

    if not api_key:
        result["error"] = "LEAKIX_API_KEY not set — free key at https://leakix.net"
        log.info("[LeakIX] No API key configured")
        return result

    headers = {
        "api-key": api_key,
        "Accept": "application/json",
        "User-Agent": "VoraGuard-ThreatIntel/3.0"
    }

    leak_data = _leakix_query("leak", domain, headers)
    if leak_data is not None:
        result["available"] = True
        for event in leak_data[:10]:
            leak_entry = _parse_leakix_event(event)
            result["leak_events"].append(leak_entry)
            if leak_entry.get("severity") == "critical":
                result["critical_leaks"] += 1
            result["data_exposed_bytes"] += leak_entry.get("size_bytes", 0)
        result["total_leaks"] = len(leak_data)

    service_data = _leakix_query("service", domain, headers)
    if service_data is not None:
        result["available"] = True
        for event in service_data[:10]:
            result["service_events"].append(_parse_leakix_event(event))
        result["total_services"] = len(service_data)

    for ip in ip_addresses[:2]:
        time.sleep(0.5)
        ip_resp = _safe_get(
            f"{LEAKIX_BASE}/host/{ip}",
            headers=headers,
            timeout=10,
            label=f"LeakIX-host-{ip}"
        )
        if ip_resp and ip_resp.status_code == 200:
            try:
                ip_data = ip_resp.json()
                for s in ip_data.get("Services", [])[:3]:
                    result["service_events"].append({
                        "ip": ip,
                        "port": s.get("port", ""),
                        "plugin": s.get("event_source", ""),
                        "summary": s.get("summary", ""),
                        "severity": "info",
                        "type": "service",
                        "date": s.get("time", "")[:10]
                    })
                for lk in ip_data.get("Leaks", [])[:3]:
                    parsed = _parse_leakix_event(lk)
                    parsed["ip"] = ip
                    result["leak_events"].append(parsed)
                    result["critical_leaks"] += 1 if parsed.get("severity") == "critical" else 0
            except Exception:
                pass

    if result["available"]:
        size_mb = result["data_exposed_bytes"] / (1024 * 1024)
        log.info(
            f"[LeakIX] {result['total_leaks']} leaks, "
            f"{result['total_services']} services, "
            f"{size_mb:.1f} MB data exposure"
        )
    return result


def _leakix_query(scope: str, query: str, headers: dict) -> Optional[list]:
    resp = _safe_get(
        f"{LEAKIX_BASE}/search",
        headers=headers,
        params={"scope": scope, "q": f'host:"{query}"', "page": 0},
        timeout=15,
        label=f"LeakIX-{scope}"
    )
    if resp is None:
        return None
    if resp.status_code == 200:
        try:
            data = resp.json()
            return data if isinstance(data, list) else []
        except Exception:
            return []
    elif resp.status_code == 401:
        log.warning("[LeakIX] Invalid API key (401)")
    elif resp.status_code == 204:
        return []
    elif resp.status_code == 429:
        log.warning("[LeakIX] Rate limited (429)")
    else:
        log.warning(f"[LeakIX] HTTP {resp.status_code}")
    return None


def _parse_leakix_event(event: dict) -> dict:
    leak_info = event.get("leak", {})
    dataset = leak_info.get("dataset", {})
    geoip = event.get("geoip", {})
    size_bytes = dataset.get("size", 0) or 0
    if size_bytes > 1_073_741_824:
        size_human = f"{size_bytes / 1_073_741_824:.1f} GB"
    elif size_bytes > 1_048_576:
        size_human = f"{size_bytes / 1_048_576:.1f} MB"
    elif size_bytes > 1024:
        size_human = f"{size_bytes / 1024:.1f} KB"
    else:
        size_human = f"{size_bytes} bytes" if size_bytes else "unknown"
    return {
        "plugin": event.get("event_source", "Unknown"),
        "event_type": event.get("event_type", "unknown"),
        "ip": event.get("ip", ""),
        "host": event.get("host", ""),
        "port": event.get("port", ""),
        "summary": event.get("summary", ""),
        "severity": leak_info.get("severity", "info"),
        "leak_type": leak_info.get("type", ""),
        "leak_stage": leak_info.get("stage", ""),
        "size_bytes": size_bytes,
        "size_human": size_human,
        "rows": dataset.get("rows", 0),
        "collections": dataset.get("collections", 0),
        "is_infected": dataset.get("infected", False),
        "ransom_notes": dataset.get("ransom_notes", []),
        "date": event.get("time", "")[:10],
        "country": geoip.get("country_name", ""),
        "tags": event.get("tags", []),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. AbuseIPDB — IP Reputation
# ─────────────────────────────────────────────────────────────────────────────

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

_ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Brute Force", 23: "IoT Targeted",
}
_HIGH_SEVERITY_CATS = {4, 15, 16, 20, 21, 22}
_MED_SEVERITY_CATS  = {3, 5, 7, 9, 14, 18, 23}


def abuseipdb_check(domain: str, ip_addresses: list, nmap_result: dict) -> dict:
    api_key = settings.ABUSEIPDB_API_KEY
    log.info(f"[AbuseIPDB] Checking {len(ip_addresses)} IPs for {domain}...")

    result = {
        "source": "AbuseIPDB",
        "available": False,
        "ip_verdicts": [],
        "malicious_ips": 0,
        "suspicious_ips": 0,
        "clean_ips": 0,
        "tor_exits": 0,
        "total_reports": 0,
        "top_categories": [],
        "highest_confidence": 0,
        "overall_threat": "LOW",
        "error": None,
    }

    if not api_key:
        result["error"] = "ABUSEIPDB_API_KEY not set — get free key at abuseipdb.com (1000/day)"
        log.info("[AbuseIPDB] No API key configured")
        return result

    if not ip_addresses:
        result["error"] = "No IPs to check"
        return result

    headers = {
        "Key": api_key.strip(),
        "Accept": "application/json",
        "User-Agent": "VoraGuard-ThreatIntel/3.0",
    }

    all_cat_ids = []

    for ip in ip_addresses[:8]:
        time.sleep(0.5)
        resp = _safe_get(
            f"{ABUSEIPDB_BASE}/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
            timeout=15,
            label=f"AbuseIPDB-{ip}",
        )
        if resp is None:
            continue

        if resp.status_code == 200:
            result["available"] = True
            try:
                data = resp.json().get("data", {})
                confidence  = data.get("abuseConfidenceScore", 0)
                total_rep   = data.get("totalReports", 0)
                is_tor      = data.get("isTor", False)
                country     = data.get("countryCode", "")
                isp         = data.get("isp", "")
                domain_name = data.get("domain", "")
                usage_type  = data.get("usageType", "Unknown")
                last_rep    = data.get("lastReportedAt", "")
                reports     = data.get("reports", []) or []

                seen_cats = set()
                for rep in reports[:20]:
                    for cid in rep.get("categories", []):
                        seen_cats.add(int(cid))

                cat_names = [_ABUSE_CATEGORIES.get(c, f"Cat-{c}") for c in seen_cats]

                if confidence >= 80 or any(c in _HIGH_SEVERITY_CATS for c in seen_cats):
                    ip_threat = "CRITICAL"
                    result["malicious_ips"] += 1
                elif confidence >= 40 or any(c in _MED_SEVERITY_CATS for c in seen_cats):
                    ip_threat = "HIGH"
                    result["suspicious_ips"] += 1
                elif confidence > 0 or total_rep > 0:
                    ip_threat = "MEDIUM"
                    result["suspicious_ips"] += 1
                else:
                    ip_threat = "CLEAN"
                    result["clean_ips"] += 1

                if is_tor:
                    result["tor_exits"] += 1

                result["total_reports"] += total_rep
                all_cat_ids.extend(list(seen_cats))

                if confidence > result["highest_confidence"]:
                    result["highest_confidence"] = confidence

                recent_reports = []
                for rep in reports[:5]:
                    recent_reports.append({
                        "reported_at": rep.get("reportedAt", "")[:10],
                        "comment": rep.get("comment", "")[:120],
                        "categories": [_ABUSE_CATEGORIES.get(int(c), f"Cat-{c}") for c in rep.get("categories", [])],
                        "reporter_country": rep.get("reporterCountryCode", ""),
                    })

                result["ip_verdicts"].append({
                    "ip": ip,
                    "confidence_score": confidence,
                    "confidence_label": (
                        "CONFIRMED MALICIOUS" if confidence >= 80 else
                        "HIGH RISK"           if confidence >= 50 else
                        "SUSPICIOUS"          if confidence >= 20 else
                        "LOW RISK"            if confidence > 0  else "CLEAN"
                    ),
                    "total_reports": total_rep,
                    "last_reported": last_rep[:10] if last_rep else "Never",
                    "country": country,
                    "isp": isp,
                    "domain": domain_name,
                    "usage_type": usage_type,
                    "is_tor": is_tor,
                    "attack_categories": cat_names,
                    "threat_level": ip_threat,
                    "recent_reports": recent_reports,
                    "link": f"https://www.abuseipdb.com/check/{ip}",
                })

            except Exception as e:
                log.warning(f"[AbuseIPDB] Parse error for {ip}: {e}")

        elif resp.status_code == 401:
            result["error"] = "Invalid AbuseIPDB API key"
            log.error("[AbuseIPDB] 401 Invalid API key")
            break
        elif resp.status_code == 429:
            result["error"] = "AbuseIPDB rate limit hit (1000/day free)"
            log.warning("[AbuseIPDB] Rate limited")
            break
        elif resp.status_code == 422:
            log.warning(f"[AbuseIPDB] Invalid IP format: {ip}")
        else:
            log.warning(f"[AbuseIPDB] HTTP {resp.status_code} for {ip}")

    from collections import Counter
    cat_counts = Counter(all_cat_ids)
    result["top_categories"] = [
        {
            "category": _ABUSE_CATEGORIES.get(cid, f"Cat-{cid}"),
            "count": cnt,
            "severity": "HIGH" if cid in _HIGH_SEVERITY_CATS else "MEDIUM" if cid in _MED_SEVERITY_CATS else "LOW",
        }
        for cid, cnt in cat_counts.most_common(8)
    ]

    hc = result["highest_confidence"]
    if result["malicious_ips"] > 0 or hc >= 80:
        result["overall_threat"] = "CRITICAL"
    elif result["suspicious_ips"] > 0 or hc >= 40:
        result["overall_threat"] = "HIGH"
    elif result["total_reports"] > 0 or hc > 0:
        result["overall_threat"] = "MEDIUM"
    elif result["available"]:
        result["overall_threat"] = "LOW"

    log.info(
        f"[AbuseIPDB] {result['malicious_ips']} malicious, "
        f"{result['suspicious_ips']} suspicious, "
        f"highest confidence={result['highest_confidence']}%, "
        f"total reports={result['total_reports']}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. HIBP — Domain + Email Breach Check
# ─────────────────────────────────────────────────────────────────────────────

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def hibp_enhanced_check(domain: str, emails: list) -> dict:
    api_key = (settings.HIBP_API_KEY or "").split("#")[0].strip()
    log.info(f"[HIBP] Checking breach history for {domain}...")

    result = {
        "source": "HaveIBeenPwned",
        "available": False,
        "domain_breaches": [],
        "email_results": [],
        "paste_results": [],
        "total_pwned_accounts": 0,
        "most_recent_breach": None,
        "data_classes_exposed": [],
        "error": None
    }

    # Domain breach check — no key needed
    resp = _safe_get(
        f"{HIBP_BASE}/breaches",
        headers={"User-Agent": "VoraGuard-ThreatIntel/3.0"},
        timeout=15,
        label="HIBP-breaches"
    )

    if resp and resp.status_code == 200:
        result["available"] = True
        try:
            all_breaches = resp.json()
            clean_domain = domain.replace("www.", "").lower()
            domain_breaches = [
                b for b in all_breaches
                if clean_domain in b.get("Domain", "").lower()
                or clean_domain.split(".")[0] in b.get("Name", "").lower()
            ]
            for breach in domain_breaches[:5]:
                result["domain_breaches"].append({
                    "name": breach.get("Name", ""),
                    "date": breach.get("BreachDate", ""),
                    "pwned_count": breach.get("PwnCount", 0),
                    "data_classes": breach.get("DataClasses", []),
                    "is_verified": breach.get("IsVerified", False),
                    "description_snippet": breach.get("Description", "")[:200]
                })
                result["total_pwned_accounts"] += breach.get("PwnCount", 0)
                result["data_classes_exposed"].extend(breach.get("DataClasses", []))
            result["data_classes_exposed"] = list(set(result["data_classes_exposed"]))
            if domain_breaches:
                sorted_breaches = sorted(domain_breaches, key=lambda x: x.get("BreachDate", ""), reverse=True)
                result["most_recent_breach"] = sorted_breaches[0].get("BreachDate")
        except Exception as e:
            log.error(f"[HIBP] Parse error: {e}")

    # Email-level check — requires paid key
    if api_key and len(api_key) > 10 and emails:
        headers = {
            "User-Agent": "VoraGuard-ThreatIntel/3.0",
            "hibp-api-key": api_key
        }
        for email in emails[:5]:
            time.sleep(1.6)
            em_resp = _safe_get(
                f"{HIBP_BASE}/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=10,
                label=f"HIBP-email-{email}"
            )
            email_entry = {"email": email, "breaches": [], "pastes": []}
            if em_resp:
                if em_resp.status_code == 200:
                    try:
                        breaches = em_resp.json()
                        email_entry["breaches"] = [
                            {"name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses", [])}
                            for b in breaches[:5]
                        ]
                    except Exception:
                        pass
                elif em_resp.status_code == 429:
                    log.warning("[HIBP] Rate limited — waiting")
                    time.sleep(2)

            time.sleep(1.6)
            paste_resp = _safe_get(
                f"{HIBP_BASE}/pasteaccount/{email}",
                headers=headers,
                timeout=10,
                label=f"HIBP-paste-{email}"
            )
            if paste_resp and paste_resp.status_code == 200:
                try:
                    pastes = paste_resp.json()
                    email_entry["pastes"] = [
                        {"source": p.get("Source"), "date": p.get("Date", "")[:10], "email_count": p.get("EmailCount", 0), "id": p.get("Id", "")}
                        for p in pastes[:5]
                    ]
                except Exception:
                    pass

            if email_entry["breaches"] or email_entry["pastes"]:
                result["email_results"].append(email_entry)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6. URLhaus — Malicious URL Database (no key needed)
# ─────────────────────────────────────────────────────────────────────────────

URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"


def urlhaus_enhanced_check(domain: str, ip_addresses: list) -> dict:
    log.info(f"[URLhaus] Checking malicious URL database for {domain}...")

    result = {
        "source": "URLhaus / Abuse.ch",
        "available": True,
        "domain_status": "not_listed",
        "malicious_urls": [],
        "active_urls": 0,
        "malware_families": [],
        "blacklists": {},
        "ip_findings": [],
        "overall_risk": "CLEAN",
        "error": None
    }

    resp = _safe_post(f"{URLHAUS_BASE}/host/", data={"host": domain}, timeout=10, label="URLhaus-domain")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            status = data.get("query_status", "no_results")
            result["domain_status"] = status
            if status == "is_host":
                result["overall_risk"] = "CRITICAL"
                result["blacklists"] = data.get("blacklists", {})
                result["malware_families"] = data.get("tags", [])
                for url_entry in data.get("urls", [])[:10]:
                    result["malicious_urls"].append({
                        "url": url_entry.get("url", ""),
                        "status": url_entry.get("url_status", ""),
                        "threat": url_entry.get("threat", ""),
                        "tags": url_entry.get("tags", []),
                        "date_added": url_entry.get("date_added", ""),
                        "reporter": url_entry.get("reporter", ""),
                    })
                    if url_entry.get("url_status") == "online":
                        result["active_urls"] += 1
                    result["malware_families"].extend(url_entry.get("tags", []))
                result["malware_families"] = list(set(result["malware_families"]))
        except Exception as e:
            log.error(f"[URLhaus] Parse error: {e}")

    for ip in ip_addresses[:3]:
        time.sleep(0.3)
        ip_resp = _safe_post(f"{URLHAUS_BASE}/host/", data={"host": ip}, timeout=10, label=f"URLhaus-ip-{ip}")
        if ip_resp and ip_resp.status_code == 200:
            try:
                ip_data = ip_resp.json()
                if ip_data.get("query_status") == "is_host":
                    result["ip_findings"].append({
                        "ip": ip,
                        "url_count": ip_data.get("urls_count", 0),
                        "malware_families": ip_data.get("tags", []),
                        "blacklists": ip_data.get("blacklists", {}),
                    })
                    if result["overall_risk"] == "CLEAN":
                        result["overall_risk"] = "HIGH"
            except Exception:
                pass

    log.info(
        f"[URLhaus] Domain: {result['domain_status']}, "
        f"{result['active_urls']} active malicious URLs, "
        f"families: {result['malware_families']}"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MASTER FUNCTION — combines all 6 sources
# ─────────────────────────────────────────────────────────────────────────────

def full_darkweb_monitoring(domain: str, harvester_result: dict,
                             nmap_result: dict) -> dict:
    """
    Master dark web monitoring — runs all 6 sources and aggregates results.
    Sources: OTX, DeHashed, LeakIX, AbuseIPDB, HIBP, URLhaus
    """
    log.info(f"[DarkWeb] Starting full dark web monitoring for {domain}...")

    emails  = harvester_result.get("emails", []) or []
    ips     = harvester_result.get("ips", []) or []
    nmap_ips = list(set(
        p.get("ip", "") for p in (nmap_result.get("open_ports", []) or [])
        if p.get("ip")
    ))
    all_ips = list(set(ips + nmap_ips))

    hibp_result      = hibp_enhanced_check(domain, emails)
    urlhaus_result   = urlhaus_enhanced_check(domain, all_ips)
    otx_result       = otx_search(domain, emails, all_ips)
    dehashed_result  = dehashed_search(domain, emails)
    leakix_result    = leakix_search(domain, all_ips)
    abuseipdb_result = abuseipdb_check(domain, all_ips, nmap_result)

    # ── Aggregate risk score ──────────────────────────────────
    risk_scores = []

    if hibp_result.get("domain_breaches"):
        risk_scores.append(3)
    if urlhaus_result.get("domain_status") == "is_host":
        risk_scores.append(4)
    if otx_result.get("pulse_count", 0) >= 10:
        risk_scores.append(4)
    elif otx_result.get("pulse_count", 0) >= 3:
        risk_scores.append(3)
    elif otx_result.get("pulse_count", 0) >= 1:
        risk_scores.append(2)
    if dehashed_result.get("domain_breach_count", 0) > 1000:
        risk_scores.append(4)
    elif dehashed_result.get("domain_breach_count", 0) > 0:
        risk_scores.append(3)
    if leakix_result.get("critical_leaks", 0) > 0:
        risk_scores.append(4)
    if abuseipdb_result.get("malicious_ips", 0) > 0:
        risk_scores.append(4)
    elif abuseipdb_result.get("suspicious_ips", 0) > 0:
        risk_scores.append(3)

    max_risk = max(risk_scores) if risk_scores else 1
    overall_risk = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(max_risk, "LOW")

    # ── Build summary findings ────────────────────────────────
    summary_findings = []

    if otx_result.get("pulse_count", 0) > 0:
        severity = "CRITICAL" if otx_result["pulse_count"] >= 10 else "HIGH" if otx_result["pulse_count"] >= 3 else "MEDIUM"
        summary_findings.append({
            "source": "AlienVault OTX",
            "severity": severity,
            "title": f"Domain found in {otx_result['pulse_count']} OTX threat pulses",
            "detail": (
                f"Malware families: {', '.join(otx_result.get('malware_families', [])[:3]) or 'Unknown'} | "
                f"Threat actors: {', '.join(otx_result.get('threat_actors', [])[:3]) or 'N/A'}"
            ),
            "data_classes": ["Domain Reputation", "Threat Intelligence"]
        })

    if hibp_result.get("domain_breaches"):
        for b in hibp_result["domain_breaches"][:3]:
            summary_findings.append({
                "source": "HaveIBeenPwned",
                "severity": "HIGH",
                "title": f"Domain in '{b['name']}' breach",
                "detail": f"{b['pwned_count']:,} accounts affected on {b['date']}",
                "data_classes": b.get("data_classes", [])
            })

    if urlhaus_result.get("malicious_urls"):
        summary_findings.append({
            "source": "URLhaus / Abuse.ch",
            "severity": "CRITICAL",
            "title": f"Domain serving malware ({urlhaus_result['active_urls']} active URLs)",
            "detail": f"Malware families: {', '.join(urlhaus_result.get('malware_families', [])) or 'Unknown'}",
            "data_classes": ["Malware Distribution", "C2 Infrastructure"]
        })

    if dehashed_result.get("domain_breach_count", 0) > 0:
        summary_findings.append({
            "source": "DeHashed",
            "severity": "CRITICAL" if dehashed_result["domain_breach_count"] > 1000 else "HIGH",
            "title": f"{dehashed_result['domain_breach_count']:,} breached credentials found",
            "detail": f"Across {len(dehashed_result.get('databases_found', []))} breach databases",
            "data_classes": ["Email Addresses", "Passwords", "Usernames"]
        })

    if leakix_result.get("total_leaks", 0) > 0:
        total_mb = leakix_result.get("data_exposed_bytes", 0) / 1_048_576
        summary_findings.append({
            "source": "LeakIX",
            "severity": "CRITICAL",
            "title": f"{leakix_result['total_leaks']} active data leaks detected",
            "detail": f"{total_mb:.1f} MB exposed, {leakix_result.get('critical_leaks', 0)} critical severity events",
            "data_classes": ["Live Exposed Data", "Database Contents"]
        })

    if abuseipdb_result.get("malicious_ips", 0) > 0:
        summary_findings.append({
            "source": "AbuseIPDB",
            "severity": "CRITICAL",
            "title": f"IP classified malicious — AbuseIPDB confidence: {abuseipdb_result.get('highest_confidence', 0)}%",
            "detail": f"Attack categories: {', '.join([c['category'] for c in abuseipdb_result.get('top_categories', [])[:3]]) or 'Malicious activity reported'}",
            "data_classes": ["C2 Infrastructure", "Botnet"]
        })
    elif abuseipdb_result.get("suspicious_ips", 0) > 0 and abuseipdb_result.get("total_reports", 0) > 5:
        summary_findings.append({
            "source": "AbuseIPDB",
            "severity": "HIGH",
            "title": f"Suspicious IP activity — {abuseipdb_result.get('total_reports', 0)} abuse reports",
            "detail": f"Top categories: {', '.join([c['category'] for c in abuseipdb_result.get('top_categories', [])[:3]])}",
            "data_classes": ["Active Exploitation"]
        })

    # ── Sources status ────────────────────────────────────────
    sources_status = [
        {
            "name": "AlienVault OTX",
            "status": "✓ Checked" if otx_result.get("available") else f"⚠ {otx_result.get('error', 'No key')}",
            "key_required": True,
            "findings": otx_result.get("pulse_count", 0)
        },
        {
            "name": "HaveIBeenPwned",
            "status": "✓ Checked" if hibp_result.get("available") else "✗ Unavailable",
            "key_required": False,
            "findings": len(hibp_result.get("domain_breaches", []))
        },
        {
            "name": "URLhaus / Abuse.ch",
            "status": "✓ Checked",
            "key_required": False,
            "findings": len(urlhaus_result.get("malicious_urls", []))
        },
        {
            "name": "DeHashed",
            "status": "✓ Checked" if dehashed_result.get("available") else f"⚠ {dehashed_result.get('error', 'No key')}",
            "key_required": True,
            "findings": dehashed_result.get("domain_breach_count", 0)
        },
        {
            "name": "LeakIX",
            "status": "✓ Checked" if leakix_result.get("available") else f"⚠ {leakix_result.get('error', 'No key')}",
            "key_required": True,
            "findings": leakix_result.get("total_leaks", 0)
        },
        {
            "name": "AbuseIPDB",
            "status": "✓ Checked" if abuseipdb_result.get("available") else "⚠ No IPs to check",
            "key_required": False,
            "findings": abuseipdb_result.get("malicious_ips", 0)
        },
    ]

    active_sources = len([s for s in sources_status if "✓" in s["status"]])

    final = {
        "domain": domain,
        "overall_risk": overall_risk,
        "summary_findings": summary_findings,
        "total_sources_checked": len(sources_status),
        "total_findings": len(summary_findings),
        "sources_status": sources_status,

        # Individual source results
        "otx": otx_result,
        "hibp": hibp_result,
        "urlhaus": urlhaus_result,
        "dehashed": dehashed_result,
        "leakix": leakix_result,
        "abuseipdb": abuseipdb_result,

        # Aggregated
        "all_breached_emails": (
            hibp_result.get("email_results", []) +
            dehashed_result.get("email_breaches", [])
        ),
        "credential_exposure_count": dehashed_result.get("domain_breach_count", 0),
        "malware_families": list(set(
            urlhaus_result.get("malware_families", []) +
            otx_result.get("malware_families", [])
        )),
        "threat_actors": otx_result.get("threat_actors", []),
        "related_cves": otx_result.get("related_cves", []),

        "disclaimer": (
            "Dark web monitoring covers: AlienVault OTX (threat pulses, malware families, threat actors), "
            "HaveIBeenPwned (breach database), URLhaus (malicious URL feeds), "
            "DeHashed (credential dumps), LeakIX (live data leaks), "
            "AbuseIPDB (IP reputation). Full Tor hidden service crawling requires "
            "commercial feeds (Recorded Future, DarkOwl, Flashpoint)."
        )
    }

    log.info(
        f"[DarkWeb] Complete — {len(summary_findings)} findings, "
        f"risk={overall_risk}, {active_sources}/6 sources active"
    )
    return final
