"""
VoraGuard IP Intelligence Module — v1.0
Unified IP scanning using all 4 free APIs:

  1. AbuseIPDB      — confidence score, attack categories, abuse history    (1000/day free)
  2. Shodan         — open ports, services, banners, CVEs, geolocation      (100 queries/mo free)
  3. IPQualityScore — fraud score, proxy/VPN/Tor, bot detection, ISP        (5000/mo free)
  4. Criminal IP    — attack score, CVE correlations, real-time threat data  (100/day free)

All functions:
  - Real HTTP API calls, real response parsing
  - Graceful degradation when key missing or rate limited
  - Returns structured dicts for the unified report

Get free keys:
  AbuseIPDB:      https://www.abuseipdb.com/register
  Shodan:         https://account.shodan.io/register
  IPQualityScore: https://www.ipqualityscore.com/create-account
  Criminal IP:    https://www.criminalip.io/en/register
"""

import time
import socket
import requests
from datetime import datetime
from typing import Optional
from utils.logger import get_logger
from config.settings import settings

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_get(url, headers=None, params=None, timeout=15, label="") -> Optional[requests.Response]:
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        return r
    except requests.Timeout:
        log.warning(f"[{label}] Request timed out")
        return None
    except requests.RequestException as e:
        log.warning(f"[{label}] Request error: {e}")
        return None

def resolve_ip(target: str) -> list:
    """Resolve domain to IPs, or return IP list if already an IP."""
    import re
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(target):
        return [target]
    try:
        infos = socket.getaddrinfo(target, None)
        return list(set(i[4][0] for i in infos if ":" not in i[4][0]))[:5]
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# 1. AbuseIPDB
# ─────────────────────────────────────────────────────────────────────────────
_ABUSE_CATEGORIES = {
    1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders", 4:"DDoS Attack",
    5:"FTP Brute Force", 6:"Ping of Death", 7:"Phishing", 8:"Fraud VoIP",
    9:"Open Proxy", 10:"Web Spam", 11:"Email Spam", 12:"Blog Spam",
    13:"VPN IP", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection",
    17:"Spoofing", 18:"Brute Force", 19:"Bad Web Bot", 20:"Exploited Host",
    21:"Web App Attack", 22:"SSH Brute Force", 23:"IoT Targeted",
}
_HIGH_SEVERITY_CATS = {4, 15, 16, 20, 21, 22}
_MED_SEVERITY_CATS  = {3, 5, 7, 9, 14, 18, 23}

def check_abuseipdb(ip: str) -> dict:
    """Check IP against AbuseIPDB — confidence score, categories, history."""
    result = {
        "source": "AbuseIPDB", "available": False, "ip": ip,
        "confidence_score": 0, "confidence_label": "UNKNOWN",
        "total_reports": 0, "last_reported": "Never",
        "country": "", "isp": "", "usage_type": "",
        "is_tor": False, "is_public": True,
        "attack_categories": [], "recent_reports": [],
        "threat_level": "UNKNOWN", "link": f"https://www.abuseipdb.com/check/{ip}",
        "error": None,
    }
    key = settings.ABUSEIPDB_API_KEY
    if not key:
        result["error"] = "ABUSEIPDB_API_KEY not set — get free key at abuseipdb.com"
        return result

    log.info(f"[AbuseIPDB] Checking {ip}...")
    resp = _safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key.strip(), "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"},
        timeout=15, label=f"AbuseIPDB-{ip}",
    )
    if resp is None:
        result["error"] = "Connection failed"; return result

    if resp.status_code == 200:
        result["available"] = True
        d = resp.json().get("data", {})
        confidence = d.get("abuseConfidenceScore", 0)
        reports = d.get("reports", [])
        seen_cats = set()
        for rep in reports[:20]:
            for cid in rep.get("categories", []):
                seen_cats.add(int(cid))
        result.update({
            "confidence_score":  confidence,
            "confidence_label":  (
                "CONFIRMED MALICIOUS" if confidence >= 80 else
                "HIGH RISK"           if confidence >= 50 else
                "SUSPICIOUS"          if confidence >= 20 else
                "LOW RISK"            if confidence > 0  else "CLEAN"
            ),
            "total_reports":    d.get("totalReports", 0),
            "last_reported":    ((d.get("lastReportedAt") or "")[:10] or "Never"),
            "country":          d.get("countryCode", ""),
            "isp":              d.get("isp", ""),
            "usage_type":       d.get("usageType", ""),
            "is_tor":           d.get("isTor", False),
            "is_public":        d.get("isPublic", True),
            "attack_categories":[_ABUSE_CATEGORIES.get(c, f"Cat-{c}") for c in seen_cats],
            "recent_reports":   [
                {
                    "date":       r.get("reportedAt","")[:10],
                    "comment":    r.get("comment","")[:100],
                    "categories": [_ABUSE_CATEGORIES.get(int(c),f"Cat-{c}") for c in r.get("categories",[])],
                }
                for r in reports[:5]
            ],
            "threat_level": (
                "CRITICAL" if confidence >= 80 or any(c in _HIGH_SEVERITY_CATS for c in seen_cats) else
                "HIGH"     if confidence >= 40 or any(c in _MED_SEVERITY_CATS  for c in seen_cats) else
                "MEDIUM"   if confidence > 0 or d.get("totalReports",0) > 0 else
                "CLEAN"
            ),
        })
    elif resp.status_code == 401:
        result["error"] = "Invalid AbuseIPDB key"
    elif resp.status_code == 429:
        result["error"] = "AbuseIPDB rate limit (1000/day)"
    else:
        result["error"] = f"HTTP {resp.status_code}"

    log.info(f"[AbuseIPDB] {ip} — confidence={result['confidence_score']}% | reports={result['total_reports']}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 2. Shodan
# ─────────────────────────────────────────────────────────────────────────────

def check_shodan(ip: str) -> dict:
    """Check IP against Shodan — open ports, banners, CVEs, geo, OS."""
    result = {
        "source": "Shodan", "available": False, "ip": ip,
        "open_ports": [], "services": [], "cves": [],
        "os": "", "country": "", "city": "", "org": "", "isp": "",
        "hostnames": [], "domains": [], "tags": [],
        "last_update": "", "vulns": [],
        "threat_level": "UNKNOWN",
        "link": f"https://www.shodan.io/host/{ip}",
        "error": None,
    }
    key = settings.SHODAN_API_KEY
    if not key:
        result["error"] = "SHODAN_API_KEY not set — get free key at shodan.io (100 queries/mo)"
        return result

    log.info(f"[Shodan] Looking up {ip}...")
    resp = _safe_get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": key.strip()},
        timeout=15, label=f"Shodan-{ip}",
    )
    if resp is None:
        result["error"] = "Connection failed"; return result

    if resp.status_code == 200:
        result["available"] = True
        d = resp.json()
        ports = d.get("ports", [])
        services = []
        for item in d.get("data", [])[:15]:
            port = item.get("port")
            transport = item.get("transport", "tcp")
            product = item.get("product", "")
            version = item.get("version", "")
            banner = (item.get("data","") or "")[:120].replace("\n"," ")
            svc = {
                "port": port, "protocol": transport,
                "product": product, "version": version,
                "banner": banner,
                "cpe": item.get("cpe", [])[:3],
                "vulns": list((item.get("vulns") or {}).keys())[:5],
            }
            services.append(svc)

        # All CVEs across all services
        all_cves = []
        for item in d.get("data",[]):
            for cve_id, cve_data in (item.get("vulns") or {}).items():
                all_cves.append({
                    "cve": cve_id,
                    "cvss": cve_data.get("cvss", 0),
                    "summary": cve_data.get("summary","")[:100],
                })
        all_cves.sort(key=lambda x: x.get("cvss",0), reverse=True)

        result.update({
            "open_ports":  ports[:20],
            "services":    services,
            "cves":        all_cves[:15],
            "os":          d.get("os") or "",
            "country":     d.get("country_name",""),
            "city":        d.get("city",""),
            "org":         d.get("org",""),
            "isp":         d.get("isp",""),
            "hostnames":   d.get("hostnames",[])[:10],
            "domains":     d.get("domains",[])[:10],
            "tags":        d.get("tags",[]),
            "last_update": d.get("last_update","")[:10],
            "vulns":       [c["cve"] for c in all_cves[:10]],
            "threat_level":(
                "CRITICAL" if len(all_cves) > 5 or any(c["cvss"]>=9 for c in all_cves) else
                "HIGH"     if len(all_cves) > 0 or len(ports) > 10 else
                "MEDIUM"   if len(ports) > 5 else
                "LOW"      if len(ports) > 0 else "CLEAN"
            ),
        })
    elif resp.status_code == 404:
        result["available"] = True
        result["threat_level"] = "CLEAN"
        result["error"] = "IP not indexed by Shodan"
    elif resp.status_code == 401:
        result["error"] = "Invalid Shodan API key"
    elif resp.status_code == 429:
        result["error"] = "Shodan rate limit (100 queries/mo on free)"
    else:
        result["error"] = f"HTTP {resp.status_code}"

    port_count = len(result["open_ports"])
    cve_count  = len(result["cves"])
    log.info(f"[Shodan] {ip} — {port_count} ports | {cve_count} CVEs | org={result['org']}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. IPQualityScore
# ─────────────────────────────────────────────────────────────────────────────

def check_ipqualityscore(ip: str) -> dict:
    """
    Check IP via IPQualityScore — fraud score, proxy/VPN/Tor, bot, ISP.
    Free: 5000 lookups/mo — best free tier for fraud + bot detection.
    """
    result = {
        "source": "IPQualityScore", "available": False, "ip": ip,
        "fraud_score": 0, "fraud_label": "UNKNOWN",
        "is_proxy": False, "is_vpn": False, "is_tor": False,
        "is_bot": False, "is_crawler": False,
        "recent_abuse": False, "abuse_velocity": "none",
        "country": "", "city": "", "region": "",
        "isp": "", "org": "", "timezone": "",
        "mobile": False, "connection_type": "",
        "threat_level": "UNKNOWN",
        "link": f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}",
        "error": None,
    }
    key = settings.IPQUALITYSCORE_KEY
    if not key:
        result["error"] = "IPQUALITYSCORE_KEY not set — get free key at ipqualityscore.com (5000/mo)"
        return result

    log.info(f"[IPQualityScore] Checking {ip}...")
    resp = _safe_get(
        f"https://ipqualityscore.com/api/json/ip/{key.strip()}/{ip}",
        params={
            "strictness": 1,
            "allow_public_access_points": "true",
            "fast": "false",
            "lighter_penalties": "false",
        },
        timeout=15, label=f"IPQS-{ip}",
    )
    if resp is None:
        result["error"] = "Connection failed"; return result

    if resp.status_code == 200:
        d = resp.json()
        if not d.get("success", True):
            result["error"] = d.get("message","IPQS error")
            return result

        result["available"] = True
        fraud = d.get("fraud_score", 0)
        result.update({
            "fraud_score":      fraud,
            "fraud_label":      (
                "HIGH FRAUD RISK" if fraud >= 85 else
                "SUSPICIOUS"      if fraud >= 60 else
                "ELEVATED"        if fraud >= 30 else
                "CLEAN"
            ),
            "is_proxy":         d.get("proxy", False),
            "is_vpn":           d.get("vpn", False),
            "is_tor":           d.get("tor", False),
            "is_bot":           d.get("bot_status", False),
            "is_crawler":       d.get("is_crawler", False),
            "recent_abuse":     d.get("recent_abuse", False),
            "abuse_velocity":   d.get("abuse_velocity","none"),
            "country":          d.get("country_code",""),
            "city":             d.get("city",""),
            "region":           d.get("region",""),
            "isp":              d.get("ISP",""),
            "org":              d.get("organization",""),
            "timezone":         d.get("timezone",""),
            "mobile":           d.get("mobile", False),
            "connection_type":  d.get("connection_type",""),
            "threat_level":     (
                "CRITICAL" if fraud >= 85 or d.get("tor") else
                "HIGH"     if fraud >= 60 or d.get("proxy") or d.get("recent_abuse") else
                "MEDIUM"   if fraud >= 30 or d.get("vpn") else
                "LOW"      if fraud > 0 else "CLEAN"
            ),
        })
    elif resp.status_code == 401:
        result["error"] = "Invalid IPQualityScore key"
    elif resp.status_code == 429:
        result["error"] = "IPQS rate limit (5000/mo free)"
    else:
        result["error"] = f"HTTP {resp.status_code}"

    log.info(f"[IPQS] {ip} — fraud={result['fraud_score']} | proxy={result['is_proxy']} | vpn={result['is_vpn']} | bot={result['is_bot']}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. Criminal IP
# ─────────────────────────────────────────────────────────────────────────────

def check_criminalip(ip: str) -> dict:
    """
    Check IP via Criminal IP — attack score, CVEs, real-time threat classification.
    Free: 100 checks/day — includes CVE data free (unique vs competitors).
    """
    result = {
        "source": "CriminalIP", "available": False, "ip": ip,
        "attack_score": 0, "score_label": "UNKNOWN",
        "inbound_score": 0, "outbound_score": 0,
        "is_scanner": False, "is_vpn": False, "is_tor": False,
        "is_cloud": False, "is_datacenter": False,
        "country": "", "city": "", "org": "", "isp": "",
        "open_ports": [], "cves": [], "tags": [],
        "current_opened_count": 0,
        "threat_level": "UNKNOWN",
        "link": f"https://www.criminalip.io/ip/{ip}",
        "error": None,
    }
    key = settings.CRIMINALIP_API_KEY
    if not key:
        result["error"] = "CRIMINALIP_API_KEY not set — get free key at criminalip.io (100/day)"
        return result

    log.info(f"[CriminalIP] Checking {ip}...")
    resp = _safe_get(
        f"https://api.criminalip.io/v1/ip/data",
        headers={"x-api-key": key.strip()},
        params={"ip": ip, "full": "false"},
        timeout=15, label=f"CriminalIP-{ip}",
    )
    if resp is None:
        result["error"] = "Connection failed"; return result

    if resp.status_code == 200:
        result["available"] = True
        d = resp.json()

        # Score
        score_obj = d.get("score", {})
        inbound   = score_obj.get("inbound", 0)
        outbound  = score_obj.get("outbound", 0)
        attack    = max(inbound, outbound)

        # Location — Criminal IP returns "ip" as string, "whois" as nested list
        whois_data = d.get("whois", {})
        if isinstance(whois_data, dict):
            whois_list = whois_data.get("data", [])
            whois = whois_list[0] if whois_list else {}
        else:
            whois = {}
        # geo fields are at top level in Criminal IP response
        geo_country = d.get("country", "") or d.get("country_code", "")
        geo_city    = d.get("city", "")

        # Open ports from criminal IP
        port_data = d.get("port", {}).get("data", [])[:10]
        open_ports = [
            {
                "port":     p.get("open_port_no"),
                "protocol": p.get("socket_type","tcp").lower(),
                "service":  p.get("app_name",""),
                "confirmed_time": p.get("confirmed_time","")[:10],
            }
            for p in port_data if p.get("open_port_no")
        ]

        # CVEs from Criminal IP (free tier includes this!)
        cve_data = d.get("vulnerability", {}).get("data", [])[:10]
        cves = [
            {
                "cve":     c.get("cve_id",""),
                "cvss":    c.get("cvssv3", c.get("cvssv2", 0)),
                "summary": c.get("cve_description","")[:100],
                "port":    c.get("open_port_no"),
            }
            for c in cve_data if c.get("cve_id")
        ]
        cves.sort(key=lambda x: x.get("cvss",0), reverse=True)

        # Tags / classification
        tags = []
        privacy = d.get("privacy_threat", {})
        if privacy.get("is_vpn"):    tags.append("VPN")
        if privacy.get("is_tor"):    tags.append("TOR")
        if privacy.get("is_proxy"):  tags.append("PROXY")
        if privacy.get("is_cloud"):  tags.append("CLOUD")
        if privacy.get("is_hosting"):tags.append("HOSTING/DATACENTER")
        if d.get("is_scanner"):      tags.append("SCANNER")

        result.update({
            "attack_score":         attack,
            "inbound_score":        inbound,
            "outbound_score":       outbound,
            "score_label":          (
                "CRITICAL" if attack >= 80 else
                "HIGH"     if attack >= 50 else
                "MEDIUM"   if attack >= 20 else
                "LOW"      if attack > 0 else "CLEAN"
            ),
            "is_scanner":           d.get("is_scanner", False),
            "is_vpn":               privacy.get("is_vpn", False),
            "is_tor":               privacy.get("is_tor", False),
            "is_cloud":             privacy.get("is_cloud", False),
            "is_datacenter":        privacy.get("is_hosting", False),
            "country":              geo_country or whois.get("org_country_code",""),
            "city":                 geo_city,
            "org":                  whois.get("org_name",""),
            "isp":                  whois.get("org_name",""),
            "open_ports":           open_ports,
            "cves":                 cves,
            "tags":                 tags,
            "current_opened_count": d.get("current_opened_count", 0),
            "threat_level":         (
                "CRITICAL" if attack >= 80 or len(cves) > 5 else
                "HIGH"     if attack >= 50 or len(cves) > 0 else
                "MEDIUM"   if attack >= 20 or len(open_ports) > 5 else
                "LOW"      if attack > 0 else "CLEAN"
            ),
        })
    elif resp.status_code == 401:
        result["error"] = "Invalid Criminal IP key"
    elif resp.status_code == 429:
        result["error"] = "Criminal IP rate limit (100/day free)"
    else:
        result["error"] = f"HTTP {resp.status_code}"

    log.info(f"[CriminalIP] {ip} — attack={result['attack_score']} | cves={len(result['cves'])} | tags={result['tags']}")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Unified IP Intelligence Report
# ─────────────────────────────────────────────────────────────────────────────

_THREAT_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0, "UNKNOWN": 0}

def run_ip_scan(target: str) -> dict:
    """
    Run full IP intelligence scan using all 4 APIs.
    Works on both direct IPs (1.2.3.4) and domains (resolves first).
    Returns unified report with data from all 4 sources.
    """
    from datetime import datetime
    scan_start = datetime.now()
    log.info(f"[IPScan] Starting full IP intelligence scan for {target}...")

    # Resolve target to IPs
    ips = resolve_ip(target)
    is_ip_target = bool(__import__('re').match(r"^\d{1,3}(\.\d{1,3}){3}$", target))

    if not ips:
        return {
            "target": target, "success": False,
            "error": f"Could not resolve {target} to any IP address",
        }

    log.info(f"[IPScan] Resolved {target} → {ips}")

    all_results = []

    for ip in ips[:3]:  # Scan up to 3 IPs
        time.sleep(0.5)
        log.info(f"[IPScan] Scanning IP: {ip}")

        abuse   = check_abuseipdb(ip)
        time.sleep(0.3)
        shodan  = check_shodan(ip)
        time.sleep(0.3)
        ipqs    = check_ipqualityscore(ip)
        time.sleep(0.3)
        criminal= check_criminalip(ip)

        # Compute unified threat score (weighted average)
        scores = {
            "abuseipdb":      abuse.get("confidence_score", 0),       # 0-100
            "shodan":         min(len(shodan.get("cves",[])) * 10, 100),
            "ipqualityscore": ipqs.get("fraud_score", 0),             # 0-100
            "criminalip":     criminal.get("attack_score", 0),        # 0-100
        }
        active_scores = [v for v in scores.values() if v > 0]
        unified_score = int(sum(active_scores) / len(active_scores)) if active_scores else 0

        # Highest threat level across all sources
        levels = [
            abuse.get("threat_level","UNKNOWN"),
            shodan.get("threat_level","UNKNOWN"),
            ipqs.get("threat_level","UNKNOWN"),
            criminal.get("threat_level","UNKNOWN"),
        ]
        highest_level = max(levels, key=lambda l: _THREAT_RANK.get(l, 0))

        # Aggregate unique CVEs from Shodan + Criminal IP
        all_cves = {}
        for cve in shodan.get("cves",[]) + criminal.get("cves",[]):
            cid = cve.get("cve","")
            if cid and cid not in all_cves:
                all_cves[cid] = cve
        cve_list = sorted(all_cves.values(), key=lambda x: x.get("cvss",0), reverse=True)

        # Aggregate open ports
        port_set = {}
        for p in shodan.get("services",[]):
            port_set[p["port"]] = {"port": p["port"], "protocol": p.get("protocol","tcp"), "service": p.get("product",""), "version": p.get("version",""), "source": "Shodan"}
        for p in criminal.get("open_ports",[]):
            if p["port"] not in port_set:
                port_set[p["port"]] = {"port": p["port"], "protocol": p.get("protocol","tcp"), "service": p.get("service",""), "version": "", "source": "CriminalIP"}

        # Geolocation — prefer Shodan, fallback to others
        country = shodan.get("country") or ipqs.get("country") or abuse.get("country") or criminal.get("country") or ""
        city    = shodan.get("city")    or ipqs.get("city")    or criminal.get("city")   or ""
        org     = shodan.get("org")     or ipqs.get("org")     or criminal.get("org")    or ""
        isp     = shodan.get("isp")     or ipqs.get("isp")     or abuse.get("isp")       or ""

        # Flags
        is_tor      = abuse.get("is_tor") or ipqs.get("is_tor") or criminal.get("is_tor")
        is_vpn      = ipqs.get("is_vpn")  or criminal.get("is_vpn")
        is_proxy    = ipqs.get("is_proxy",False)
        is_bot      = ipqs.get("is_bot",False)
        is_scanner  = criminal.get("is_scanner",False)

        # Key findings summary
        findings = []
        if abuse.get("confidence_score",0) >= 50:
            findings.append(f"AbuseIPDB: {abuse['confidence_score']}% confidence malicious ({abuse.get('total_reports',0)} reports)")
        if cve_list:
            top = cve_list[0]
            findings.append(f"Shodan/CriminalIP: {len(cve_list)} CVEs found — highest CVSS {top.get('cvss',0)} ({top.get('cve','')})")
        if ipqs.get("fraud_score",0) >= 50:
            findings.append(f"IPQualityScore: Fraud score {ipqs['fraud_score']}% — {ipqs.get('fraud_label','')}")
        if criminal.get("attack_score",0) >= 50:
            findings.append(f"CriminalIP: Attack score {criminal['attack_score']} — {criminal.get('score_label','')}")
        if is_tor:   findings.append("TOR exit node detected across multiple sources")
        if is_vpn:   findings.append("VPN/anonymizer service detected")
        if is_proxy: findings.append("Open proxy detected")
        if is_bot:   findings.append("Bot activity detected")
        if is_scanner: findings.append("IP is an active internet scanner")

        ip_result = {
            "ip": ip,
            "unified_score":  unified_score,
            "threat_level":   highest_level,
            "source_scores":  scores,
            "country":        country,
            "city":           city,
            "org":            org,
            "isp":            isp,
            "is_tor":         is_tor,
            "is_vpn":         is_vpn,
            "is_proxy":       is_proxy,
            "is_bot":         is_bot,
            "is_scanner":     is_scanner,
            "open_ports":     list(port_set.values()),
            "cves":           cve_list[:15],
            "key_findings":   findings,
            # Raw source data
            "abuseipdb":      abuse,
            "shodan":         shodan,
            "ipqualityscore": ipqs,
            "criminalip":     criminal,
        }
        all_results.append(ip_result)

    # Overall summary across all IPs
    max_score = max((r["unified_score"] for r in all_results), default=0)
    max_level = max((r["threat_level"] for r in all_results), key=lambda l: _THREAT_RANK.get(l,0), default="UNKNOWN")
    all_findings = []
    for r in all_results:
        all_findings.extend(r["key_findings"])
    all_cves_combined = {}
    for r in all_results:
        for cve in r["cves"]:
            cid = cve.get("cve","")
            if cid and cid not in all_cves_combined:
                all_cves_combined[cid] = cve

    duration = (datetime.now() - scan_start).total_seconds()

    report = {
        "target":          target,
        "is_direct_ip":    is_ip_target,
        "resolved_ips":    ips,
        "scan_duration":   duration,
        "scanned_at":      datetime.now().isoformat()[:19],
        "success":         True,
        "overall_score":   max_score,
        "overall_threat":  max_level,
        "total_cves":      len(all_cves_combined),
        "total_reports":   sum(r["abuseipdb"].get("total_reports",0) for r in all_results),
        "key_findings":    all_findings,
        "ip_results":      all_results,
        "sources_used":    ["AbuseIPDB","Shodan","IPQualityScore","CriminalIP"],
        "sources_active":  [
            s for s, k in [
                ("AbuseIPDB",      settings.ABUSEIPDB_API_KEY),
                ("Shodan",         settings.SHODAN_API_KEY),
                ("IPQualityScore", settings.IPQUALITYSCORE_KEY),
                ("CriminalIP",     settings.CRIMINALIP_API_KEY),
            ] if k
        ],
    }

    log.info(
        f"[IPScan] Complete for {target} — "
        f"score={max_score} | level={max_level} | "
        f"cves={len(all_cves_combined)} | duration={duration:.1f}s"
    )
    return report
