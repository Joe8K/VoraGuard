"""
VoraGuard EPSS Intel v6.0 - Live Data
FIRST.org EPSS API + CISA KEV + NVD
Developed by Jithu
"""
import os, json, time, logging, requests
from datetime import datetime, timezone
from pathlib import Path

VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
INTEL_DIR  = VORAG_HOME / "intel"
INTEL_DIR.mkdir(parents=True, exist_ok=True)
EPSS_CACHE = INTEL_DIR / "epss_cache.json"
KEV_CACHE  = INTEL_DIR / "kev_cache.json"
log = logging.getLogger("vorag.epss")
HDR = {"User-Agent": "VoraGuard/6.0"}

# ── EPSS Score for single CVE ─────────────────────────────────────────────
def get_epss_score(cve_id):
    cve_id = cve_id.upper().strip()
    result = {"cve": cve_id, "epss": 0, "percentile": 0, "risk": "UNKNOWN", "source": "FIRST.org EPSS API"}
    # 1. EPSS from FIRST.org
    try:
        r = requests.get("https://api.first.org/data/v1/epss?cve=" + cve_id, headers=HDR, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", [])
            if data:
                d = data[0]
                score = float(d.get("epss", 0))
                result.update({
                    "epss": round(score, 4),
                    "percentile": round(float(d.get("percentile", 0)), 4),
                    "date": d.get("date", ""),
                    "risk": "CRITICAL" if score >= 0.7 else "HIGH" if score >= 0.4 else "MEDIUM" if score >= 0.1 else "LOW",
                })
    except Exception as e:
        log.error("EPSS score error: " + str(e))
    # 2. NVD for description, CVSS, references, CWE, vendor
    try:
        nvd = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id,
                           headers={"User-Agent": "VoraGuard/5.0"}, timeout=12)
        if nvd.status_code == 200:
            items = nvd.json().get("vulnerabilities", [])
            if items:
                cve_data = items[0].get("cve", {})
                # Description
                descs = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description available.")
                result["description"] = desc
                # CVSS v3.1 then v3.0 then v2
                metrics = cve_data.get("metrics", {})
                cvss_score = None
                cvss_vector = None
                cvss_severity = None
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score = m.get("baseScore")
                        cvss_vector = m.get("vectorString")
                        cvss_severity = m.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                        break
                if cvss_score:
                    result["cvss_score"] = cvss_score
                    result["cvss_vector"] = cvss_vector
                    result["cvss_severity"] = cvss_severity
                # CWE
                weaknesses = cve_data.get("weaknesses", [])
                cwes = []
                for w in weaknesses:
                    for wd in w.get("description", []):
                        if wd.get("value", "").startswith("CWE-"):
                            cwes.append(wd["value"])
                if cwes:
                    result["cwe"] = cwes
                # References
                refs = cve_data.get("references", [])
                result["references"] = [{"url": ref.get("url"), "source": ref.get("source", "")} for ref in refs[:8]]
                # Published / modified dates
                result["published"] = cve_data.get("published", "")[:10]
                result["last_modified"] = cve_data.get("lastModified", "")[:10]
                # Vendor/product from CPE
                configs = cve_data.get("configurations", [])
                vendors = set()
                for cfg in configs:
                    for node in cfg.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            parts = cpe.get("criteria", "").split(":")
                            if len(parts) > 3:
                                vendors.add(parts[3])
                if vendors:
                    result["affected_vendors"] = list(vendors)[:6]
                result["nvd_source"] = "NVD NIST"
    except Exception as e:
        log.error("NVD enrichment error: " + str(e))
    return result

# ── Top exploited CVEs from CISA KEV ─────────────────────────────────────

def get_recent_high_risk(limit=20):
    """
    Fetch CVEs published this calendar year up to today, scored by EPSS.
    Cache refreshes every 24 hours so it updates daily automatically.
    """
    import datetime, json, os
    cache_file = str(VORAG_HOME / "data" / "recent_cves_cache.json")
    now = datetime.datetime.utcnow()
    current_year = now.year

    # Load cache — valid for 24 hours
    try:
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                cache = json.load(f)
            age_hours = (now.timestamp() - cache.get("_ts", 0)) / 3600
            if age_hours < 24 and cache.get("year") == current_year:
                log.info("Recent CVEs: serving from cache (" + str(round(age_hours,1)) + "h old)")
                return cache.get("data", [])[:limit]
    except Exception:
        pass

    log.info("Recent CVEs: fetching from NVD for year " + str(current_year))
    year_start = str(current_year) + "-01-01T00:00:00.000"
    year_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    all_cve_ids = []
    start_index = 0
    results_per_page = 2000

    # Page through NVD to get ALL CVEs published this year
    while True:
        try:
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                "?pubStartDate=" + year_start +
                "&pubEndDate=" + year_end +
                "&resultsPerPage=" + str(results_per_page) +
                "&startIndex=" + str(start_index)
            )
            r = requests.get(url, headers={"User-Agent": "VoraGuard/5.0"}, timeout=30)
            if r.status_code == 200:
                body = r.json()
                vulns = body.get("vulnerabilities", [])
                all_cve_ids += [v["cve"]["id"] for v in vulns if "cve" in v]
                total = body.get("totalResults", 0)
                log.info("NVD page " + str(start_index) + "/" + str(total) + " got " + str(len(vulns)))
                if start_index + results_per_page >= total:
                    break
                start_index += results_per_page
                time.sleep(0.6)   # NVD rate limit
            else:
                log.error("NVD status: " + str(r.status_code))
                break
        except Exception as e:
            log.error("NVD page error: " + str(e))
            break

    if not all_cve_ids:
        log.warning("No CVEs from NVD, falling back to FIRST.org top list")
        return get_top_epss(limit)

    log.info("NVD returned " + str(len(all_cve_ids)) + " CVEs for " + str(current_year))

    # Score all with EPSS in batches of 100
    scored = []
    for i in range(0, len(all_cve_ids), 100):
        batch = all_cve_ids[i:i+100]
        try:
            er = requests.get(
                "https://api.first.org/data/v1/epss?cve=" + ",".join(batch),
                headers=HDR, timeout=20
            )
            if er.status_code == 200:
                for d in er.json().get("data", []):
                    score = float(d.get("epss", 0))
                    scored.append({
                        "cve":        d.get("cve", ""),
                        "epss":       round(score, 4),
                        "percentile": round(float(d.get("percentile", 0)), 4),
                        "date":       d.get("date", ""),
                        "risk":       ("CRITICAL" if score >= 0.7 else
                                       "HIGH"     if score >= 0.4 else
                                       "MEDIUM"   if score >= 0.1 else "LOW"),
                        "year":       current_year,
                    })
            time.sleep(0.3)
        except Exception as e:
            log.error("EPSS batch error: " + str(e))

    # Sort by EPSS score descending
    scored.sort(key=lambda x: x["epss"], reverse=True)

    # Save to cache
    try:
        os.makedirs(str(VORAG_HOME / "data"), exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump({"data": scored, "_ts": now.timestamp(), "year": current_year}, f)
        log.info("Recent CVEs cached: " + str(len(scored)) + " entries")
    except Exception as e:
        log.error("Cache write error: " + str(e))

    return scored[:limit]

def get_kev_catalog():
    cache = _load(KEV_CACHE)
    if cache and time.time() - cache.get("_ts", 0) < 3600:
        return cache.get("data", [])
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                         headers=HDR, timeout=15)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            _save(KEV_CACHE, {"data": vulns, "_ts": time.time()})
            log.info(f"KEV: loaded {len(vulns)} vulnerabilities")
            return vulns
    except Exception as e:
        log.error(f"KEV error: {e}")
    return cache.get("data", []) if cache else []

# ── Top CVEs by EPSS score ────────────────────────────────────────────────
def get_top_epss(limit=20):
    try:
        r = requests.get(f"https://api.first.org/data/v1/epss?order=!epss&limit={limit}",
                         headers=HDR, timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", [])
            result = []
            for d in data:
                score = float(d.get("epss", 0))
                result.append({
                    "cve": d.get("cve", ""),
                    "epss": round(score, 4),
                    "percentile": round(float(d.get("percentile", 0)), 4),
                    "date": d.get("date", ""),
                    "risk": "CRITICAL" if score >= 0.7 else "HIGH" if score >= 0.4 else "MEDIUM" if score >= 0.1 else "LOW",
                })
            return result
    except Exception as e:
        log.error(f"Top EPSS error: {e}")
    return []

# ── Enrich CVE list with EPSS + KEV ──────────────────────────────────────
def enrich_cves(cve_list):
    if not cve_list:
        return []
    cves = ",".join([c.upper() for c in cve_list[:100]])
    try:
        r = requests.get(f"https://api.first.org/data/v1/epss?cve={cves}", headers=HDR, timeout=15)
        if r.status_code == 200:
            data = {d["cve"]: d for d in r.json().get("data", [])}
            kev = {v["cveID"]: v for v in get_kev_catalog()}
            result = []
            for cve in cve_list:
                cve = cve.upper()
                d = data.get(cve, {})
                score = float(d.get("epss", 0))
                k = kev.get(cve, {})
                result.append({
                    "cve": cve,
                    "epss": round(score, 4),
                    "percentile": round(float(d.get("percentile", 0)), 4),
                    "risk": "CRITICAL" if score >= 0.7 else "HIGH" if score >= 0.4 else "MEDIUM" if score >= 0.1 else "LOW",
                    "in_kev": bool(k),
                    "kev_name": k.get("vulnerabilityName", ""),
                    "vendor": k.get("vendorProject", ""),
                    "product": k.get("product", ""),
                    "due_date": k.get("dueDate", ""),
                    "ransomware": k.get("knownRansomwareCampaignUse", "Unknown"),
                })
            return sorted(result, key=lambda x: x["epss"], reverse=True)
    except Exception as e:
        log.error(f"Enrich CVEs error: {e}")
    return [{"cve": c, "epss": 0, "risk": "UNKNOWN"} for c in cve_list]

# ── Stats ──────────────────────────────────────────────────────────────────
def get_epss_stats():
    top = get_top_epss(50)
    kev = get_kev_catalog()
    return {
        "top_cves": top[:10],
        "total_kev": len(kev),
        "kev_sample": kev[:5] if kev else [],
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "FIRST.org EPSS + CISA KEV"
    }

def _load(p):
    try:
        if Path(p).exists(): return json.loads(Path(p).read_text())
    except: pass
    return {}

def _save(p, d):
    try: Path(p).write_text(json.dumps(d, indent=2, default=str))
    except: pass
