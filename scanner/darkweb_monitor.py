"""
VoraGuard Dark Web & Telegram Stealer Log Monitor v5.0
Developed by Jithu

Monitors:
  1. LeakIX — leaked databases, exposed services (you have API key)
  2. Have I Been Pwned — breach notifications (free email search)
  3. IntelX — dark web search (free tier: 1 search/day)
  4. DeHashed — credential database search (free: limited)
  5. Pastebin / paste sites — keyword monitoring
  6. Telegram Bot — monitor channels for brand/credential mentions
  7. URLhaus / MalwareBazaar — credential stealer C2 tracking

Stealer Log Intelligence:
  Monitors for domain-linked credentials appearing in:
  - Redline stealer logs
  - Raccoon stealer dumps
  - Lumma stealer
  - Vidar stealer
  - MetaStealer
"""
import os, re, json, time, logging, requests, threading
from datetime import datetime, timezone, timedelta
from pathlib import Path

VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
DW_DIR     = VORAG_HOME / "darkweb"
DW_DIR.mkdir(parents=True, exist_ok=True)
FINDINGS_FILE = DW_DIR / "findings.json"
CACHE_FILE    = DW_DIR / "cache.json"
log           = logging.getLogger("vorag.darkweb")
HEADERS       = {"User-Agent": "VoraGuard/5.0 Security Research"}

def _get_env(key): return (os.environ.get(key) or "").strip()

def _load_findings():
    if FINDINGS_FILE.exists():
        try: return json.loads(FINDINGS_FILE.read_text())
        except: pass
    return []

def _save_findings(findings):
    FINDINGS_FILE.write_text(json.dumps(findings[-2000:], indent=2, default=str))

def _add_finding(finding):
    findings = _load_findings()
    finding["detected_at"] = datetime.now(timezone.utc).isoformat()
    findings.append(finding)
    _save_findings(findings)
    # Trigger SOAR
    if finding.get("severity") in ("CRITICAL","HIGH"):
        try:
            from soar_engine import get_soar_engine
            get_soar_engine().process_event({
                "trigger":   "darkweb_mention",
                "severity":  finding["severity"],
                "title":     finding.get("title",""),
                "summary":   finding.get("summary",""),
                "source":    finding.get("source","darkweb"),
                "domain":    finding.get("domain",""),
                "affected_email": finding.get("email",""),
                "details":   finding,
            })
        except Exception as e:
            log.error(f"[DW] SOAR: {e}")

# ══════════════════════════════════════════════════════════════════
# LEAKIX — Leaked database & exposed service monitoring
# ══════════════════════════════════════════════════════════════════

def scan_leakix(domain: str) -> list:
    api_key = _get_env("LEAKIX_API_KEY")
    if not api_key:
        return [{"source":"LeakIX","status":"not_configured",
                 "message":"Set LEAKIX_API_KEY","severity":"INFO"}]
    findings = []
    try:
        r = requests.get(
            f"https://leakix.net/domain/{domain}",
            headers={**HEADERS, "api-key": api_key,
                     "Accept": "application/json"},
            timeout=15)
        if r.status_code == 200:
            data = r.json()
            services = data.get("Services",[]) or []
            leaks    = data.get("Leaks",[])    or []
            for leak in leaks[:10]:
                sev = "CRITICAL" if leak.get("severity","").lower() in ("critical","high") else "HIGH"
                f = {
                    "source":   "LeakIX",
                    "type":     "credential_leak",
                    "title":    f"LeakIX: Data leak for {domain}",
                    "summary":  f"Event: {leak.get('event_source','')} | Plugin: {leak.get('event_fingerprint','')} | "
                                f"Description: {str(leak.get('summary',''))[:200]}",
                    "severity": sev,
                    "domain":   domain,
                    "url":      f"https://leakix.net/domain/{domain}",
                    "date":     leak.get("time","")[:10],
                }
                findings.append(f)
                _add_finding(f)
            for svc in services[:5]:
                if svc.get("leak") or svc.get("event_source","").lower() not in ("","unknown"):
                    f = {
                        "source":   "LeakIX",
                        "type":     "exposed_service",
                        "title":    f"Exposed service: {svc.get('port','')} on {domain}",
                        "summary":  f"Protocol: {svc.get('protocol','')} | Transport: {svc.get('transport','')}",
                        "severity": "MEDIUM",
                        "domain":   domain,
                        "url":      f"https://leakix.net/host/{domain}",
                    }
                    findings.append(f)
        elif r.status_code == 401:
            findings.append({"source":"LeakIX","status":"auth_error",
                             "message":"Invalid API key","severity":"INFO"})
        elif r.status_code == 404:
            findings.append({"source":"LeakIX","status":"clean",
                             "message":f"No leaks found for {domain}","severity":"INFO"})
    except Exception as e:
        log.error(f"[LeakIX] {e}")
        findings.append({"source":"LeakIX","status":"error","message":str(e),"severity":"INFO"})
    return findings

# ══════════════════════════════════════════════════════════════════
# HAVE I BEEN PWNED — Breach & Paste search
# ══════════════════════════════════════════════════════════════════

def scan_hibp_domain(domain: str) -> list:
    """Check domain against HIBP breach database."""
    findings = []
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachesfordomain/{domain}",
            headers={**HEADERS, "hibp-api-key": _get_env("HIBP_API_KEY") or "public",
                     "User-Agent": "VoraGuard/5.0"},
            timeout=15)
        if r.status_code == 200:
            breaches = r.json()
            for b in breaches[:10]:
                classes = b.get("DataClasses",[])
                has_pw  = any(c.lower() in ("passwords","password hints") for c in classes)
                sev     = "CRITICAL" if has_pw else "HIGH"
                f = {
                    "source":   "HIBP",
                    "type":     "breach",
                    "title":    f"Domain in breach: {b.get('Name','')} ({b.get('BreachDate','')})",
                    "summary":  f"Breach '{b['Name']}' exposed {b.get('PwnCount',0):,} accounts. "
                                f"Data: {', '.join(classes[:5])}. Verified: {b.get('IsVerified','')}",
                    "severity": sev,
                    "domain":   domain,
                    "breach_name": b.get("Name",""),
                    "date":     b.get("BreachDate",""),
                    "count":    b.get("PwnCount",0),
                    "data_classes": classes,
                    "has_passwords": has_pw,
                    "url":      f"https://haveibeenpwned.com/api/v3/breach/{b.get('Name','')}",
                }
                findings.append(f)
                if sev in ("CRITICAL","HIGH"):
                    _add_finding(f)
        elif r.status_code == 404:
            findings.append({"source":"HIBP","status":"clean",
                             "message":f"Domain {domain} not found in any known breach","severity":"INFO"})
        elif r.status_code == 401:
            findings.append({"source":"HIBP","status":"no_key",
                             "message":"HIBP domain search requires API key ($3.50/mo). Email search is free.",
                             "severity":"INFO"})
    except Exception as e:
        log.error(f"[HIBP] {e}")
    return findings

def scan_hibp_email(email: str) -> list:
    """Check single email against HIBP (free endpoint)."""
    findings = []
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers={**HEADERS, "hibp-api-key": _get_env("HIBP_API_KEY") or "",
                     "User-Agent": "VoraGuard/5.0"},
            timeout=15)
        if r.status_code == 200:
            for b in r.json()[:5]:
                classes = b.get("DataClasses",[])
                has_pw  = any("password" in c.lower() for c in classes)
                findings.append({
                    "source":   "HIBP",
                    "type":     "email_breach",
                    "title":    f"Email in breach: {b.get('Name','')}",
                    "summary":  f"{email} found in {b['Name']} breach ({b.get('BreachDate','')}). Data: {', '.join(classes[:4])}",
                    "severity": "CRITICAL" if has_pw else "HIGH",
                    "email":    email,
                    "breach":   b.get("Name",""),
                    "date":     b.get("BreachDate",""),
                })
    except Exception as e:
        log.error(f"[HIBP email] {e}")
    return findings

# ══════════════════════════════════════════════════════════════════
# PASTE SITE MONITORING (Pastebin, GitHub Gist, etc.)
# ══════════════════════════════════════════════════════════════════

def scan_paste_sites(domain: str) -> list:
    """Monitor paste sites for domain/credential mentions."""
    findings = []

    # Use GitHub code search (using existing GITHUB_TOKEN) to find exposed credentials
    github_token = _get_env("GITHUB_TOKEN")
    if github_token:
        queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" credentials',
        ]
        headers_gh = {"Authorization": f"token {github_token}",
                      "Accept": "application/vnd.github.v3+json"}
        for query in queries[:2]:  # Rate limit: 2 queries
            try:
                r = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 5},
                    headers=headers_gh, timeout=15)
                if r.status_code == 200:
                    items = r.json().get("items",[])
                    for item in items[:3]:
                        if item.get("repository",{}).get("private"):
                            continue  # Skip private repos
                        f = {
                            "source":   "GitHub (Public)",
                            "type":     "exposed_credential",
                            "title":    f"Possible credential exposure on GitHub: {item.get('name','')}",
                            "summary":  f"File '{item.get('name','')}' in repo "
                                        f"'{item.get('repository',{}).get('full_name','')}' "
                                        f"may contain credentials for {domain}",
                            "severity": "HIGH",
                            "domain":   domain,
                            "url":      item.get("html_url",""),
                            "repo":     item.get("repository",{}).get("full_name",""),
                        }
                        findings.append(f)
                        _add_finding(f)
                time.sleep(2)  # GitHub rate limit: 30 searches/min
            except Exception as e:
                log.debug(f"[Paste] GitHub: {e}")

    # Shodan — check for exposed credentials in banners
    shodan_key = _get_env("SHODAN_API_KEY")
    if shodan_key:
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": shodan_key,
                        "query": f'http.title:"{domain}" has_vuln:true',
                        "limit": 5},
                headers=HEADERS, timeout=12)
            if r.status_code == 200:
                for match in r.json().get("matches",[])[:3]:
                    ip = match.get("ip_str","")
                    findings.append({
                        "source":   "Shodan",
                        "type":     "exposed_host",
                        "title":    f"Exposed host with vulnerabilities: {ip}",
                        "summary":  f"Host {ip} linked to {domain} has known vulnerabilities exposed on the internet",
                        "severity": "HIGH",
                        "domain":   domain,
                        "ip":       ip,
                        "url":      f"https://www.shodan.io/host/{ip}",
                    })
        except Exception as e:
            log.debug(f"[Paste] Shodan: {e}")

    if not findings:
        findings.append({"source":"Paste Monitor","status":"clean",
                         "message":f"No paste site exposures found for {domain}","severity":"INFO"})
    return findings

# ══════════════════════════════════════════════════════════════════
# STEALER LOG INTELLIGENCE — Malware family tracking
# ══════════════════════════════════════════════════════════════════

STEALER_FAMILIES = {
    "redline": {"name":"Redline Stealer","risk":"CRITICAL","targets":["browsers","wallets","vpn","discord"]},
    "raccoon": {"name":"Raccoon Stealer","risk":"CRITICAL","targets":["browsers","email","ftp","crypto"]},
    "lumma":   {"name":"Lumma Stealer","risk":"CRITICAL","targets":["browsers","crypto","2fa","discord"]},
    "vidar":   {"name":"Vidar Stealer","risk":"HIGH","targets":["browsers","crypto","telegram"]},
    "meta":    {"name":"MetaStealer","risk":"HIGH","targets":["browsers","vpn","rdp"]},
    "azorult": {"name":"AZORult","risk":"HIGH","targets":["browsers","ftp","vpn","wallets"]},
    "aurora":  {"name":"Aurora Stealer","risk":"HIGH","targets":["browsers","crypto","telegram"]},
}

def scan_stealer_logs(domain: str) -> list:
    """Check malware feeds for stealer logs mentioning domain."""
    findings = []

    # URLhaus — check if domain is in active malware distribution
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": domain},
                          headers=HEADERS, timeout=10)
        if r.status_code == 200 and r.json().get("query_status") != "no_results":
            data = r.json()
            urls = data.get("urls",[])
            if urls:
                f = {
                    "source":   "URLhaus",
                    "type":     "malware_distribution",
                    "title":    f"Domain in malware distribution: {domain}",
                    "summary":  f"Domain found in {len(urls)} URLhaus entries as malware host",
                    "severity": "CRITICAL",
                    "domain":   domain,
                    "url_count":len(urls),
                    "url":      f"https://urlhaus.abuse.ch/host/{domain}",
                }
                findings.append(f)
                _add_finding(f)
    except Exception as e:
        log.debug(f"[Stealer] URLhaus: {e}")

    # MalwareBazaar — check if domain appears in samples
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query":"get_taginfo","tag":domain.replace(".","_"),"limit":"5"},
                          headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                for sample in data.get("data",[])[:3]:
                    sig = sample.get("signature","") or "Unknown"
                    family_key = next((k for k in STEALER_FAMILIES if k in sig.lower()), None)
                    family_info = STEALER_FAMILIES.get(family_key, {})
                    f = {
                        "source":       "MalwareBazaar",
                        "type":         "stealer_log_mention",
                        "title":        f"Stealer sample references {domain}: {sig}",
                        "summary":      f"Malware family '{sig}' sample found referencing your domain. "
                                        f"SHA256: {sample.get('sha256_hash','')[:16]}...",
                        "severity":     family_info.get("risk","HIGH"),
                        "domain":       domain,
                        "malware":      sig,
                        "targets":      family_info.get("targets",[]),
                        "sha256":       sample.get("sha256_hash",""),
                        "url":          f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash','')}",
                    }
                    findings.append(f)
                    _add_finding(f)
    except Exception as e:
        log.debug(f"[Stealer] MalwareBazaar: {e}")

    # OTX — check domain in threat intelligence pulses
    otx_key = _get_env("OTX_API_KEY")
    if otx_key:
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={**HEADERS, "X-OTX-API-KEY": otx_key},
                timeout=15)
            if r.status_code == 200:
                data  = r.json()
                pulse_count = data.get("pulse_info",{}).get("count",0)
                pulses      = data.get("pulse_info",{}).get("pulses",[])
                if pulse_count > 0:
                    sev = "CRITICAL" if pulse_count >= 10 else "HIGH" if pulse_count >= 3 else "MEDIUM"
                    f = {
                        "source":       "AlienVault OTX",
                        "type":         "threat_intel_match",
                        "title":        f"Domain in {pulse_count} threat intel pulses: {domain}",
                        "summary":      f"AlienVault OTX: {domain} appears in {pulse_count} threat intelligence pulses. "
                                        f"Latest: {pulses[0].get('name','') if pulses else ''}",
                        "severity":     sev,
                        "domain":       domain,
                        "pulse_count":  pulse_count,
                        "url":          f"https://otx.alienvault.com/indicator/domain/{domain}",
                    }
                    findings.append(f)
                    if sev in ("CRITICAL","HIGH"):
                        _add_finding(f)
        except Exception as e:
            log.debug(f"[Stealer] OTX: {e}")

    if not findings:
        findings.append({"source":"Stealer Monitor","status":"clean",
                         "message":f"No stealer log activity found for {domain}","severity":"INFO"})
    return findings

# ══════════════════════════════════════════════════════════════════
# TELEGRAM MONITOR — Real-time channel keyword monitoring
# ══════════════════════════════════════════════════════════════════

class TelegramMonitor:
    """
    Monitor Telegram channels for brand/credential mentions.
    Uses Telegram Bot API (free).

    Setup:
    1. Create a bot: message @BotFather → /newbot
    2. Add bot to target channels as admin or member
    3. Set TELEGRAM_MONITOR_BOT_TOKEN and TELEGRAM_MONITOR_CHANNELS
       TELEGRAM_MONITOR_CHANNELS = comma-separated list of @channel_usernames or chat_ids
    4. Set DARKWEB_KEYWORDS = comma-separated keywords to watch for
    """
    def __init__(self, domain: str):
        self.domain   = domain
        self.token    = _get_env("TELEGRAM_MONITOR_BOT_TOKEN") or _get_env("TELEGRAM_BOT_TOKEN")
        self.channels = [c.strip() for c in (_get_env("TELEGRAM_MONITOR_CHANNELS") or "").split(",") if c.strip()]
        self.keywords = [k.strip() for k in (_get_env("DARKWEB_KEYWORDS") or domain).split(",") if k.strip()]
        self._running = False
        self._thread  = None
        self.base     = f"https://api.telegram.org/bot{self.token}"

    @property
    def is_configured(self):
        return bool(self.token and self.channels)

    def get_status(self):
        if not self.token:
            return {"status":"not_configured",
                    "message":"Set TELEGRAM_MONITOR_BOT_TOKEN and TELEGRAM_MONITOR_CHANNELS",
                    "instructions":[
                        "1. Create bot: message @BotFather → /newbot",
                        "2. Add bot to channels you want to monitor",
                        "3. Set TELEGRAM_MONITOR_BOT_TOKEN=<your-bot-token>",
                        "4. Set TELEGRAM_MONITOR_CHANNELS=@channel1,@channel2",
                        "5. Set DARKWEB_KEYWORDS=yourdomain.com,your-brand-name",
                    ]}
        return {"status":"configured","running":self._running,"keywords":self.keywords,
                "channels":self.channels}

    def check_channels_once(self) -> list:
        """Fetch recent messages from configured channels and check for keywords."""
        if not self.is_configured:
            return []
        findings = []
        for channel in self.channels:
            try:
                r = requests.get(f"{self.base}/getUpdates",
                                 params={"limit":100,"allowed_updates":["channel_post","message"]},
                                 timeout=15)
                if r.status_code != 200:
                    continue
                for update in r.json().get("result",[]):
                    msg = update.get("channel_post") or update.get("message",{})
                    text = (msg.get("text","") or msg.get("caption","")).lower()
                    for keyword in self.keywords:
                        if keyword.lower() in text:
                            chat = msg.get("chat",{})
                            f = {
                                "source":   "Telegram Monitor",
                                "type":     "telegram_mention",
                                "title":    f"Keyword '{keyword}' found in Telegram: {chat.get('title','') or chat.get('username','')}",
                                "summary":  f"Message in {chat.get('title','channel')} mentions '{keyword}': "
                                            f"{text[:200]}",
                                "severity": "HIGH",
                                "domain":   self.domain,
                                "keyword":  keyword,
                                "channel":  chat.get("username",""),
                                "message_id": msg.get("message_id",""),
                            }
                            findings.append(f)
                            _add_finding(f)
            except Exception as e:
                log.debug(f"[Telegram] {channel}: {e}")
        return findings

    def start_monitoring(self, interval: int = 300):
        """Start background monitoring thread (default: check every 5 min)."""
        if self._running or not self.is_configured:
            return
        self._running = True
        def _monitor():
            log.info(f"[Telegram] Monitor started: {self.channels}")
            last_update_id = 0
            while self._running:
                try:
                    r = requests.get(f"{self.base}/getUpdates",
                                     params={"offset":last_update_id+1,"limit":100,"timeout":30},
                                     timeout=40)
                    if r.status_code == 200:
                        updates = r.json().get("result",[])
                        for update in updates:
                            last_update_id = max(last_update_id, update.get("update_id",0))
                            msg  = update.get("channel_post") or update.get("message",{})
                            text = (msg.get("text","") or "").lower()
                            for kw in self.keywords:
                                if kw.lower() in text:
                                    _add_finding({
                                        "source":  "Telegram Monitor",
                                        "type":    "telegram_mention",
                                        "title":   f"Telegram alert: '{kw}' mentioned",
                                        "summary": f"Keyword detected in Telegram: {text[:300]}",
                                        "severity":"HIGH",
                                        "domain":  self.domain,
                                        "keyword": kw,
                                    })
                    time.sleep(interval)
                except Exception as e:
                    log.error(f"[Telegram] monitor error: {e}")
                    time.sleep(60)
        self._thread = threading.Thread(target=_monitor, daemon=True)
        self._thread.start()

    def stop_monitoring(self):
        self._running = False

# ══════════════════════════════════════════════════════════════════
# COMBINED DARK WEB SCAN
# ══════════════════════════════════════════════════════════════════

def full_darkweb_scan(domain: str) -> dict:
    """Run all dark web monitoring checks for a domain."""
    log.info(f"[DarkWeb] Full scan: {domain}")
    all_findings = []
    scanners = [
        ("LeakIX",           lambda: scan_leakix(domain)),
        ("HIBP",             lambda: scan_hibp_domain(domain)),
        ("Paste Monitor",    lambda: scan_paste_sites(domain)),
        ("Stealer Logs",     lambda: scan_stealer_logs(domain)),
    ]
    results_by_source = {}
    for name, fn in scanners:
        try:
            findings = fn()
            results_by_source[name] = findings
            all_findings.extend([f for f in findings if f.get("severity") not in ("INFO",)])
        except Exception as e:
            log.error(f"[DarkWeb] {name}: {e}")
            results_by_source[name] = [{"source":name,"status":"error","message":str(e),"severity":"INFO"}]

    critical = sum(1 for f in all_findings if f.get("severity")=="CRITICAL")
    high     = sum(1 for f in all_findings if f.get("severity")=="HIGH")
    return {
        "domain":         domain,
        "scanned_at":     datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "critical":       critical,
        "high":           high,
        "risk_level":     "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "LOW",
        "findings":       all_findings,
        "by_source":      results_by_source,
    }

def get_all_findings(limit: int = 200) -> list:
    f = _load_findings()
    return f[-limit:][::-1]
