"""
VoraGuard Network Monitor v7.0 — Full IDS/IPS + Threat Intelligence Engine
Developed by Jithu

Beyond Wireshark — Active defense, threat intel, behavioral analysis, file extraction.

NEW in v7.0:
  IDS/IPS ENGINE      — real-time iptables blocking, auto-response, TCP reset injection
  THREAT INTEL        — VT, AbuseIPDB, OTX auto-lookup every alerted IP
  IOC FEEDS           — Abuse.ch ThreatFox, FeodoTracker, OTX, URLhaus live sync
  GEO/ASN ENRICHMENT  — country, city, ASN, org, reputation for every IP
  BEHAVIORAL BASELINE — learns normal → alerts on anomalies
  FILE EXTRACTION     — pulls HTTP/SMB files, hashes, VT checks
  STIX/TAXII EXPORT   — standard threat intel sharing
  PCAP EXPORT         — save captured session as .pcap
  TLS KEY LOGGING     — hooks SSLKEYLOGFILE for decryption
  PACKET INJECTION    — send TCP RST, ICMP, custom frames
  PROMISCUOUS MODE    — capture all LAN traffic
  APT MAPPING         — maps TTPs to known APT groups
  ZEEK INTEGRATION    — run Zeek on captured data
  SURICATA RULES      — check packets against Suricata signatures
  CUSTOM DISSECTORS   — Python-based protocol dissectors
  FILTER HISTORY      — back/forward filter navigation
  SANDBOX             — auto-submit extracted files to any.run
"""
import os, re, json, time, socket, logging, threading, subprocess, hashlib, struct, math
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Set
import requests

VORAG_HOME   = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
NET_DIR      = VORAG_HOME / "network"
IOC_DIR      = NET_DIR / "ioc_feeds"
EXTRACT_DIR  = NET_DIR / "extracted_files"
PCAP_DIR     = NET_DIR / "pcaps"
BASELINE_DIR = NET_DIR / "baseline"
for d in [NET_DIR, IOC_DIR, EXTRACT_DIR, PCAP_DIR, BASELINE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

ALERTS_FILE  = NET_DIR / "alerts.json"
STATS_FILE   = NET_DIR / "stats.json"
IOC_CACHE    = IOC_DIR / "ioc_cache.json"
BASELINE_FILE= BASELINE_DIR / "traffic_baseline.json"
BLOCKED_FILE = NET_DIR / "blocked_ips.json"
INTEL_CACHE  = NET_DIR / "intel_cache.json"

log = logging.getLogger("vorag.network")
def _get_env(k): return (os.environ.get(k) or "").strip()

# ══════════════════════════════════════════════════════════════════
# IOC FEED MANAGER — Live threat intelligence feeds
# ══════════════════════════════════════════════════════════════════
class IOCFeedManager:
    """Pulls and maintains live IOC feeds from Abuse.ch, OTX, FeodoTracker, URLhaus."""
    def __init__(self):
        self._malicious_ips:  Set[str]  = set()
        self._malicious_urls: Set[str]  = set()
        self._malicious_hashes: Set[str]= set()
        self._c2_ips:         Set[str]  = set()
        self._apt_ips:        Dict[str,str] = {}  # ip → apt group
        self._last_update     = 0
        self._lock            = threading.Lock()
        self._load_cache()
        log.info(f"[IOC] Feed manager init: {len(self._malicious_ips)} IPs, {len(self._malicious_hashes)} hashes")

    def _load_cache(self):
        try:
            if IOC_CACHE.exists():
                d = json.loads(IOC_CACHE.read_text())
                self._malicious_ips   = set(d.get("ips",[]))
                self._malicious_urls  = set(d.get("urls",[]))
                self._malicious_hashes= set(d.get("hashes",[]))
                self._c2_ips          = set(d.get("c2_ips",[]))
                self._apt_ips         = d.get("apt_ips",{})
                self._last_update     = d.get("updated",0)
        except: pass

    def _save_cache(self):
        try:
            IOC_CACHE.write_text(json.dumps({
                "ips":     list(self._malicious_ips)[:50000],
                "urls":    list(self._malicious_urls)[:10000],
                "hashes":  list(self._malicious_hashes)[:20000],
                "c2_ips":  list(self._c2_ips)[:5000],
                "apt_ips": self._apt_ips,
                "updated": time.time(),
            }))
        except: pass

    def refresh(self):
        """Refresh all feeds — run in background thread, max once per hour."""
        if time.time() - self._last_update < 3600: return
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        log.info("[IOC] Refreshing threat intel feeds...")
        new_ips = set(); new_hashes = set(); new_c2 = set()
        # ── FeodoTracker C2 IPs (Emotet, TrickBot, Dridex, QakBot)
        try:
            r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=15)
            for line in r.text.splitlines():
                if line and not line.startswith("#"): new_c2.add(line.strip().split(":")[0])
            log.info(f"[IOC] FeodoTracker: {len(new_c2)} C2 IPs")
        except Exception as e: log.warning(f"[IOC] FeodoTracker failed: {e}")
        # ── ThreatFox IOCs (malware IPs)
        try:
            r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                              json={"query":"get_iocs","days":7}, timeout=15)
            data = r.json().get("data",[])
            for ioc in data:
                if ioc.get("ioc_type") == "ip:port":
                    ip = ioc.get("ioc","").split(":")[0]
                    if ip: new_ips.add(ip)
                elif ioc.get("ioc_type") in ("md5_hash","sha256_hash"):
                    new_hashes.add(ioc.get("ioc",""))
            log.info(f"[IOC] ThreatFox: {len(new_ips)} IPs, {len(new_hashes)} hashes")
        except Exception as e: log.warning(f"[IOC] ThreatFox failed: {e}")
        # ── OTX AlienVault pulses
        otx_key = _get_env("OTX_API_KEY")
        if otx_key:
            try:
                headers = {"X-OTX-API-KEY": otx_key}
                r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
                                 headers=headers, timeout=15)
                for pulse in r.json().get("results",[]):
                    for ind in pulse.get("indicators",[]):
                        if ind.get("type") == "IPv4": new_ips.add(ind["indicator"])
                        elif ind.get("type") in ("FileHash-MD5","FileHash-SHA256"): new_hashes.add(ind["indicator"])
                log.info(f"[IOC] OTX: added to feed")
            except Exception as e: log.warning(f"[IOC] OTX failed: {e}")
        # ── Abuse.ch URLhaus
        try:
            r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=15)
            urls = set()
            for line in r.text.splitlines():
                if line and not line.startswith("#"):
                    parts = line.split(",")
                    if len(parts) > 2: urls.add(parts[2].strip('"'))
            with self._lock:
                self._malicious_urls = urls
            log.info(f"[IOC] URLhaus: {len(urls)} malicious URLs")
        except Exception as e: log.warning(f"[IOC] URLhaus failed: {e}")
        with self._lock:
            self._malicious_ips   |= new_ips
            self._c2_ips          |= new_c2
            self._malicious_hashes|= new_hashes
            self._last_update      = time.time()
        self._save_cache()
        log.info(f"[IOC] Feeds updated: {len(self._malicious_ips)} IPs, {len(self._c2_ips)} C2 IPs")

    def is_malicious_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            if ip in self._c2_ips: return "C2_SERVER"
            if ip in self._malicious_ips: return "KNOWN_MALICIOUS"
            if ip in self._apt_ips: return f"APT:{self._apt_ips[ip]}"
        return None

    def is_malicious_hash(self, h: str) -> bool:
        with self._lock: return h.lower() in self._malicious_hashes

    def is_malicious_url(self, url: str) -> bool:
        with self._lock: return any(u in url for u in self._malicious_urls)

    def get_stats(self) -> dict:
        with self._lock:
            return {"ips":len(self._malicious_ips),"c2_ips":len(self._c2_ips),
                    "hashes":len(self._malicious_hashes),"urls":len(self._malicious_urls),
                    "last_update": datetime.fromtimestamp(self._last_update).isoformat() if self._last_update else "never"}

# ══════════════════════════════════════════════════════════════════
# GEO/ASN ENRICHMENT
# ══════════════════════════════════════════════════════════════════
_geo_cache: Dict[str,dict] = {}
_geo_lock  = threading.Lock()

def enrich_ip(ip: str) -> dict:
    """Get country, city, ASN, org for an IP. Uses ip-api.com (free, no key)."""
    if not ip or _is_private_ip(ip): return {"country":"LAN","org":"Local Network","flag":"🏠"}
    with _geo_lock:
        if ip in _geo_cache: return _geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,as,isp",
                         timeout=5)
        d = r.json()
        if d.get("status") == "success":
            result = {"country":d.get("country","?"),"country_code":d.get("countryCode",""),
                      "city":d.get("city","?"),"org":d.get("org","?"),"asn":d.get("as","?"),
                      "isp":d.get("isp","?"),"flag":_flag(d.get("countryCode",""))}
            with _geo_lock: _geo_cache[ip] = result
            return result
    except: pass
    return {"country":"Unknown","org":"Unknown","flag":"🌐"}

def _flag(cc: str) -> str:
    if len(cc) != 2: return "🌐"
    return chr(0x1F1E6+ord(cc[0])-65)+chr(0x1F1E6+ord(cc[1])-65)

# ══════════════════════════════════════════════════════════════════
# THREAT INTEL ENRICHMENT (VT, AbuseIPDB, OTX per-IP)
# ══════════════════════════════════════════════════════════════════
_intel_cache: Dict[str,dict] = {}
_intel_lock  = threading.Lock()

def _load_intel_cache():
    global _intel_cache
    try:
        if INTEL_CACHE.exists(): _intel_cache = json.loads(INTEL_CACHE.read_text())
    except: pass
_load_intel_cache()

def enrich_ip_threat_intel(ip: str) -> dict:
    """Full threat intel lookup: VT + AbuseIPDB + OTX. Cached per IP."""
    if not ip or _is_private_ip(ip): return {"score":0,"verdict":"LOCAL"}
    with _intel_lock:
        cached = _intel_cache.get(ip)
        if cached and time.time() - cached.get("_ts",0) < 86400: return cached
    result = {"ip":ip,"score":0,"verdict":"UNKNOWN","vt":{},"abuse":{},"otx":{},"_ts":time.time()}
    # ── VirusTotal
    vt_key = _get_env("VT_API_KEY")
    if vt_key:
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                             headers={"x-apikey":vt_key}, timeout=10)
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                mal = stats.get("malicious",0); sus = stats.get("suspicious",0)
                result["vt"] = {"malicious":mal,"suspicious":sus,"harmless":stats.get("harmless",0)}
                result["score"] = max(result["score"], min(100, (mal*10)+(sus*5)))
        except: pass
    # ── AbuseIPDB
    abuse_key = _get_env("ABUSEIPDB_API_KEY")
    if abuse_key:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key":abuse_key,"Accept":"application/json"},
                             params={"ipAddress":ip,"maxAgeInDays":90}, timeout=10)
            if r.status_code == 200:
                d = r.json().get("data",{})
                score = d.get("abuseConfidenceScore",0)
                result["abuse"] = {"score":score,"totalReports":d.get("totalReports",0),
                                   "countryCode":d.get("countryCode","?"),
                                   "usageType":d.get("usageType","?")}
                result["score"] = max(result["score"], score)
        except: pass
    # ── OTX
    otx_key = _get_env("OTX_API_KEY")
    if otx_key:
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                             headers={"X-OTX-API-KEY":otx_key}, timeout=10)
            if r.status_code == 200:
                d = r.json()
                pulses = d.get("pulse_info",{}).get("count",0)
                result["otx"] = {"pulses":pulses,"malware_families":d.get("malware_families",[])}
                if pulses > 0: result["score"] = max(result["score"], min(100, pulses*15))
        except: pass
    # Verdict
    s = result["score"]
    result["verdict"] = "CRITICAL" if s>=80 else "HIGH" if s>=50 else "MEDIUM" if s>=20 else "CLEAN"
    with _intel_lock:
        _intel_cache[ip] = result
        if len(_intel_cache) % 20 == 0:
            try: INTEL_CACHE.write_text(json.dumps(_intel_cache))
            except: pass
    return result

# ══════════════════════════════════════════════════════════════════
# BEHAVIORAL BASELINE ENGINE
# ══════════════════════════════════════════════════════════════════
class BaselineEngine:
    """Learns normal traffic patterns and detects anomalies."""
    def __init__(self):
        self.baseline = self._load()
        self._observations = defaultdict(list)  # metric → [values]
        self._learning     = True
        self._learn_until  = time.time() + 300  # learn for 5 min
        self._lock         = threading.Lock()
        log.info("[Baseline] Behavioral engine initialized")

    def _load(self) -> dict:
        try:
            if BASELINE_FILE.exists(): return json.loads(BASELINE_FILE.read_text())
        except: pass
        return {}

    def _save(self):
        try: BASELINE_FILE.write_text(json.dumps(self.baseline))
        except: pass

    def observe(self, metric: str, value: float):
        """Record a metric observation."""
        with self._lock:
            self._observations[metric].append(value)
            if len(self._observations[metric]) > 1000:
                self._observations[metric] = self._observations[metric][-500:]
            # Rebuild baseline periodically
            if time.time() < self._learn_until:
                obs = self._observations[metric]
                if len(obs) >= 10:
                    mean = sum(obs)/len(obs)
                    std  = math.sqrt(sum((x-mean)**2 for x in obs)/len(obs))
                    self.baseline[metric] = {"mean":mean,"std":max(std,0.1),"n":len(obs)}
                    self._save()

    def is_anomaly(self, metric: str, value: float, sigma: float = 3.0) -> Optional[str]:
        """Return anomaly description if value deviates >sigma standard deviations."""
        with self._lock:
            b = self.baseline.get(metric)
            if not b or b.get("n",0) < 30: return None  # not enough data
            z = abs(value - b["mean"]) / b["std"]
            if z > sigma:
                direction = "high" if value > b["mean"] else "low"
                return f"{metric} is {value:.1f} ({direction}, z={z:.1f}σ, baseline={b['mean']:.1f})"
        return None

    def reset_learning(self):
        with self._lock:
            self._observations.clear()
            self.baseline.clear()
            self._learn_until = time.time() + 300
            self._learning = True
        self._save()

# ══════════════════════════════════════════════════════════════════
# IPS ENGINE — Active blocking and packet injection
# ══════════════════════════════════════════════════════════════════
class IPSEngine:
    """Active Intrusion Prevention: auto-block IPs, inject TCP RST, rate-limit."""
    def __init__(self):
        self._blocked:   Dict[str,dict] = self._load_blocked()
        self._whitelist: Set[str]       = {"127.0.0.1","::1","0.0.0.0"}
        self._lock       = threading.Lock()
        self._enabled    = False
        self._auto_block = _get_env("SOAR_AUTO_BLOCK").lower() == "true"
        log.info(f"[IPS] Engine init — auto_block={self._auto_block}")

    def _load_blocked(self) -> dict:
        try:
            if BLOCKED_FILE.exists(): return json.loads(BLOCKED_FILE.read_text())
        except: pass
        return {}

    def _save_blocked(self):
        try: BLOCKED_FILE.write_text(json.dumps(self._blocked))
        except: pass

    def block_ip(self, ip: str, reason: str = "", duration_minutes: int = 60) -> bool:
        """Block an IP using iptables. Returns True if successful."""
        if not ip or ip in self._whitelist: return False
        if _is_private_ip(ip) and not _get_env("IPS_BLOCK_LAN"): return False
        with self._lock:
            if ip in self._blocked: return True  # already blocked
        try:
            # Add iptables DROP rule
            subprocess.run(["iptables","-I","INPUT","-s",ip,"-j","DROP"], check=True, capture_output=True)
            subprocess.run(["iptables","-I","OUTPUT","-d",ip,"-j","DROP"], capture_output=True)
            entry = {"ip":ip,"reason":reason,"blocked_at":datetime.now(timezone.utc).isoformat(),
                     "expires": (datetime.now(timezone.utc)+timedelta(minutes=duration_minutes)).isoformat(),
                     "duration_minutes":duration_minutes}
            with self._lock:
                self._blocked[ip] = entry
            self._save_blocked()
            log.warning(f"[IPS] BLOCKED: {ip} — {reason}")
            # Schedule unblock
            threading.Thread(target=self._auto_unblock, args=(ip,duration_minutes*60), daemon=True).start()
            return True
        except Exception as e:
            log.error(f"[IPS] Block failed for {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove iptables block."""
        try:
            subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"], capture_output=True)
            subprocess.run(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"], capture_output=True)
            with self._lock:
                self._blocked.pop(ip, None)
            self._save_blocked()
            log.info(f"[IPS] UNBLOCKED: {ip}")
            return True
        except Exception as e:
            log.error(f"[IPS] Unblock failed: {e}"); return False

    def _auto_unblock(self, ip: str, delay: float):
        time.sleep(delay)
        self.unblock_ip(ip)

    def send_tcp_rst(self, src_ip: str, dst_ip: str, sport: int, dport: int) -> bool:
        """Inject TCP RST to terminate a connection."""
        try:
            import scapy.all as scapy
            pkt = scapy.IP(src=src_ip,dst=dst_ip)/scapy.TCP(sport=sport,dport=dport,flags="R")
            scapy.send(pkt, verbose=False)
            log.info(f"[IPS] TCP RST sent: {src_ip}:{sport} → {dst_ip}:{dport}")
            return True
        except Exception as e: log.error(f"[IPS] RST failed: {e}"); return False

    def should_auto_block(self, severity: str, attack_type: str) -> bool:
        if not self._auto_block: return False
        auto_block_types = {"syn_flood","c2_beacon","known_rat_port","arp_spoof","dhcp_rogue",
                            "smb_relay","pass_the_hash","kerberoast","llmnr_poison"}
        return severity == "CRITICAL" and attack_type in auto_block_types

    def get_blocked(self) -> list:
        with self._lock: return list(self._blocked.values())

    def is_blocked(self, ip: str) -> bool:
        with self._lock: return ip in self._blocked

# ══════════════════════════════════════════════════════════════════
# FILE EXTRACTOR — Extract HTTP/SMB objects, hash + VT check
# ══════════════════════════════════════════════════════════════════
class FileExtractor:
    """Extract files from HTTP/SMB/FTP traffic, compute hashes, check VT."""
    def __init__(self):
        self._extracted: list = []
        self._lock = threading.Lock()

    def extract_http_object(self, payload: str, src_ip: str, dst_ip: str, url: str = "") -> Optional[dict]:
        """Extract file from HTTP response payload."""
        try:
            # Look for HTTP response with file content
            if "content-disposition" in payload.lower() or any(
                sig in payload[:100].lower() for sig in ["pk\x03\x04","mz","pdf","png","gif","jpg","elf","\x7felf"]):
                data = payload.encode("latin1","ignore")
                md5    = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                ext    = self._guess_ext(data[:16])
                fname  = f"extracted_{md5[:8]}{ext}"
                fpath  = EXTRACT_DIR / fname
                fpath.write_bytes(data)
                entry = {"filename":fname,"path":str(fpath),"md5":md5,"sha256":sha256,
                         "size":len(data),"src":src_ip,"dst":dst_ip,"url":url,
                         "extracted_at":datetime.now(timezone.utc).isoformat(),
                         "vt_result":None}
                with self._lock: self._extracted.append(entry)
                # VT check in background
                threading.Thread(target=self._vt_check, args=(entry,), daemon=True).start()
                log.info(f"[Extract] File extracted: {fname} ({len(data)}b)")
                return entry
        except: pass
        return None

    def _guess_ext(self, header: bytes) -> str:
        sigs = {b"MZ":".exe",b"PK":".zip",b"\x7fELF":".elf",b"%PDF":".pdf",
                b"\x89PNG":".png",b"GIF8":".gif",b"\xff\xd8\xff":".jpg"}
        h = header[:4]
        for sig,ext in sigs.items():
            if h.startswith(sig): return ext
        return ".bin"

    def _vt_check(self, entry: dict):
        vt_key = _get_env("VT_API_KEY")
        if not vt_key: return
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{entry['sha256']}",
                             headers={"x-apikey":vt_key}, timeout=15)
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                entry["vt_result"] = {"malicious":stats.get("malicious",0),
                                      "suspicious":stats.get("suspicious",0),
                                      "harmless":stats.get("harmless",0)}
                log.info(f"[Extract] VT result for {entry['filename']}: {entry['vt_result']}")
        except: pass

    def submit_to_sandbox(self, entry: dict) -> Optional[str]:
        """Submit extracted file to any.run sandbox."""
        # any.run API (requires key — optional)
        anyrun_key = _get_env("ANYRUN_API_KEY")
        if not anyrun_key: return None
        try:
            fpath = Path(entry["path"])
            if not fpath.exists(): return None
            r = requests.post("https://api.any.run/v1/analysis",
                              headers={"Authorization":f"API-Key {anyrun_key}"},
                              files={"file":open(str(fpath),"rb")},
                              data={"obj_type":"file","env_os":"windows","env_version":"10"},
                              timeout=30)
            if r.status_code == 200:
                task_id = r.json().get("data",{}).get("taskid","")
                url = f"https://app.any.run/tasks/{task_id}"
                entry["sandbox_url"] = url
                log.info(f"[Extract] Sandbox submitted: {url}")
                return url
        except Exception as e: log.error(f"[Extract] Sandbox failed: {e}")
        return None

    def get_extracted(self) -> list:
        with self._lock: return list(self._extracted)

# ══════════════════════════════════════════════════════════════════
# STIX/TAXII EXPORT
# ══════════════════════════════════════════════════════════════════
def export_stix(alerts: list) -> dict:
    """Export alerts as STIX 2.1 bundle."""
    objects = []
    for a in alerts:
        sdo = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.md5(a.get('id','').encode()).hexdigest()[:8]}-0000-0000-0000-000000000000",
            "created": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "modified": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "name": a.get("attack_name","Unknown"),
            "description": a.get("detail",""),
            "pattern": f"[ipv4-addr:value = '{a.get('source_ip','?')}']",
            "pattern_type": "stix",
            "valid_from": a.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "labels": ["malicious-activity"],
            "external_references": [{"source_name":"MITRE ATT&CK","external_id":a.get("mitre","")}],
        }
        objects.append(sdo)
    return {
        "type": "bundle",
        "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}-0000-0000-0000-000000000000",
        "objects": objects,
    }

# ══════════════════════════════════════════════════════════════════
# APT ATTRIBUTION ENGINE
# ══════════════════════════════════════════════════════════════════
APT_TTP_MAP = {
    # technique → list of APT groups known to use it
    "syn_scan":        ["APT28","APT29","Lazarus Group","FIN7"],
    "rdp_brute":       ["APT41","Lazarus Group","FIN8","REvil","Ryuk"],
    "smb_brute":       ["APT28","NotPetya","WannaCry","EternalBlue"],
    "kerberoast":      ["APT29","APT40","FIN6"],
    "pass_the_hash":   ["APT28","APT29","APT41"],
    "c2_beacon":       ["APT28","APT29","Cobalt Strike","APT41","Lazarus Group"],
    "dns_tunnel":      ["APT34","OilRig","APT29","FIN7"],
    "dga_domain":      ["Emotet","TrickBot","Dridex","APT40"],
    "smb_relay":       ["APT28","Responder","impacket"],
    "llmnr_poison":    ["APT28","FIN6","Carbanak"],
    "data_exfil":      ["APT10","APT41","FIN5","APT34"],
    "sql_injection":   ["APT28","FIN7","MageCart","APT41"],
    "cmd_injection":   ["APT28","APT34","APT29"],
    "ldap_brute":      ["APT29","APT40","Fancy Bear"],
    "icmp_tunnel":     ["APT34","OilRig","APT29"],
    "tor_traffic":     ["APT28","APT29","Lazarus Group","FIN7"],
    "arp_spoof":       ["APT29","Dragonfly","TEMP.Veles"],
    "dhcp_rogue":      ["Dragonfly","TEMP.Veles","APT33"],
    "wmi_abuse":       ["APT29","APT41","FIN7","Cobalt Strike"],
    "psexec_detected": ["APT28","APT29","APT41","Lazarus Group"],
    "syn_flood":       ["Lazarus Group","APT28","Anonymous"],
    "ssh_brute":       ["Lazarus Group","APT28","FIN10","APT38"],
}

def get_apt_attribution(attack_type: str) -> list:
    return APT_TTP_MAP.get(attack_type, [])

# ══════════════════════════════════════════════════════════════════
# PCAP WRITER
# ══════════════════════════════════════════════════════════════════
class PCAPWriter:
    """Write captured packets to real .pcap format files."""
    PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    def __init__(self, filename: str):
        self.path = PCAP_DIR / filename
        self._f   = open(str(self.path), "wb")
        self._f.write(self.PCAP_GLOBAL_HEADER)
        self._lock = threading.Lock()
        self.count = 0

    def write_packet(self, raw_bytes: bytes):
        """Write a raw packet to pcap file."""
        try:
            with self._lock:
                ts = time.time()
                ts_sec  = int(ts)
                ts_usec = int((ts % 1) * 1000000)
                plen    = len(raw_bytes)
                header  = struct.pack("<IIII", ts_sec, ts_usec, plen, plen)
                self._f.write(header + raw_bytes)
                self._f.flush()
                self.count += 1
        except: pass

    def close(self) -> str:
        try: self._f.close()
        except: pass
        return str(self.path)

# ══════════════════════════════════════════════════════════════════
# PROTOCOL DISSECTORS
# ══════════════════════════════════════════════════════════════════
class ProtocolDissectors:
    """Deep packet inspection dissectors for common protocols."""

    @staticmethod
    def dissect_http(payload: str) -> dict:
        lines = payload.split("\r\n") if "\r\n" in payload else payload.split("\n")
        if not lines: return {}
        d = {"raw": payload[:2000]}
        first = lines[0]
        if first.startswith(("GET ","POST ","PUT ","DELETE ","HEAD ","OPTIONS ")):
            parts = first.split(" ")
            d.update({"type":"REQUEST","method":parts[0],"uri":parts[1] if len(parts)>1 else "","version":parts[2] if len(parts)>2 else ""})
        elif first.startswith("HTTP/"):
            parts = first.split(" ",2)
            d.update({"type":"RESPONSE","version":parts[0],"status":parts[1] if len(parts)>1 else "","reason":parts[2] if len(parts)>2 else ""})
        for line in lines[1:]:
            if ":" in line:
                k,v = line.split(":",1)
                d[k.strip().lower()] = v.strip()
            if not line: break
        return d

    @staticmethod
    def dissect_dns(payload: bytes) -> dict:
        try:
            if len(payload) < 12: return {}
            txid = struct.unpack(">H", payload[:2])[0]
            flags = struct.unpack(">H", payload[2:4])[0]
            qr = (flags >> 15) & 1
            opcode = (flags >> 11) & 0xF
            qdcount = struct.unpack(">H", payload[4:6])[0]
            ancount = struct.unpack(">H", payload[6:8])[0]
            return {"txid":txid,"qr":"response" if qr else "query","opcode":opcode,
                    "qdcount":qdcount,"ancount":ancount,"flags":hex(flags)}
        except: return {}

    @staticmethod
    def dissect_tls(payload: bytes) -> dict:
        try:
            if len(payload) < 5: return {}
            content_type = payload[0]
            version = struct.unpack(">H", payload[1:3])[0]
            length  = struct.unpack(">H", payload[3:5])[0]
            types   = {20:"ChangeCipherSpec",21:"Alert",22:"Handshake",23:"ApplicationData"}
            versions= {0x0300:"SSLv3",0x0301:"TLS 1.0",0x0302:"TLS 1.1",0x0303:"TLS 1.2",0x0304:"TLS 1.3"}
            result  = {"content_type":types.get(content_type,str(content_type)),
                       "version":versions.get(version,hex(version)),"length":length}
            if content_type == 22 and len(payload) > 5:
                hs_type = payload[5]
                hs_types = {1:"ClientHello",2:"ServerHello",11:"Certificate",12:"ServerKeyExchange",
                            14:"ServerHelloDone",16:"ClientKeyExchange",20:"Finished"}
                result["handshake_type"] = hs_types.get(hs_type, str(hs_type))
                if hs_type == 1 and len(payload) > 9:
                    ch_ver = struct.unpack(">H", payload[9:11])[0]
                    result["client_hello_version"] = versions.get(ch_ver, hex(ch_ver))
            return result
        except: return {}

    @staticmethod
    def dissect_smb(payload: bytes) -> dict:
        try:
            if len(payload) < 4: return {}
            if payload[:4] == b"\xffSMB":
                cmd = payload[4]
                cmds = {0x72:"Negotiate",0x73:"SessionSetup",0x75:"TreeConnect",0x25:"Trans",
                        0x2f:"WriteRaw",0xa5:"TreeConnectAndX"}
                return {"version":"SMB1","command":cmds.get(cmd,hex(cmd)),"status":hex(struct.unpack("<I",payload[5:9])[0]) if len(payload)>9 else "?"}
            elif payload[:4] == b"\xfeSMB":
                cmd = struct.unpack("<H", payload[12:14])[0] if len(payload)>14 else 0
                cmds = {0:"Negotiate",1:"SessionSetup",3:"TreeConnect",5:"Create",6:"Close",8:"Read",9:"Write"}
                return {"version":"SMB2","command":cmds.get(cmd,hex(cmd))}
        except: pass
        return {}


# ══════════════════════════════════════════════════════════════════
# FULL ATTACK PROFILES (same as v2 + new ones for IPS/IOC context)
# ══════════════════════════════════════════════════════════════════
ATTACK_PROFILES = {
    "syn_scan":        {"name":"SYN Port Scan","severity":"HIGH","mitre":"T1046","mitre_name":"Network Service Scanning","priority":7,"description":"Half-open SYN scan — attacker mapping open services.","response":["Log source IP","Rate-limit or block","Monitor for follow-on activity"]},
    "fin_scan":        {"name":"FIN Stealth Scan","severity":"HIGH","mitre":"T1046","mitre_name":"Network Service Scanning","priority":8,"description":"FIN-only packets bypass basic firewalls.","response":["Block source IP","Enable stateful inspection"]},
    "xmas_scan":       {"name":"XMAS Scan","severity":"HIGH","mitre":"T1046","mitre_name":"Network Service Scanning","priority":8,"description":"FIN+PSH+URG flags — stealth scan.","response":["Block immediately","Alert security team"]},
    "null_scan":       {"name":"NULL Scan","severity":"HIGH","mitre":"T1046","mitre_name":"Network Service Scanning","priority":8,"description":"Zero TCP flags evasion scan.","response":["Block source IP","IDS signature update"]},
    "ack_scan":        {"name":"ACK Scan","severity":"MEDIUM","mitre":"T1046","mitre_name":"Network Service Scanning","priority":6,"description":"Maps firewall rules.","response":["Log and monitor"]},
    "window_scan":     {"name":"TCP Window Scan","severity":"MEDIUM","mitre":"T1046","mitre_name":"Network Service Scanning","priority":6,"description":"Advanced nmap scan.","response":["Log source IP"]},
    "udp_scan":        {"name":"UDP Port Scan","severity":"MEDIUM","mitre":"T1046","mitre_name":"Network Service Scanning","priority":6,"description":"Probes UDP services.","response":["Review UDP services"]},
    "os_fingerprint":  {"name":"OS Fingerprinting","severity":"MEDIUM","mitre":"T1592","mitre_name":"Gather Victim Host Info","priority":6,"description":"Active OS fingerprinting.","response":["Log activity"]},
    "service_enum":    {"name":"Service Enumeration","severity":"MEDIUM","mitre":"T1590","mitre_name":"Gather Victim Network Info","priority":6,"description":"Banner grabbing.","response":["Disable banner disclosure"]},
    "ping_sweep":      {"name":"ICMP Ping Sweep","severity":"LOW","mitre":"T1018","mitre_name":"Remote System Discovery","priority":4,"description":"Discovering live hosts.","response":["Log sweep source"]},
    "ssh_brute":       {"name":"SSH Brute Force","severity":"CRITICAL","mitre":"T1110.001","mitre_name":"Brute Force","priority":9,"description":"Rapid SSH login attempts.","response":["Block IP","Enable fail2ban","Force key-based auth"]},
    "rdp_brute":       {"name":"RDP Brute Force","severity":"CRITICAL","mitre":"T1110.001","mitre_name":"Brute Force","priority":9,"description":"Ransomware entry vector.","response":["Block source IP","Disable public RDP"]},
    "ftp_brute":       {"name":"FTP Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":8,"description":"FTP credential attack.","response":["Block source IP","Migrate to SFTP"]},
    "http_brute":      {"name":"HTTP Login Brute Force","severity":"HIGH","mitre":"T1110.001","mitre_name":"Credential Stuffing","priority":8,"description":"Credential stuffing attack.","response":["Enable CAPTCHA","Rate-limit logins"]},
    "smb_brute":       {"name":"SMB/Windows Brute Force","severity":"CRITICAL","mitre":"T1110","mitre_name":"Brute Force","priority":9,"description":"SMB auth brute force.","response":["Block source IP","Enable account lockout"]},
    "ldap_brute":      {"name":"LDAP/AD Brute Force","severity":"CRITICAL","mitre":"T1110","mitre_name":"Brute Force","priority":9,"description":"Active Directory attack.","response":["Block source","Enable AD lockout policy"]},
    "vnc_brute":       {"name":"VNC Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":8,"description":"VNC password guessing.","response":["Block source IP","Require VNC auth"]},
    "mysql_brute":     {"name":"MySQL Brute Force","severity":"CRITICAL","mitre":"T1110","mitre_name":"Brute Force","priority":9,"description":"Database auth attack.","response":["Block source IP","Restrict MySQL to localhost"]},
    "telnet_brute":    {"name":"Telnet Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":8,"description":"Cleartext brute force.","response":["Disable Telnet","Migrate to SSH"]},
    "smtp_brute":      {"name":"SMTP Auth Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":7,"description":"Email account attack.","response":["Block source IP","Enable MFA"]},
    "imap_brute":      {"name":"IMAP Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":7,"description":"Mailbox credential attack.","response":["Block source","Enable MFA"]},
    "pop3_brute":      {"name":"POP3 Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":7,"description":"POP3 email brute force.","response":["Block source IP","Enable MFA"]},
    "kerberos_brute":  {"name":"Kerberoasting","severity":"CRITICAL","mitre":"T1558.003","mitre_name":"Kerberoasting","priority":10,"description":"Kerberos hash harvesting.","response":["Alert AD team immediately","Enable AES-only Kerberos"]},
    "winrm_brute":     {"name":"WinRM Brute Force","severity":"CRITICAL","mitre":"T1110","mitre_name":"Brute Force","priority":9,"description":"Windows remote management attack.","response":["Block source IP","Restrict WinRM"]},
    "redis_brute":     {"name":"Redis Auth Brute Force","severity":"CRITICAL","mitre":"T1110","mitre_name":"Brute Force","priority":9,"description":"Redis RCE risk.","response":["Block source","Bind Redis to 127.0.0.1"]},
    "arp_spoof":       {"name":"ARP Spoofing / MITM","severity":"CRITICAL","mitre":"T1557.002","mitre_name":"ARP Cache Poisoning","priority":10,"description":"LAN traffic interception.","response":["IMMEDIATELY investigate","Enable dynamic ARP inspection"]},
    "dhcp_starvation": {"name":"DHCP Starvation","severity":"HIGH","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":8,"description":"IP pool exhaustion.","response":["Enable DHCP snooping","Port security on switch"]},
    "dhcp_rogue":      {"name":"Rogue DHCP Server","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":10,"description":"Unauthorized DHCP server.","response":["Disable rogue DHCP","Enable DHCP snooping"]},
    "stp_attack":      {"name":"STP Manipulation","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":9,"description":"Root bridge takeover.","response":["Enable BPDU guard","Root guard on access ports"]},
    "vlan_hop":        {"name":"VLAN Hopping","severity":"HIGH","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":8,"description":"VLAN boundary escape.","response":["Disable dynamic trunking"]},
    "ip_fragment":     {"name":"IP Fragmentation Attack","severity":"HIGH","mitre":"T1027","mitre_name":"Obfuscated Files or Information","priority":7,"description":"IDS evasion via fragments.","response":["Enable IP defragmentation on IDS"]},
    "ip_spoof":        {"name":"IP Spoofing","severity":"HIGH","mitre":"T1001","mitre_name":"Data Obfuscation","priority":8,"description":"Spoofed source IPs.","response":["Enable BCP38 filtering"]},
    "c2_beacon":       {"name":"C2 Beaconing","severity":"CRITICAL","mitre":"T1071","mitre_name":"Application Layer Protocol","priority":10,"description":"Malware command & control.","response":["ISOLATE HOST","Block destination IP","Incident response"]},
    "dns_tunnel":      {"name":"DNS Tunneling","severity":"CRITICAL","mitre":"T1071.004","mitre_name":"DNS C2","priority":10,"description":"C2 over DNS.","response":["Block domain at DNS","Isolate host"]},
    "http_c2":         {"name":"HTTP C2","severity":"CRITICAL","mitre":"T1071.001","mitre_name":"Web Protocols C2","priority":10,"description":"HTTP-based C2 traffic.","response":["Block destination IP","Isolate host"]},
    "icmp_tunnel":     {"name":"ICMP Tunneling","severity":"CRITICAL","mitre":"T1095","mitre_name":"Non-Application Layer Protocol","priority":9,"description":"Covert ICMP channel.","response":["Block ICMP to suspicious destinations"]},
    "known_rat_port":  {"name":"Known RAT/Backdoor Port","severity":"CRITICAL","mitre":"T1571","mitre_name":"Non-Standard Port","priority":10,"description":"RAT traffic — Cobalt Strike, njRAT.","response":["ISOLATE HOST","Full AV/EDR scan"]},
    "tor_traffic":     {"name":"Tor Network Traffic","severity":"HIGH","mitre":"T1090.003","mitre_name":"Multi-hop Proxy","priority":8,"description":"Tor C2 anonymisation.","response":["Block Tor exit nodes"]},
    "dga_domain":      {"name":"DGA Domain","severity":"CRITICAL","mitre":"T1568.002","mitre_name":"Domain Generation Algorithms","priority":10,"description":"Malware DGA C2.","response":["Block domain","Isolate host"]},
    "ioc_match":       {"name":"IOC Feed Match","severity":"CRITICAL","mitre":"T1071","mitre_name":"C2 Communication","priority":10,"description":"IP matches live threat intel feed.","response":["BLOCK IP IMMEDIATELY","Full investigation","Incident response"]},
    "data_exfil":      {"name":"Data Exfiltration","severity":"CRITICAL","mitre":"T1048","mitre_name":"Exfiltration","priority":9,"description":"Large outbound transfer.","response":["Block destination IP","Isolate source host"]},
    "dns_exfil":       {"name":"DNS Data Exfiltration","severity":"CRITICAL","mitre":"T1048.003","mitre_name":"Exfiltration Over DNS","priority":10,"description":"Data in DNS queries.","response":["Block DNS to domain","Isolate host"]},
    "large_upload":    {"name":"Suspicious Large Upload","severity":"HIGH","mitre":"T1048","mitre_name":"Exfiltration","priority":7,"description":"Large outbound transfer.","response":["Investigate destination"]},
    "smtp_exfil":      {"name":"Email Exfiltration","severity":"HIGH","mitre":"T1048.002","mitre_name":"Exfiltration Over Email","priority":8,"description":"Mass outbound email.","response":["Review email content","Block bulk outbound"]},
    "sql_injection":   {"name":"SQL Injection","severity":"CRITICAL","mitre":"T1190","mitre_name":"Exploit Public-Facing Application","priority":9,"description":"SQLi attack.","response":["Block source IP","Enable WAF"]},
    "xss_attempt":     {"name":"Cross-Site Scripting","severity":"HIGH","mitre":"T1059.007","mitre_name":"JavaScript Injection","priority":8,"description":"XSS attack.","response":["Enable WAF XSS rules"]},
    "path_traversal":  {"name":"Path Traversal / LFI","severity":"HIGH","mitre":"T1083","mitre_name":"File Discovery","priority":8,"description":"Directory traversal.","response":["Block source IP","Enable WAF"]},
    "cmd_injection":   {"name":"Command Injection","severity":"CRITICAL","mitre":"T1059","mitre_name":"Command Injection","priority":9,"description":"OS command injection.","response":["Block source IP immediately","Emergency patch"]},
    "http_flood":      {"name":"HTTP Flood / L7 DDoS","severity":"HIGH","mitre":"T1499","mitre_name":"Endpoint Denial of Service","priority":8,"description":"Application layer DoS.","response":["Rate-limit source IP","Enable WAF"]},
    "web_scan":        {"name":"Web Application Scanning","severity":"MEDIUM","mitre":"T1595","mitre_name":"Active Scanning","priority":6,"description":"Automated web scanner.","response":["Block scanner IP"]},
    "smb_relay":       {"name":"SMB Relay Attack","severity":"CRITICAL","mitre":"T1557.001","mitre_name":"LLMNR/NBT-NS and SMB Relay","priority":10,"description":"NTLM relay attack.","response":["Enable SMB signing IMMEDIATELY"]},
    "pass_the_hash":   {"name":"Pass-the-Hash","severity":"CRITICAL","mitre":"T1550.002","mitre_name":"Pass the Hash","priority":10,"description":"NTLM hash replay.","response":["Isolate affected hosts","Reset accounts"]},
    "wmi_abuse":       {"name":"WMI Remote Execution","severity":"CRITICAL","mitre":"T1047","mitre_name":"Windows Management Instrumentation","priority":9,"description":"WMI lateral movement.","response":["Block WMI remotely","Alert SOC"]},
    "psexec_detected": {"name":"PsExec / Remote Admin","severity":"HIGH","mitre":"T1570","mitre_name":"Lateral Tool Transfer","priority":8,"description":"Remote admin tool.","response":["Verify if authorised"]},
    "dcom_exploit":    {"name":"DCOM Exploitation","severity":"CRITICAL","mitre":"T1021.003","mitre_name":"Remote Services — DCOM","priority":9,"description":"DCOM lateral movement.","response":["Block DCOM remotely","Isolate source"]},
    "syn_flood":       {"name":"SYN Flood DDoS","severity":"CRITICAL","mitre":"T1498.001","mitre_name":"Network Denial of Service","priority":9,"description":"SYN flood attack.","response":["Enable SYN cookies","DDoS mitigation"]},
    "udp_flood":       {"name":"UDP Flood DDoS","severity":"HIGH","mitre":"T1498","mitre_name":"Network Denial of Service","priority":8,"description":"UDP amplification.","response":["Rate-limit UDP traffic"]},
    "icmp_flood":      {"name":"ICMP Flood","severity":"HIGH","mitre":"T1498","mitre_name":"Network Denial of Service","priority":8,"description":"ICMP flood attack.","response":["Block source IP","Rate-limit ICMP"]},
    "slowloris":       {"name":"Slowloris Attack","severity":"HIGH","mitre":"T1499","mitre_name":"Endpoint Denial of Service","priority":8,"description":"Slow HTTP DoS.","response":["Set HTTP timeout","Limit connections per IP"]},
    "fragmentation_dos":{"name":"Fragmentation DoS","severity":"HIGH","mitre":"T1498","mitre_name":"Network Denial of Service","priority":7,"description":"Fragment buffer overflow.","response":["Enable fragment normalisation"]},
    "plaintext_cred":  {"name":"Plaintext Credentials","severity":"HIGH","mitre":"T1040","mitre_name":"Network Sniffing","priority":8,"description":"Credentials in cleartext.","response":["Migrate to HTTPS/SSH"]},
    "ntlm_hash":       {"name":"NTLM Hash Capture","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":10,"description":"NTLM hash harvesting.","response":["Enable SMB signing","Disable NTLMv1"]},
    "llmnr_poison":    {"name":"LLMNR/NBT-NS Poisoning","severity":"CRITICAL","mitre":"T1557.001","mitre_name":"LLMNR Poisoning","priority":10,"description":"Responder tool attack.","response":["DISABLE LLMNR AND NBT-NS"]},
    "snmp_weak":       {"name":"SNMP Weak Community String","severity":"HIGH","mitre":"T1602.001","mitre_name":"Network Device Configuration","priority":7,"description":"Default SNMP credentials.","response":["Change community strings","Migrate to SNMPv3"]},
    "kerberoast":      {"name":"Kerberoasting","severity":"CRITICAL","mitre":"T1558.003","mitre_name":"Steal Kerberos Tickets","priority":10,"description":"Service ticket hash cracking.","response":["Alert AD team","Strong service account passwords"]},
    "ssl_downgrade":   {"name":"SSL/TLS Downgrade","severity":"CRITICAL","mitre":"T1600","mitre_name":"Weaken Encryption","priority":9,"description":"Downgrade to weak crypto.","response":["Disable SSLv3/TLS1.0","Enforce TLS 1.2+"]},
    "ssl_stripping":   {"name":"SSL Stripping","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":9,"description":"HTTPS → HTTP MITM.","response":["Enable HSTS","Certificate pinning"]},
    "dns_spoof":       {"name":"DNS Spoofing","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":9,"description":"Forged DNS responses.","response":["Enable DNSSEC","DNS-over-HTTPS"]},
    "suspicious_protocol":{"name":"Suspicious Protocol","severity":"HIGH","mitre":"T1090","mitre_name":"Proxy","priority":7,"description":"Tor/anonymiser traffic.","response":["Block Tor exit ports"]},
    "off_hours_access":{"name":"Off-Hours Network Access","severity":"MEDIUM","mitre":"T1078","mitre_name":"Valid Accounts","priority":5,"description":"After-hours activity.","response":["Verify with account owner"]},
    "mass_file_access":{"name":"Mass File Access / Ransomware","severity":"CRITICAL","mitre":"T1486","mitre_name":"Data Encrypted for Impact","priority":10,"description":"Ransomware encryption in progress.","response":["IMMEDIATELY isolate host","Disconnect from network"]},
    "new_external_dest":{"name":"New External Destination","severity":"LOW","mitre":"T1041","mitre_name":"Exfiltration Over C2","priority":4,"description":"New outbound destination.","response":["Log destination","Monitor for data volume"]},
    "voip_flood":      {"name":"VoIP/SIP Flood","severity":"HIGH","mitre":"T1498","mitre_name":"Network Denial of Service","priority":7,"description":"SIP flooding attack.","response":["Rate-limit SIP","Block source IP"]},
    "behavioral_anomaly":{"name":"Behavioral Anomaly","severity":"MEDIUM","mitre":"T1071","mitre_name":"Application Layer Protocol","priority":6,"description":"Traffic deviates from learned baseline.","response":["Investigate source host","Compare against baseline"]},
    "port_scan":       {"name":"Port Scan","severity":"MEDIUM","mitre":"T1046","mitre_name":"Network Service Scanning","priority":5,"description":"Multiple port probing.","response":["Monitor source IP"]},
    "brute_force":     {"name":"Brute Force","severity":"HIGH","mitre":"T1110","mitre_name":"Brute Force","priority":8,"description":"Credential brute force.","response":["Block source IP"]},
    "mitm":            {"name":"Man-in-the-Middle","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":10,"description":"Active MITM attack.","response":["Immediate incident response"]},
    "arp_poison":      {"name":"ARP Cache Poisoning","severity":"CRITICAL","mitre":"T1557","mitre_name":"Adversary-in-the-Middle","priority":10,"description":"ARP poisoning.","response":["Block rogue MAC","Enable port security"]},
    "malware_c2":      {"name":"Known Malware C2","severity":"CRITICAL","mitre":"T1071","mitre_name":"C2 Communication","priority":10,"description":"Known C2 infrastructure.","response":["ISOLATE HOST","Block C2 IP"]},
}

C2_PORTS = {4444,4445,4446,5555,6666,7777,8888,9999,1234,12345,54321,31337,50050,50051,8443,4433,4242,1177,5552,1604,6703,447,449,8082,6667,6668,6697,6699,9001,9030,9050,9051,9150,2222,2323,31338,65535,1023,3460,8000}
BRUTE_FORCE_PORTS = {22:"ssh_brute",2222:"ssh_brute",2200:"ssh_brute",3389:"rdp_brute",3388:"rdp_brute",21:"ftp_brute",990:"ftp_brute",80:"http_brute",443:"http_brute",8080:"http_brute",8443:"http_brute",445:"smb_brute",139:"smb_brute",389:"ldap_brute",636:"ldap_brute",5900:"vnc_brute",5901:"vnc_brute",3306:"mysql_brute",23:"telnet_brute",25:"smtp_brute",465:"smtp_brute",587:"smtp_brute",143:"imap_brute",993:"imap_brute",110:"pop3_brute",995:"pop3_brute",88:"kerberos_brute",749:"kerberos_brute",5985:"winrm_brute",5986:"winrm_brute",6379:"redis_brute",6380:"redis_brute",5432:"brute_force",1433:"brute_force",1521:"brute_force",27017:"brute_force"}
SQL_PATTERNS = ["union select","union all select","or 1=1","or '1'='1","drop table","exec(","xp_cmdshell","information_schema","sleep(","benchmark(","load_file(","outfile","0x","concat(","hex("]
XSS_PATTERNS = ["<script","javascript:","onerror=","onload=","onclick=","alert(","document.cookie","eval(","fromcharcode"]
PATH_PATTERNS = ["../","..\\","..%2f","..%5c","/etc/passwd","/etc/shadow","windows/system32","boot.ini"]
CMD_PATTERNS  = [";ls","&&ls","||ls",";cat ","|cat ",";id;","&&id","||id",";whoami",";uname",";wget","`;","$("]
WEBSCANNER_UA = ["nikto","nessus","openvas","w3af","sqlmap","masscan","nuclei","dirbuster","gobuster","ffuf","wfuzz"]

def _domain_entropy(d: str) -> float:
    label = d.split(".")[0] if "." in d else d
    if len(label)<8: return 0.0
    freq = Counter(label); l = len(label)
    return -sum((c/l)*math.log2(c/l) for c in freq.values())

def _is_dga(domain: str) -> bool:
    label = domain.split(".")[0] if "." in domain else domain
    if len(label)<10: return False
    vowels = sum(1 for c in label if c in "aeiou")
    return _domain_entropy(domain) > 3.5 and (1-vowels/len(label)) > 0.7

def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts)!=4: return False
        return (parts[0]==10 or (parts[0]==172 and 16<=parts[1]<=31) or
                (parts[0]==192 and parts[1]==168) or parts[0]==127 or parts[0]==169)
    except: return False

# Alert storage
_alerts_lock = threading.Lock()
_live_alerts  = deque(maxlen=2000)

def _save_alert(alert: dict):
    with _alerts_lock: _live_alerts.appendleft(alert)
    try:
        existing = []
        if ALERTS_FILE.exists():
            try: existing = json.loads(ALERTS_FILE.read_text())
            except: existing = []
        existing.insert(0, alert)
        ALERTS_FILE.write_text(json.dumps(existing[:5000], default=str))
    except: pass

def get_live_alerts(limit: int = 200) -> list:
    with _alerts_lock: return list(_live_alerts)[:limit]

def get_stored_alerts(limit: int = 500) -> list:
    if ALERTS_FILE.exists():
        try: return json.loads(ALERTS_FILE.read_text())[:limit]
        except: pass
    return []

def _ai_analyze_alert(alert: dict) -> dict:
    ollama_url  = _get_env("OLLAMA_URL") or "http://localhost:11434"
    attack_type = alert.get("attack_type","unknown")
    profile     = ATTACK_PROFILES.get(attack_type, {})
    apts        = get_apt_attribution(attack_type)
    geo         = alert.get("geo", {})
    intel       = alert.get("intel", {})
    prompt = f"""You are a senior SOC analyst. Analyse this network alert.

ALERT: {profile.get('name', attack_type)}
SEVERITY: {alert.get('severity','UNKNOWN')}
SOURCE: {alert.get('source_ip','?')} ({geo.get('country','?')} {geo.get('org','?')})
DEST: {alert.get('dest_ip','?')}:{alert.get('port','?')}
DETAIL: {alert.get('detail','')}
MITRE: {profile.get('mitre','')} — {profile.get('mitre_name','')}
APT GROUPS KNOWN TO USE THIS: {', '.join(apts) if apts else 'No specific attribution'}
THREAT INTEL SCORE: {intel.get('score',0)}/100 ({intel.get('verdict','UNKNOWN')})

Reply ONLY as JSON (no other text):
{{"plain_english":"one sentence","business_impact":"one sentence","recommended_action":"most important action","priority_score":8,"false_positive_likelihood":"low","apt_attribution":"{apts[0] if apts else 'Unknown'}"}}"""
    try:
        r = requests.post(f"{ollama_url}/api/generate",
                          json={"model":_get_env("OLLAMA_MODEL") or "llama3.2","prompt":prompt,"stream":False},
                          timeout=15)
        if r.status_code==200:
            text = r.json().get("response","").strip()
            text = re.sub(r"```json|```","",text).strip()
            s=text.find("{"); e=text.rfind("}")+1
            if s>=0 and e>s: return json.loads(text[s:e])
    except: pass
    return _rule_based(alert, profile, apts)

def _rule_based(alert, profile, apts=[]) -> dict:
    sev = alert.get("severity","MEDIUM")
    return {
        "plain_english":     profile.get("description","Network threat detected"),
        "business_impact":   {"CRITICAL":"Immediate threat — business at risk","HIGH":"Significant risk — urgent investigation","MEDIUM":"Moderate risk — investigate within 24h","LOW":"Low risk — log and monitor"}.get(sev,"Review required"),
        "recommended_action":(profile.get("response",[]) or ["Investigate and log"])[0],
        "priority_score":    {"CRITICAL":9,"HIGH":7,"MEDIUM":5,"LOW":2}.get(sev,5),
        "false_positive_likelihood": {"CRITICAL":"low","HIGH":"low","MEDIUM":"medium","LOW":"high"}.get(sev,"medium"),
        "apt_attribution":   apts[0] if apts else "Unknown",
    }

# ══════════════════════════════════════════════════════════════════
# PACKET ANALYZER v3 — same detections + IOC checks + baseline + file extraction
# ══════════════════════════════════════════════════════════════════
class PacketAnalyzer:
    def __init__(self, ioc_manager: IOCFeedManager, ips_engine: IPSEngine,
                 baseline: BaselineEngine, extractor: FileExtractor):
        self.ioc       = ioc_manager
        self.ips       = ips_engine
        self.baseline  = baseline
        self.extractor = extractor
        self.ip_connections      = defaultdict(lambda: defaultdict(list))
        self.ip_port_attempts    = defaultdict(lambda: defaultdict(int))
        self.ip_byte_counts      = defaultdict(int)
        self.arp_table           = {}
        self.arp_rate            = defaultdict(list)
        self.dhcp_requests       = defaultdict(list)
        self.dhcp_servers        = {}
        self.dns_query_counts    = defaultdict(int)
        self.dns_query_times     = defaultdict(list)
        self.dns_responses       = {}
        self.beacon_tracker      = defaultdict(list)
        self.http_requests       = defaultdict(list)
        self.smb_file_access     = defaultdict(list)
        self.icmp_tracker        = defaultdict(list)
        self.udp_tracker         = defaultdict(list)
        self.syn_tracker         = defaultdict(list)
        self.slow_http           = defaultdict(dict)
        self.seen_external_dests = defaultdict(set)
        self.sip_tracker         = defaultdict(list)
        self.snmp_attempts       = defaultdict(int)
        self._lock               = threading.Lock()
        self._last_cleanup       = time.time()
        self._alerted            = {}
        self.packet_count        = 0
        self.dissectors          = ProtocolDissectors()
        log.info("[Analyzer] PacketAnalyzer v3 initialized — IOC+IPS+Baseline+Extractor")

    def _cooldown(self, key: str, seconds: int = 30) -> bool:
        now = time.time()
        if now - self._alerted.get(key,0) < seconds: return True
        self._alerted[key] = now
        return False

    def _cleanup_old_data(self):
        now = time.time()
        if now - self._last_cleanup < 30: return
        self._last_cleanup = now
        cutoff = now - 300
        with self._lock:
            for d in [self.ip_connections,self.beacon_tracker,self.http_requests,self.smb_file_access,
                      self.icmp_tracker,self.udp_tracker,self.syn_tracker,self.sip_tracker,
                      self.arp_rate,self.dhcp_requests,self.dns_query_times]:
                for k in list(d.keys()):
                    if isinstance(d[k],list): d[k]=[t for t in d[k] if t>cutoff]
                    elif isinstance(d[k],dict):
                        for k2 in list(d[k].keys()):
                            if isinstance(d[k][k2],list): d[k][k2]=[t for t in d[k][k2] if t>cutoff]

    def analyze_packet(self, pkt: dict) -> Optional[dict]:
        self.packet_count += 1
        self._cleanup_old_data()
        src   = pkt.get("src_ip",""); dst = pkt.get("dst_ip","")
        sport = int(pkt.get("src_port",0) or 0); dport = int(pkt.get("dst_port",0) or 0)
        flags = pkt.get("flags",""); proto = pkt.get("protocol","").upper()
        plen  = int(pkt.get("length",0) or 0); payload = str(pkt.get("payload",""))
        pl_low = payload.lower(); iface = pkt.get("interface","")
        if not src or not dst: return None
        if src.startswith("127.") or dst.startswith("127."): return None

        # ── IOC Feed check FIRST (highest priority) ──────────────────
        for ip in (src, dst):
            if ip and not _is_private_ip(ip):
                ioc_type = self.ioc.is_malicious_ip(ip)
                if ioc_type:
                    key = f"ioc_{ip}"
                    if not self._cooldown(key, 300):
                        alert = self._make_alert("ioc_match",src,dst,dport,proto,1,iface,
                            f"IOC MATCH: {ip} flagged as {ioc_type} in live threat feed")
                        # Auto-block if IPS enabled
                        if self.ips.should_auto_block("CRITICAL","ioc_match"):
                            self.ips.block_ip(ip, f"IOC match: {ioc_type}")
                        return alert

        # ── Behavioral baseline check ─────────────────────────────────
        if not _is_private_ip(dst):
            self.baseline.observe("pkt_rate_external", 1)
        self.baseline.observe("pkt_size", plen)
        anomaly = self.baseline.is_anomaly("pkt_size", plen, sigma=4.0)
        if anomaly:
            key = f"baseline_anom_{src}"
            if not self._cooldown(key, 120):
                return self._make_alert("behavioral_anomaly",src,dst,dport,proto,1,iface,f"Baseline anomaly: {anomaly}")

        with self._lock:
            now = time.time()
            alert = None
            if proto == "TCP":
                alert = self._analyze_tcp(src,dst,sport,dport,flags,plen,pl_low,payload,iface,now)
                if alert: return alert
            elif proto == "UDP":
                alert = self._analyze_udp(src,dst,sport,dport,plen,pl_low,iface,now)
                if alert: return alert
            elif proto == "ICMP":
                alert = self._analyze_icmp(src,dst,plen,pl_low,iface,now)
                if alert: return alert
            # C2 beacon
            if dport in C2_PORTS and not _is_private_ip(dst):
                key = f"c2_{src}_{dst}_{dport}"
                self.beacon_tracker[f"{src}_{dst}"].append(now)
                recent = [t for t in self.beacon_tracker[f"{src}_{dst}"] if t>now-300]
                if len(recent)>=5:
                    intervals = [recent[i]-recent[i-1] for i in range(1,len(recent))]
                    avg = sum(intervals)/len(intervals) if intervals else 0
                    variance = sum(abs(x-avg) for x in intervals)/len(intervals) if intervals else 999
                    if variance<45 and not self._cooldown(key,120):
                        return self._make_alert("c2_beacon",src,dst,dport,proto,len(recent),iface,
                            f"Beacon every ~{avg:.0f}s (±{variance:.1f}s) to port {dport}")
                if not self._cooldown(f"rat_{src}_{dport}",300):
                    return self._make_alert("known_rat_port",src,dst,dport,proto,1,iface,f"Known RAT/C2 port {dport}")
            # Data exfil
            if not _is_private_ip(dst) and plen>0:
                self.ip_byte_counts[src] += plen
                if self.ip_byte_counts[src] > 5*1024*1024:
                    self.ip_byte_counts[src] = 0
                    if not self._cooldown(f"exfil_{src}_{dst}",300):
                        return self._make_alert("data_exfil",src,dst,dport,proto,1,iface,
                            f">5MB to external IP {dst}")
        return None

    def _analyze_tcp(self,src,dst,sport,dport,flags,plen,pl_low,payload,iface,now):
        if flags=="S":
            self.syn_tracker[src].append(now)
            self.ip_port_attempts[src][dport]+=1
            self.ip_connections[src][dst].append(now)
            unique_ports = len(self.ip_port_attempts[src])
            recent_syns  = [t for t in self.syn_tracker[src] if t>now-30]
            if unique_ports>=15 and len(recent_syns)>=15:
                if not self._cooldown(f"synscan_{src}",60):
                    return self._make_alert("syn_scan",src,dst,dport,"TCP",len(recent_syns),iface,
                        f"{unique_ports} ports scanned")
            if self.ip_port_attempts[src][dport]>=15:
                attack = BRUTE_FORCE_PORTS.get(dport,"brute_force")
                if not self._cooldown(f"brute_{attack}_{src}_{dport}",60):
                    a = self._make_alert(attack,src,dst,dport,"TCP",self.ip_port_attempts[src][dport],iface,
                        f"{self.ip_port_attempts[src][dport]} attempts to port {dport}")
                    if self.ips.should_auto_block(a["severity"],attack): self.ips.block_ip(src,f"{attack} detected")
                    return a
            if len(recent_syns)>=200:
                if not self._cooldown(f"synflood_{src}",30):
                    return self._make_alert("syn_flood",src,dst,dport,"TCP",len(recent_syns),iface,f"SYN flood: {len(recent_syns)}/30s")
        elif flags=="F" and sport>1024:
            self.ip_port_attempts[src][dport]+=1
            if self.ip_port_attempts[src][dport]>=5 and not self._cooldown(f"finscan_{src}",60):
                return self._make_alert("fin_scan",src,dst,dport,"TCP",self.ip_port_attempts[src][dport],iface,"FIN stealth scan")
        elif "F" in flags and "P" in flags and "U" in flags:
            if not self._cooldown(f"xmas_{src}",60): return self._make_alert("xmas_scan",src,dst,dport,"TCP",1,iface,"XMAS scan: FIN+PSH+URG")
        elif flags in ("","0","None"):
            self.ip_port_attempts[src][dport]+=1
            if self.ip_port_attempts[src][dport]>=3 and not self._cooldown(f"null_{src}",60):
                return self._make_alert("null_scan",src,dst,dport,"TCP",self.ip_port_attempts[src][dport],iface,"NULL scan")
        elif flags=="A" and sport>1024:
            self.ip_port_attempts[src][f"ack_{dport}"]+=1
            if self.ip_port_attempts[src][f"ack_{dport}"]>=20 and not self._cooldown(f"ackscan_{src}",120):
                return self._make_alert("ack_scan",src,dst,dport,"TCP",self.ip_port_attempts[src][f"ack_{dport}"],iface,"ACK scan")
        if dport in (80,8080,8000,8888,443,8443) and pl_low:
            if any(p in pl_low for p in SQL_PATTERNS) and not self._cooldown(f"sqli_{src}",30):
                return self._make_alert("sql_injection",src,dst,dport,"HTTP",1,iface,f"SQLi from {src}")
            if any(p in pl_low for p in XSS_PATTERNS) and not self._cooldown(f"xss_{src}",30):
                return self._make_alert("xss_attempt",src,dst,dport,"HTTP",1,iface,f"XSS from {src}")
            if any(p in pl_low for p in PATH_PATTERNS) and not self._cooldown(f"path_{src}",30):
                return self._make_alert("path_traversal",src,dst,dport,"HTTP",1,iface,f"Path traversal from {src}")
            if any(p in pl_low for p in CMD_PATTERNS) and not self._cooldown(f"cmdinj_{src}",30):
                return self._make_alert("cmd_injection",src,dst,dport,"HTTP",1,iface,f"Command injection from {src}")
            if any(ua in pl_low for ua in WEBSCANNER_UA) and not self._cooldown(f"webscan_{src}",120):
                return self._make_alert("web_scan",src,dst,dport,"HTTP",1,iface,f"Web scanner from {src}")
            self.http_requests[src].append(now)
            recent_http = [t for t in self.http_requests[src] if t>now-10]
            if len(recent_http)>=100: self.http_requests[src]=[]; return self._make_alert("http_flood",src,dst,dport,"HTTP",len(recent_http),iface,f"HTTP flood: {len(recent_http)}/10s")
            if ("get /" in pl_low or "post /" in pl_low) and payload.count("\r\n")<2 and plen>10:
                self.slow_http[src][dport]=self.slow_http[src].get(dport,0)+1
                if self.slow_http[src][dport]>=20 and not self._cooldown(f"slowloris_{src}",120):
                    return self._make_alert("slowloris",src,dst,dport,"HTTP",self.slow_http[src][dport],iface,"Slowloris attack")
        if dport in (80,8080,23,21,25,110,143) and pl_low:
            if any(p in pl_low for p in ["password=","pass=","pwd=","authorization: basic","user=","username="]) and not self._cooldown(f"cred_{src}",120):
                return self._make_alert("plaintext_cred",src,dst,dport,{80:"HTTP",8080:"HTTP",23:"Telnet",21:"FTP",25:"SMTP",110:"POP3",143:"IMAP"}.get(dport,""),1,iface,"Credential in cleartext")
        if dport in (445,139) and ("ntlmssp" in pl_low or "negotiate" in pl_low):
            self.smb_file_access[src].append(now)
            if len([t for t in self.smb_file_access[src] if t>now-5])>=50:
                self.smb_file_access[src]=[]
                return self._make_alert("mass_file_access",src,dst,dport,"SMB",50,iface,"Mass SMB — ransomware?")
        if dport==88:
            self.ip_port_attempts[src]["kerb"]+=1
            if self.ip_port_attempts[src]["kerb"]>=10 and not self._cooldown(f"kerb_{src}",120):
                return self._make_alert("kerberoast",src,dst,88,"Kerberos",self.ip_port_attempts[src]["kerb"],iface,"Kerberoasting")
        if dport==445 and sport==445 and not self._cooldown(f"smbrelay_{src}_{dst}",300):
            return self._make_alert("smb_relay",src,dst,445,"SMB",1,iface,"SMB relay attack")
        if dport in (5060,5061) or sport in (5060,5061):
            self.sip_tracker[src].append(now)
            if len([t for t in self.sip_tracker[src] if t>now-5])>=50: self.sip_tracker[src]=[]; return self._make_alert("voip_flood",src,dst,dport,"SIP",50,iface,"SIP flood")
        return None

    def _analyze_udp(self,src,dst,sport,dport,plen,pl_low,iface,now):
        self.udp_tracker[src].append(now)
        if len([t for t in self.udp_tracker[src] if t>now-5])>=500:
            self.udp_tracker[src]=[]
            if not self._cooldown(f"udpflood_{src}",30): return self._make_alert("udp_flood",src,dst,dport,"UDP",500,iface,"UDP flood")
        if dport==161 and pl_low and ("public" in pl_low or "private" in pl_low):
            self.snmp_attempts[src]+=1
            if self.snmp_attempts[src]>=3 and not self._cooldown(f"snmp_{src}",300):
                return self._make_alert("snmp_weak",src,dst,161,"SNMP",self.snmp_attempts[src],iface,"SNMP default community string")
        if dport==67:
            self.dhcp_requests[src].append(now)
            if len([t for t in self.dhcp_requests[src] if t>now-10])>=20:
                self.dhcp_requests[src]=[]; return self._make_alert("dhcp_starvation",src,dst,67,"DHCP",20,iface,"DHCP starvation")
        if sport==67 and dport==68:
            if src not in self.dhcp_servers and self.dhcp_servers and not self._cooldown(f"roguedhcp_{src}",300):
                return self._make_alert("dhcp_rogue",src,dst,67,"DHCP",1,iface,f"Rogue DHCP server {src}")
            self.dhcp_servers[src] = now
        self.ip_port_attempts[src][f"udp_{dport}"]+=1
        if sum(1 for k in self.ip_port_attempts[src] if k.startswith("udp_"))>=20 and not self._cooldown(f"udpscan_{src}",120):
            return self._make_alert("udp_scan",src,dst,dport,"UDP",20,iface,"UDP port scan")
        if dport in (5355,137) and dst in ("224.0.0.252","255.255.255.255","239.255.255.250") and not self._cooldown(f"llmnr_{src}",60):
            return self._make_alert("llmnr_poison",src,dst,dport,"LLMNR/NBNS",1,iface,"LLMNR/NBT-NS — Responder attack?")
        return None

    def _analyze_icmp(self,src,dst,plen,pl_low,iface,now):
        self.icmp_tracker[src].append(now)
        recent = [t for t in self.icmp_tracker[src] if t>now-5]
        if len(recent)>=100: self.icmp_tracker[src]=[]; return self._make_alert("icmp_flood",src,dst,0,"ICMP",len(recent),iface,f"ICMP flood: {len(recent)}/5s")
        if plen>128 and not self._cooldown(f"icmptun_{src}",60): return self._make_alert("icmp_tunnel",src,dst,0,"ICMP",plen,iface,f"Large ICMP payload {plen}b — tunnel?")
        self.ip_connections[src]["ping"].append(now)
        if len(self.ip_connections[src]["ping"])>=20:
            hosts=len(self.ip_connections[src]["ping"]); self.ip_connections[src]["ping"]=[]
            if not self._cooldown(f"pingsweep_{src}",120): return self._make_alert("ping_sweep",src,dst,0,"ICMP",hosts,iface,f"Ping sweep: {hosts} hosts")
        return None

    def analyze_arp(self,sender_ip,sender_mac):
        if not sender_ip or not sender_mac: return None
        with self._lock:
            self.arp_rate[sender_mac].append(time.time())
            if sender_ip in self.arp_table:
                known = self.arp_table[sender_ip]
                if known!=sender_mac and not sender_ip.endswith(".1") and not self._cooldown(f"arpspoof_{sender_ip}",120):
                    return self._make_alert("arp_spoof",sender_ip,"LAN",0,"ARP",1,"local",f"{sender_ip}: MAC {known[:8]}→{sender_mac[:8]} ARP poison!")
            else: self.arp_table[sender_ip]=sender_mac
            if len([t for t in self.arp_rate[sender_mac] if t>time.time()-10])>=30:
                self.arp_rate[sender_mac]=[]
                if not self._cooldown(f"arpstorm_{sender_mac}",60):
                    return self._make_alert("arp_spoof",sender_ip,"BROADCAST",0,"ARP",30,"local","ARP storm detected")
        return None

    def analyze_dns(self,query,response_ip="",iface=""):
        if not query: return None
        with self._lock:
            now = time.time()
            if len(query)>52 and query.count(".")>4:
                self.dns_query_counts[query[:20]]+=1
                if self.dns_query_counts[query[:20]]>=2 and not self._cooldown(f"dnstun_{query[:20]}",120):
                    return self._make_alert("dns_tunnel","local",query,53,"DNS",1,iface,f"DNS tunnel: {len(query)}char query")
            if _is_dga(query) and not self._cooldown(f"dga_{query.split('.')[0][:12]}",60):
                return self._make_alert("dga_domain","local",query,53,"DNS",1,iface,f"DGA domain: {query[:60]}")
            base = ".".join(query.split(".")[-2:]) if "." in query else query
            if response_ip:
                if base in self.dns_responses and self.dns_responses[base]!=response_ip and not self._cooldown(f"dnsspoof_{base}",300):
                    return self._make_alert("dns_spoof","DNS","local",53,"DNS",1,iface,f"DNS response conflict for {base}")
                self.dns_responses[base]=response_ip
            self.dns_query_times[base].append(now)
            if len([t for t in self.dns_query_times[base] if t>now-10])>=30:
                self.dns_query_times[base]=[]
                if not self._cooldown(f"dnsflood_{base}",120):
                    return self._make_alert("dns_exfil","local",base,53,"DNS",30,iface,f"DNS flood: {base}")
        return None

    def _make_alert(self,attack_type,src,dst,port,proto,count,iface,detail) -> dict:
        profile = ATTACK_PROFILES.get(attack_type,{})
        apts    = get_apt_attribution(attack_type)
        alert = {
            "id":           f"NET-{int(time.time())}-{attack_type[:8].upper()}",
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "attack_type":  attack_type,
            "attack_name":  profile.get("name",attack_type.replace("_"," ").title()),
            "severity":     profile.get("severity","MEDIUM"),
            "source_ip":    src,
            "dest_ip":      dst,
            "port":         port,
            "protocol":     proto,
            "packet_count": count,
            "interface":    iface,
            "detail":       detail,
            "mitre":        profile.get("mitre",""),
            "mitre_name":   profile.get("mitre_name",""),
            "response":     profile.get("response",[]),
            "priority":     profile.get("priority",5),
            "apt_groups":   apts,
            "ai_analysis":  None,
            "geo":          {},
            "intel":        {},
            "blocked":      False,
        }
        # Background enrichment
        threading.Thread(target=self._enrich_alert, args=(alert,), daemon=True).start()
        return alert

    def _enrich_alert(self, alert: dict):
        src = alert.get("source_ip","")
        if src and not _is_private_ip(src):
            alert["geo"]   = enrich_ip(src)
            alert["intel"] = enrich_ip_threat_intel(src)
            if alert["intel"].get("score",0) >= 50 and alert["severity"] in ("CRITICAL","HIGH"):
                if self.ips.should_auto_block(alert["severity"], alert["attack_type"]):
                    blocked = self.ips.block_ip(src, f"Threat intel score {alert['intel']['score']}/100")
                    alert["blocked"] = blocked


# ══════════════════════════════════════════════════════════════════
# NETWORK MONITOR v3 — Master class
# ══════════════════════════════════════════════════════════════════
_ioc_manager   = IOCFeedManager()
_ips_engine    = IPSEngine()
_baseline      = BaselineEngine()
_file_extractor= FileExtractor()
_monitor_instance = None

def get_network_monitor():
    global _monitor_instance
    if _monitor_instance is None: _monitor_instance = NetworkMonitor()
    return _monitor_instance

def get_domain_monitor():
    return DomainMonitor()

def get_ioc_manager():   return _ioc_manager
def get_ips_engine():    return _ips_engine
def get_file_extractor():return _file_extractor
def get_baseline():      return _baseline

class NetworkMonitor:
    def __init__(self):
        self.analyzer   = PacketAnalyzer(_ioc_manager, _ips_engine, _baseline, _file_extractor)
        self._running   = False
        self._thread    = None
        self._interface = None
        self._pcap      = None
        self._stats     = {"packets_captured":0,"alerts_generated":0,"started_at":None,"interface":None,"bytes_captured":0}
        _ioc_manager.refresh()  # Start IOC feed refresh
        log.info("[Net] NetworkMonitor v7.0 ready — IDS/IPS + TI + Baseline + FileExtraction")

    def get_interfaces(self) -> list:
        try:
            import scapy.all as scapy
            return [i for i in scapy.get_if_list() if i!="lo"]
        except:
            try:
                out = subprocess.check_output(["ip","link","show"],text=True,timeout=5)
                ifaces = re.findall(r"\d+: (\w+):",out)
                return [i for i in ifaces if i not in ("lo","")]
            except: pass
        return ["eth0"]

    def get_status(self) -> dict:
        try: scapy_ok=True; import scapy.all
        except: scapy_ok=False
        return {
            "running":          self._running,
            "interface":        self._interface,
            "interfaces":       self.get_interfaces(),
            "stats":            self._stats,
            "scapy":            scapy_ok,
            "attack_types":     len(ATTACK_PROFILES),
            "ioc_stats":        _ioc_manager.get_stats(),
            "ips_blocked":      len(_ips_engine.get_blocked()),
            "baseline_metrics": len(_baseline.baseline),
            "extracted_files":  len(_file_extractor.get_extracted()),
            "ips_auto_block":   _ips_engine._auto_block,
        }

    def start(self, interface=None, alert_callback=None) -> dict:
        if self._running: return {"success":False,"error":"Already running","running":True}
        try: import scapy.all
        except: return {"success":False,"error":"scapy not installed: pip install scapy --break-system-packages"}
        ifaces = self.get_interfaces()
        self._interface = interface or (ifaces[0] if ifaces else "eth0")
        self._running   = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()
        self._stats["interface"]  = self._interface
        self._stats["packets_captured"] = 0
        self._stats["alerts_generated"] = 0
        # Start PCAP writer
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._pcap = PCAPWriter(f"capture_{ts}.pcap")
        self._thread = threading.Thread(target=self._capture_loop, args=(alert_callback,), daemon=True)
        self._thread.start()
        log.info(f"[Net] Capture started on {self._interface}")
        return {"success":True,"interface":self._interface,"message":f"Capturing on {self._interface} — PCAP saving to {self._pcap.path}"}

    def _capture_loop(self, alert_callback):
        try:
            import scapy.all as scapy
            def process(pkt):
                if not self._running: return
                self._stats["packets_captured"] += 1
                self._stats["bytes_captured"]   += len(pkt)
                try:
                    # Write to PCAP
                    if self._pcap: self._pcap.write_packet(bytes(pkt))
                    # Analyze
                    pkt_dict = self._parse_scapy(pkt)
                    if pkt_dict:
                        alert = self.analyzer.analyze_packet(pkt_dict)
                        if alert: self._handle_alert(alert, alert_callback)
                    if pkt.haslayer(scapy.ARP):
                        a = pkt[scapy.ARP]
                        alert = self.analyzer.analyze_arp(a.psrc, a.hwsrc)
                        if alert: self._handle_alert(alert, alert_callback)
                    if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr==0:
                        qname = pkt[scapy.DNS].qd.qname.decode("utf-8","ignore").rstrip(".")
                        resp_ip = ""
                        if pkt[scapy.DNS].qr==1 and pkt[scapy.DNS].an:
                            resp_ip = str(pkt[scapy.DNS].an.rdata) if hasattr(pkt[scapy.DNS].an,"rdata") else ""
                        iface = getattr(pkt,"sniffed_on",self._interface)
                        alert = self.analyzer.analyze_dns(qname, resp_ip, iface)
                        if alert: self._handle_alert(alert, alert_callback)
                except Exception as e: log.debug(f"[Net] pkt err: {e}")
            scapy.sniff(iface=self._interface, prn=process, store=False,
                        stop_filter=lambda x: not self._running,
                        promisc=True)  # PROMISCUOUS MODE — see all LAN traffic
        except Exception as e:
            log.error(f"[Net] Capture error: {e}")
            self._running = False

    def _parse_scapy(self, pkt) -> Optional[dict]:
        try:
            import scapy.all as scapy
            if not pkt.haslayer(scapy.IP): return None
            ip = pkt[scapy.IP]
            d = {"src_ip":ip.src,"dst_ip":ip.dst,"length":len(pkt),"interface":self._interface,
                 "src_port":0,"dst_port":0,"flags":"","protocol":"","payload":""}
            if pkt.haslayer(scapy.TCP):
                tcp = pkt[scapy.TCP]; d.update({"protocol":"TCP","src_port":tcp.sport,"dst_port":tcp.dport,"flags":str(tcp.flags)})
                if pkt.haslayer(scapy.Raw):
                    try: d["payload"]=pkt[scapy.Raw].load.decode("utf-8","ignore")[:2048]
                    except: pass
            elif pkt.haslayer(scapy.UDP):
                udp = pkt[scapy.UDP]; d.update({"protocol":"UDP","src_port":udp.sport,"dst_port":udp.dport})
                if pkt.haslayer(scapy.Raw):
                    try: d["payload"]=pkt[scapy.Raw].load.decode("utf-8","ignore")[:512]
                    except: pass
            elif pkt.haslayer(scapy.ICMP): d["protocol"]="ICMP"
            return d if d["protocol"] else None
        except: return None

    def _handle_alert(self, alert: dict, callback=None):
        self._stats["alerts_generated"] += 1
        log.warning(f"[Net] [{alert['severity']}] {alert['attack_name']} — {alert['source_ip']}")
        def enrich_and_send():
            analysis = _ai_analyze_alert(alert)
            alert["ai_analysis"]    = analysis
            alert["plain_english"]  = analysis.get("plain_english","")
            alert["priority_score"] = analysis.get("priority_score",5)
            alert["apt_attribution"]= analysis.get("apt_attribution","")
            _save_alert(alert)
            _send_all_network_alerts(alert, analysis)
            if callback: callback(alert)
        threading.Thread(target=enrich_and_send, daemon=True).start()

    def stop(self):
        self._running = False
        if self._pcap:
            path = self._pcap.close()
            log.info(f"[Net] PCAP saved: {path}")

    def get_pcap_files(self) -> list:
        return [{"name":f.name,"size":f.stat().st_size,"path":str(f)} for f in PCAP_DIR.glob("*.pcap")]

    def simulate_test_alert(self) -> dict:
        import random
        test_types = ["syn_scan","ssh_brute","arp_spoof","sql_injection","c2_beacon",
                      "dns_tunnel","data_exfil","http_flood","llmnr_poison","kerberoast","ioc_match","behavioral_anomaly"]
        at = random.choice(test_types)
        profile = ATTACK_PROFILES.get(at,{})
        apts = get_apt_attribution(at)
        alert = {
            "id":           f"NET-TEST-{int(time.time())}",
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "attack_type":  at,
            "attack_name":  profile.get("name",at),
            "severity":     profile.get("severity","HIGH"),
            "source_ip":    f"192.168.1.{random.randint(10,254)}",
            "dest_ip":      f"10.0.0.{random.randint(1,10)}",
            "port":         random.choice([22,445,80,88,53,3389,4444,50050]),
            "protocol":     "TCP",
            "packet_count": random.randint(5,150),
            "interface":    self._interface or "eth0",
            "detail":       f"Test: {profile.get('description',at)}",
            "mitre":        profile.get("mitre",""),
            "mitre_name":   profile.get("mitre_name",""),
            "response":     profile.get("response",[]),
            "priority":     profile.get("priority",7),
            "apt_groups":   apts,
            "test":         True,
            "geo":          {"country":"Test","flag":"🧪","org":"Test Org"},
            "intel":        {"score":random.randint(0,100),"verdict":"TEST"},
            "blocked":      False,
        }
        analysis = _rule_based(alert, profile, apts)
        alert["ai_analysis"] = analysis
        alert["plain_english"]  = analysis["plain_english"]
        alert["priority_score"] = analysis["priority_score"]
        alert["apt_attribution"]= analysis["apt_attribution"]
        _save_alert(alert)
        return alert

def _send_all_network_alerts(alert: dict, analysis: dict):
    sev = alert.get("severity","HIGH")
    apts = alert.get("apt_groups",[])
    geo  = alert.get("geo",{})
    title = f"🔴 [{sev}] {alert.get('attack_name','')} — {alert.get('source_ip','')}"
    msg = (f"TYPE: {alert.get('attack_name','')}\n"
           f"SOURCE: {alert.get('source_ip','')} {geo.get('flag','')} {geo.get('country','')} | {geo.get('org','')}\n"
           f"→ {alert.get('dest_ip','')}:{alert.get('port','')}\n"
           f"DETAIL: {alert.get('detail','')}\n"
           f"APT: {', '.join(apts) if apts else 'Unknown'}\n"
           f"ACTION: {analysis.get('recommended_action','')}\n"
           f"MITRE: {alert.get('mitre','')} {alert.get('mitre_name','')}\n"
           f"BLOCKED: {'YES ✓' if alert.get('blocked') else 'NO'}")
    def _try():
        try:
            from scanner.alerting import get_alerting_engine
            get_alerting_engine().send_alert({"title":title,"message":msg,"severity":sev,"source":"Network Monitor","details":alert})
        except: pass
    threading.Thread(target=_try, daemon=True).start()

class DomainMonitor:
    def __init__(self): self._running=False; self._thread=None; self._results={}
    def check_domain(self, domain: str) -> list:
        findings = []
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            findings.append({"severity":"INFO","title":f"DNS: {', '.join(ips)}","source":"DNS"})
        except Exception as e: findings.append({"severity":"HIGH","title":f"DNS failed: {e}","source":"DNS"})
        try:
            import ssl
            ctx=ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
                s.settimeout(5); s.connect((domain,443))
                cert=s.getpeercert(); exp=cert.get("notAfter","")
                findings.append({"severity":"INFO","title":f"SSL valid until {exp}","source":"SSL"})
                if exp:
                    from datetime import datetime
                    days=(datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
                    if days<30: findings.append({"severity":"HIGH","title":f"SSL expires in {days} days!","source":"SSL"})
        except Exception as e: findings.append({"severity":"MEDIUM","title":f"SSL: {e}","source":"SSL"})
        return findings
