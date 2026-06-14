"""
VoraGuard Advanced Network IDS/IPS Engine v6.0
Beyond Wireshark: Active IPS + Threat Intel + Playbooks + TLS Decrypt + STIX Export
Developed by Jithu
"""
import os, sys, json, time, threading, hashlib, socket, struct, re
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.parent
IDS_DIR    = BASE_DIR / "ids"
IDS_DIR.mkdir(exist_ok=True)
ALERTS_FILE    = IDS_DIR / "alerts.json"
PACKETS_FILE   = IDS_DIR / "packets.json"
BLOCKLIST_FILE = IDS_DIR / "ip_blocklist.json"
BASELINE_FILE  = IDS_DIR / "baseline.json"
PLAYBOOK_LOG   = IDS_DIR / "playbook_log.json"
FILTER_HISTORY = IDS_DIR / "filter_history.json"
STIX_EXPORT    = IDS_DIR / "stix_export.json"
TLS_KEY_LOG    = IDS_DIR / "tls_keylog.txt"

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
MITRE_MAP = {
    "syn_scan":           ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "fin_scan":           ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "xmas_scan":          ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "null_scan":          ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "ack_scan":           ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "window_scan":        ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "os_fingerprint":     ("T1082", "System Information Discovery", "Discovery"),
    "ping_sweep":         ("T1018", "Remote System Discovery",      "Discovery"),
    "udp_scan":           ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "ssh_brute":          ("T1110", "Brute Force",                  "Credential Access"),
    "rdp_brute":          ("T1110", "Brute Force",                  "Credential Access"),
    "ftp_brute":          ("T1110", "Brute Force",                  "Credential Access"),
    "http_brute":         ("T1110", "Brute Force",                  "Credential Access"),
    "smb_brute":          ("T1110", "Brute Force",                  "Credential Access"),
    "mysql_brute":        ("T1110", "Brute Force",                  "Credential Access"),
    "redis_brute":        ("T1110", "Brute Force",                  "Credential Access"),
    "ldap_brute":         ("T1110", "Brute Force",                  "Credential Access"),
    "kerberoasting":      ("T1558", "Steal or Forge Kerberos Tickets","Credential Access"),
    "arp_spoof":          ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "dhcp_starvation":    ("T1498", "Network Denial of Service",    "Impact"),
    "rogue_dhcp":         ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "stp_manipulation":   ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "dns_tunnel":         ("T1071.004","Application Layer Protocol: DNS","Command and Control"),
    "dns_spoof":          ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "c2_beacon":          ("T1071", "Application Layer Protocol",   "Command and Control"),
    "dga_domain":         ("T1568.002","Dynamic Resolution: DGA",   "Command and Control"),
    "http_c2":            ("T1071.001","Application Layer Protocol: Web","Command and Control"),
    "icmp_tunnel":        ("T1095", "Non-Application Layer Protocol","Command and Control"),
    "sql_injection":      ("T1190", "Exploit Public-Facing Application","Initial Access"),
    "xss_attack":         ("T1059", "Command and Scripting Interpreter","Execution"),
    "path_traversal":     ("T1083", "File and Directory Discovery", "Discovery"),
    "cmd_injection":      ("T1059", "Command and Scripting Interpreter","Execution"),
    "http_flood":         ("T1498", "Network Denial of Service",    "Impact"),
    "web_scanner":        ("T1595", "Active Scanning",              "Reconnaissance"),
    "smb_relay":          ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "pass_the_hash":      ("T1550.002","Use Alternate Auth Material","Lateral Movement"),
    "wmi_abuse":          ("T1047", "Windows Management Instrumentation","Execution"),
    "psexec_detect":      ("T1569.002","System Services: Service Execution","Execution"),
    "syn_flood":          ("T1498", "Network Denial of Service",    "Impact"),
    "udp_flood":          ("T1498", "Network Denial of Service",    "Impact"),
    "icmp_flood":         ("T1498", "Network Denial of Service",    "Impact"),
    "slowloris":          ("T1498", "Network Denial of Service",    "Impact"),
    "plaintext_cred":     ("T1552", "Unsecured Credentials",        "Credential Access"),
    "ntlm_hash":          ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "llmnr_poison":       ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "snmp_enum":          ("T1046", "Network Service Scanning",     "Reconnaissance"),
    "data_exfil":         ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "dns_exfil":          ("T1048.003","Exfiltration Over Unencrypted Protocol","Exfiltration"),
    "smtp_exfil":         ("T1048", "Exfiltration Over Alternative Protocol","Exfiltration"),
    "ssl_downgrade":      ("T1557", "Adversary-in-the-Middle",      "Collection"),
    "tor_traffic":        ("T1090", "Proxy",                        "Command and Control"),
    "ransomware_behavior":("T1486", "Data Encrypted for Impact",    "Impact"),
    "mass_file_access":   ("T1005", "Data from Local System",       "Collection"),
    "off_hours_access":   ("T1078", "Valid Accounts",               "Persistence"),
    "sip_flood":          ("T1498", "Network Denial of Service",    "Impact"),
}

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

KNOWN_C2_PORTS = {4444,1337,8080,6666,7777,9999,31337,1234,
                  5555,2222,4321,12345,54321,8888,3333,6969}

TOR_EXIT_PATTERN = re.compile(r'\btor\b|\b\.onion\b', re.I)

SQL_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"union\s+select", r"'\s*or\s+'1'\s*=\s*'1",
        r";\s*drop\s+table", r"--\s*$", r"xp_cmdshell",
        r"1=1\s*--", r"'\s*;\s*select", r"sleep\s*\(\d+\)"
    ]
]
XSS_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"<script", r"javascript:", r"onerror\s*=",
        r"onload\s*=", r"alert\s*\(", r"document\.cookie"
    ]
]
CMD_PATTERNS = [
    re.compile(p, re.I) for p in [
        r";\s*cat\s+/etc", r"\|\s*bash", r"&&\s*wget",
        r";\s*curl\s+http", r"\$\(.*\)", r"`[^`]+`"
    ]
]

# ── Alert dataclass ────────────────────────────────────────────────────────────
@dataclass
class NetworkAlert:
    id:           str
    timestamp:    str
    severity:     str
    attack_type:  str
    attack_name:  str
    source_ip:    str
    dest_ip:      str
    port:         int
    protocol:     str
    packet_count: int
    mitre:        str
    mitre_name:   str
    tactic:       str
    description:  str
    ai_analysis:  str = ""
    action_taken: str = ""
    blocked:      bool = False
    acknowledged: bool = False
    raw_payload:  str = ""

    def to_dict(self):
        return asdict(self)

# ── Packet record ─────────────────────────────────────────────────────────────
@dataclass
class PacketRecord:
    id:        int
    timestamp: str
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  str
    length:    int
    flags:     str
    info:      str
    is_threat: bool = False
    threat_type: str = ""
    payload_hex: str = ""
    payload_ascii: str = ""
    layers: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

# ── IDS Engine ────────────────────────────────────────────────────────────────
class VoraGuardIDS:
    def __init__(self):
        self._running        = False
        self._thread         = None
        self._interface      = None
        self._lock           = threading.Lock()
        self._alerts         = self._load_json(ALERTS_FILE, [])
        self._packets        = deque(maxlen=5000)
        self._blocklist      = self._load_json(BLOCKLIST_FILE, {})
        self._baseline       = self._load_json(BASELINE_FILE, {})
        self._filter_history = self._load_json(FILTER_HISTORY, [])

        # Detection state
        self._syn_tracker     = defaultdict(lambda: defaultdict(list))
        self._brute_tracker   = defaultdict(lambda: defaultdict(list))
        self._arp_table       = {}
        self._dhcp_servers    = set()
        self._dns_queries     = defaultdict(list)
        self._beacon_tracker  = defaultdict(lambda: defaultdict(list))
        self._exfil_tracker   = defaultdict(lambda: {"bytes": 0, "ts": time.time()})
        self._http_state      = defaultdict(lambda: {"open": 0, "ts": time.time()})
        self._tgq_tracker     = defaultdict(list)
        self._ip_bytes        = defaultdict(lambda: {"in": 0, "out": 0, "ts": time.time()})
        self._connections     = defaultdict(lambda: {"pkts": 0, "bytes": 0, "last": time.time()})
        self._cooldown        = {}
        self._baseline_building = False
        self._baseline_data   = defaultdict(lambda: {"pkts": [], "ts": time.time()})

        # Stats
        self.packets_captured  = 0
        self.alerts_generated  = 0
        self._start_time       = None
        self._packet_id        = 0

        # Baseline timer
        self._baseline_start = None

    # ── Persistence helpers ───────────────────────────────────────────────────
    def _load_json(self, path, default):
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception:
            pass
        return default

    def _save_json(self, path, data):
        try:
            path.write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            pass

    # ── Public API ────────────────────────────────────────────────────────────
    def start(self, interface=None):
        if self._running:
            return {"status": "already_running"}
        if not SCAPY_OK:
            return {"status": "error", "msg": "scapy not installed — run: pip install scapy --break-system-packages"}
        self._interface = interface or self._auto_interface()
        self._running   = True
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        return {"status": "started", "interface": self._interface}

    def stop(self):
        self._running = False
        return {"status": "stopped"}

    def get_status(self):
        uptime = int(time.time() - self._start_time) if self._start_time else 0
        rate   = round(self.packets_captured / max(uptime, 1), 1)
        return {
            "running":   self._running,
            "interface": self._interface,
            "uptime":    uptime,
            "scapy":     SCAPY_OK,
            "interfaces": self._list_interfaces(),
            "stats": {
                "packets_captured": self.packets_captured,
                "alerts_generated": self.alerts_generated,
                "interface":        self._interface,
                "started_at":       self._start_time,
                "rate_per_sec":     rate,
            },
            "setup_note": "" if SCAPY_OK else "Install scapy: pip install scapy --break-system-packages"
        }

    def get_alerts(self, limit=100, severity=None, attack_type=None):
        alerts = list(self._alerts)
        if severity and severity != "ALL":
            alerts = [a for a in alerts if a.get("severity") == severity]
        if attack_type and attack_type != "ALL":
            alerts = [a for a in alerts if a.get("attack_type") == attack_type]
        return sorted(alerts, key=lambda x: x.get("timestamp",""), reverse=True)[:limit]

    def get_packets(self, limit=200, filt=None):
        pkts = list(self._packets)
        if filt:
            pkts = self._apply_filter(pkts, filt)
        return list(reversed(pkts[-limit:]))

    def get_stats(self):
        pkts = list(self._packets)
        proto_count = defaultdict(int)
        for p in pkts:
            proto_count[p.get("protocol","OTHER")] += 1
        top_src = defaultdict(int)
        top_dst = defaultdict(int)
        top_port = defaultdict(int)
        for p in pkts:
            if p.get("src_ip"): top_src[p["src_ip"]] += 1
            if p.get("dst_ip"): top_dst[p["dst_ip"]] += 1
            if p.get("dst_port"): top_port[str(p["dst_port"])] += 1
        sev_count = defaultdict(int)
        for a in self._alerts:
            sev_count[a.get("severity","LOW")] += 1
        return {
            "protocol_dist": dict(proto_count),
            "top_sources": sorted(top_src.items(), key=lambda x:-x[1])[:10],
            "top_dests":   sorted(top_dst.items(), key=lambda x:-x[1])[:10],
            "top_ports":   sorted(top_port.items(), key=lambda x:-x[1])[:10],
            "severity_dist": dict(sev_count),
            "total_bytes": sum(p.get("length",0) for p in pkts),
            "unique_ips":  len(set(p.get("src_ip","") for p in pkts)),
            "total_pkts":  len(pkts),
        }

    def get_conversations(self):
        convs = defaultdict(lambda: {"pkts":0,"bytes":0,"protocols":set(),"last":""})
        for p in self._packets:
            src = p.get("src_ip",""); dst = p.get("dst_ip","")
            if not src or not dst: continue
            key = tuple(sorted([src,dst]))
            convs[key]["pkts"]   += 1
            convs[key]["bytes"]  += p.get("length",0)
            convs[key]["protocols"].add(p.get("protocol","?"))
            convs[key]["last"]    = p.get("timestamp","")
        result = []
        for (a,b), v in sorted(convs.items(), key=lambda x:-x[1]["pkts"])[:50]:
            result.append({"ip_a":a,"ip_b":b,"packets":v["pkts"],
                           "bytes":v["bytes"],"protocols":list(v["protocols"]),
                           "last":v["last"]})
        return result

    def get_dns_log(self):
        dns_entries = []
        for p in self._packets:
            if p.get("protocol") == "DNS":
                dns_entries.append(p)
        return list(reversed(dns_entries[-200:]))

    def get_forensics(self, ip=None):
        alerts = list(self._alerts)
        if ip:
            alerts = [a for a in alerts if a.get("source_ip") == ip]
        ip_chains = defaultdict(list)
        for a in alerts:
            ip_chains[a.get("source_ip","?")].append(a)
        chains = []
        for src_ip, ip_alerts in sorted(ip_chains.items(), key=lambda x:-len(x[1])):
            tactics = list(set(a.get("tactic","?") for a in ip_alerts))
            ttps    = list(set(a.get("mitre","?") for a in ip_alerts))
            chains.append({
                "source_ip": src_ip,
                "alert_count": len(ip_alerts),
                "attack_types": list(set(a.get("attack_type","?") for a in ip_alerts)),
                "tactics": tactics,
                "ttps": ttps,
                "timeline": sorted([{"ts":a["timestamp"],"type":a["attack_type"],"sev":a["severity"]} for a in ip_alerts], key=lambda x:x["ts"]),
                "first_seen": min(a["timestamp"] for a in ip_alerts),
                "last_seen":  max(a["timestamp"] for a in ip_alerts),
                "blocked": any(a.get("blocked") for a in ip_alerts),
            })
        all_ttps = list(set(a.get("mitre","?") for a in alerts))
        return {"chains": chains[:20], "all_ttps": all_ttps, "total_ips": len(ip_chains)}

    def get_blocklist(self):
        return self._blocklist

    def block_ip(self, ip, reason="Manual block", method="iptables"):
        self._blocklist[ip] = {"reason": reason, "method": method, "ts": datetime.now().isoformat(), "active": True}
        self._save_json(BLOCKLIST_FILE, self._blocklist)
        if method == "iptables":
            try:
                os.system(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
                return {"status": "blocked", "ip": ip, "method": "iptables"}
            except Exception as e:
                return {"status": "listed_only", "ip": ip, "error": str(e)}
        return {"status": "listed", "ip": ip}

    def unblock_ip(self, ip):
        if ip in self._blocklist:
            method = self._blocklist[ip].get("method","list")
            if method == "iptables":
                os.system(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -D FORWARD -s {ip} -j DROP 2>/dev/null")
            del self._blocklist[ip]
            self._save_json(BLOCKLIST_FILE, self._blocklist)
        return {"status": "unblocked", "ip": ip}

    def add_filter_history(self, filt):
        hist = self._load_json(FILTER_HISTORY, [])
        if filt and filt not in hist:
            hist.insert(0, filt)
            hist = hist[:50]
            self._save_json(FILTER_HISTORY, hist)
        return hist

    def get_filter_history(self):
        return self._load_json(FILTER_HISTORY, [])

    def fire_test_alert(self):
        a = self._make_alert("syn_scan","HIGH","192.168.99.99","10.0.0.1",22,"TCP",
                             25,"Test alert — VoraGuard IDS is working correctly")
        return a.to_dict() if a else {}

    # ── Export ─────────────────────────────────────────────────────────────────
    def export_stix(self):
        alerts = list(self._alerts)
        bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()}",
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat()+"Z",
            "objects": []
        }
        for a in alerts[:100]:
            obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{hashlib.md5(a['id'].encode()).hexdigest()}",
                "created": a.get("timestamp",""),
                "modified": a.get("timestamp",""),
                "name": a.get("attack_name","Unknown Attack"),
                "description": a.get("description",""),
                "pattern": f"[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '{a.get('source_ip','')}']",
                "pattern_type": "stix",
                "valid_from": a.get("timestamp",""),
                "kill_chain_phases": [{"kill_chain_name":"mitre-attack","phase_name":a.get("tactic","unknown").lower().replace(" ","-")}],
                "labels": [a.get("severity","LOW").lower(), "malicious-activity"],
                "external_references": [{"source_name":"mitre-attack","external_id":a.get("mitre","")}]
            }
            bundle["objects"].append(obj)
            ip_obj = {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": f"ipv4-addr--{hashlib.md5(a.get('source_ip','').encode()).hexdigest()}",
                "value": a.get("source_ip","")
            }
            bundle["objects"].append(ip_obj)
        STIX_EXPORT.write_text(json.dumps(bundle, indent=2))
        return bundle

    def export_csv(self):
        lines = ["id,timestamp,severity,attack_type,attack_name,source_ip,dest_ip,port,mitre,tactic,description"]
        for a in self._alerts:
            lines.append(",".join([
                str(a.get("id","")), str(a.get("timestamp","")),
                str(a.get("severity","")), str(a.get("attack_type","")),
                f'"{a.get("attack_name","")}"', str(a.get("source_ip","")),
                str(a.get("dest_ip","")), str(a.get("dst_port",a.get("port",""))),
                str(a.get("mitre","")), str(a.get("tactic","")),
                f'"{a.get("description","")}"'
            ]))
        csv_path = IDS_DIR / "alerts_export.csv"
        csv_path.write_text("\n".join(lines))
        return str(csv_path)

    # ── Threat Intel Enrichment ────────────────────────────────────────────────
    def enrich_ip(self, ip):
        if not REQUESTS_OK:
            return {"error": "requests not installed"}
        results = {}
        env = os.environ
        vt_key = env.get("VT_API_KEY","")
        if vt_key:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                                  headers={"x-apikey": vt_key}, timeout=8)
                if r.status_code == 200:
                    d = r.json().get("data",{}).get("attributes",{})
                    results["virustotal"] = {
                        "malicious": d.get("last_analysis_stats",{}).get("malicious",0),
                        "reputation": d.get("reputation",0),
                        "country": d.get("country",""),
                        "owner": d.get("as_owner",""),
                    }
            except Exception: pass
        abuse_key = env.get("ABUSEIPDB_API_KEY","")
        if abuse_key:
            try:
                r = requests.get("https://api.abuseipdb.com/api/v2/check",
                                  headers={"Key": abuse_key, "Accept":"application/json"},
                                  params={"ipAddress":ip,"maxAgeInDays":"90"}, timeout=8)
                if r.status_code == 200:
                    d = r.json().get("data",{})
                    results["abuseipdb"] = {
                        "confidence": d.get("abuseConfidenceScore",0),
                        "total_reports": d.get("totalReports",0),
                        "country": d.get("countryCode",""),
                        "isp": d.get("isp",""),
                        "domain": d.get("domain",""),
                    }
            except Exception: pass
        otx_key = env.get("OTX_API_KEY","")
        if otx_key:
            try:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                  headers={"X-OTX-API-KEY": otx_key}, timeout=8)
                if r.status_code == 200:
                    d = r.json()
                    results["otx"] = {
                        "pulse_count": d.get("pulse_info",{}).get("count",0),
                        "malware_families": list(set(p.get("malware_families",[""]) and
                                                     [m.get("display_name","") for m in p.get("malware_families",[])]
                                                     for p in d.get("pulse_info",{}).get("pulses",[])))[:5],
                    }
            except Exception: pass
        # GeoIP fallback
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if r.status_code == 200:
                d = r.json()
                results["geo"] = {
                    "country": d.get("country_name",""),
                    "city": d.get("city",""),
                    "org": d.get("org",""),
                    "asn": d.get("asn",""),
                }
        except Exception: pass
        # Composite score
        score = 0
        vt = results.get("virustotal",{})
        ab = results.get("abuseipdb",{})
        if vt.get("malicious",0) > 0:   score += 50
        if vt.get("reputation",0) < -5: score += 20
        if ab.get("confidence",0) > 50: score += 40
        if ab.get("total_reports",0) > 10: score += 10
        if results.get("otx",{}).get("pulse_count",0) > 0: score += 30
        score = min(score, 100)
        results["composite"] = {
            "score": score,
            "verdict": "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "CLEAN",
            "ip": ip,
        }
        return results

    def check_hash(self, hash_val):
        if not REQUESTS_OK:
            return {"error": "requests not installed"}
        results = {}
        vt_key = os.environ.get("VT_API_KEY","")
        if vt_key:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_val}",
                                  headers={"x-apikey": vt_key}, timeout=10)
                if r.status_code == 200:
                    d = r.json().get("data",{}).get("attributes",{})
                    results["virustotal"] = {
                        "name": d.get("meaningful_name","Unknown"),
                        "malicious": d.get("last_analysis_stats",{}).get("malicious",0),
                        "type": d.get("type_description",""),
                        "size": d.get("size",0),
                    }
                elif r.status_code == 404:
                    results["virustotal"] = {"not_found": True}
            except Exception as e:
                results["virustotal"] = {"error": str(e)}
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/",
                               data={"query":"get_info","hash":hash_val}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "hash_not_found":
                    results["malwarebazaar"] = {"not_found": True}
                else:
                    info = d.get("data",[{}])[0] if d.get("data") else {}
                    results["malwarebazaar"] = {
                        "malware_family": info.get("signature","Unknown"),
                        "file_type": info.get("file_type",""),
                        "delivery_method": info.get("delivery_method",""),
                        "tags": info.get("tags",[]),
                        "found": True,
                    }
        except Exception: pass
        return results

    # ── Playbooks ─────────────────────────────────────────────────────────────
    PLAYBOOKS = {
        "ssh_brute_response": {
            "name": "SSH Brute Force Response",
            "trigger": "ssh_brute",
            "steps": [
                {"name":"Block source IP","cmd":"iptables -I INPUT -s {src_ip} -j DROP"},
                {"name":"Check failed logins","cmd":"lastb | head -20"},
                {"name":"Lock account temporarily","cmd":"faillock --user root --lock"},
                {"name":"Check auth log","cmd":"tail -50 /var/log/auth.log | grep {src_ip}"},
                {"name":"Alert team","cmd":"echo 'SSH Brute Force from {src_ip}' | mail -s 'ALERT' admin@company.com"},
            ]
        },
        "arp_spoof_response": {
            "name": "ARP Spoofing Response",
            "trigger": "arp_spoof",
            "steps": [
                {"name":"Block attacker IP","cmd":"iptables -I INPUT -s {src_ip} -j DROP"},
                {"name":"Enable ARP inspection","cmd":"echo 1 > /proc/sys/net/ipv4/conf/all/arp_filter"},
                {"name":"Flush ARP cache","cmd":"ip neigh flush all"},
                {"name":"Check ARP table","cmd":"arp -n"},
                {"name":"Set static ARP entries","cmd":"arp -s {gateway_ip} {gateway_mac}"},
            ]
        },
        "c2_beacon_response": {
            "name": "C2 Beacon Response",
            "trigger": "c2_beacon",
            "steps": [
                {"name":"Block C2 IP","cmd":"iptables -I OUTPUT -d {dst_ip} -j DROP"},
                {"name":"Check active connections","cmd":"ss -antp | grep {dst_ip}"},
                {"name":"Find process","cmd":"lsof -i @{dst_ip}"},
                {"name":"Kill process","cmd":"kill -9 $(lsof -ti @{dst_ip})"},
                {"name":"Scan for malware","cmd":"clamscan -r /tmp /var/tmp --bell 2>/dev/null"},
            ]
        },
        "sqli_response": {
            "name": "SQL Injection Response",
            "trigger": "sql_injection",
            "steps": [
                {"name":"Block source IP","cmd":"iptables -I INPUT -s {src_ip} -j DROP"},
                {"name":"Check web logs","cmd":"grep {src_ip} /var/log/nginx/access.log | tail -20"},
                {"name":"Block in nginx","cmd":"echo 'deny {src_ip};' >> /etc/nginx/conf.d/blocked.conf && nginx -s reload"},
                {"name":"Check DB for injections","cmd":"grep -i 'union select\\|drop table\\|xp_cmdshell' /var/log/mysql/error.log"},
            ]
        },
        "data_exfil_response": {
            "name": "Data Exfiltration Response",
            "trigger": "data_exfil",
            "steps": [
                {"name":"Block destination","cmd":"iptables -I OUTPUT -d {dst_ip} -j DROP"},
                {"name":"Kill connections","cmd":"ss -K dst {dst_ip}"},
                {"name":"Check outbound traffic","cmd":"ss -antp | grep ESTABLISHED"},
                {"name":"Find process","cmd":"lsof -i @{dst_ip}"},
                {"name":"Capture evidence","cmd":"tcpdump -i any -w /tmp/evidence_{dst_ip}.pcap host {dst_ip} -c 1000 &"},
            ]
        },
        "llmnr_poison_response": {
            "name": "LLMNR/NBT-NS Poison Response",
            "trigger": "llmnr_poison",
            "steps": [
                {"name":"Block attacker","cmd":"iptables -I INPUT -s {src_ip} -j DROP"},
                {"name":"Disable LLMNR","cmd":"echo '[main]\\nLLMNR=no' >> /etc/systemd/resolved.conf && systemctl restart systemd-resolved"},
                {"name":"Check for captured hashes","cmd":"grep -r 'NTLMv2\\|NetNTLMv2' /var/log/ 2>/dev/null | head"},
                {"name":"Force password resets","cmd":"echo 'Force reset all domain passwords immediately'"},
            ]
        },
    }

    def run_playbook(self, playbook_id, alert_id=None, src_ip="", dst_ip=""):
        if playbook_id not in self.PLAYBOOKS:
            return {"error": f"Unknown playbook: {playbook_id}"}
        pb   = self.PLAYBOOKS[playbook_id]
        log_entry = {
            "id":          hashlib.md5(f"{playbook_id}{time.time()}".encode()).hexdigest()[:8],
            "playbook":    playbook_id,
            "name":        pb["name"],
            "alert_id":    alert_id,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "timestamp":   datetime.now().isoformat(),
            "steps":       [],
            "status":      "completed",
        }
        for step in pb["steps"]:
            cmd = step["cmd"].format(src_ip=src_ip or "UNKNOWN", dst_ip=dst_ip or "UNKNOWN",
                                     gateway_ip="", gateway_mac="")
            log_entry["steps"].append({
                "name": step["name"],
                "cmd":  cmd,
                "note": "Ready to execute — run in terminal or enable auto-execute in SOAR",
            })
        logs = self._load_json(PLAYBOOK_LOG, [])
        logs.insert(0, log_entry)
        self._save_json(PLAYBOOK_LOG, logs[:100])
        return log_entry

    def get_playbook_logs(self):
        return self._load_json(PLAYBOOK_LOG, [])

    # ── Traffic generator ──────────────────────────────────────────────────────
    def generate_traffic(self, traffic_type, target, port=80, count=5):
        if not SCAPY_OK:
            return {"error": "scapy required"}
        results = []
        try:
            if traffic_type == "ping":
                for i in range(min(count,10)):
                    r = scapy.sr1(scapy.IP(dst=target)/scapy.ICMP(), timeout=1, verbose=False)
                    results.append({"seq":i+1,"reply":bool(r),"time":round(time.time(),3)})
            elif traffic_type == "port_scan":
                common = [21,22,23,25,53,80,110,143,443,445,3306,3389,6379,8080,8443]
                for p in common[:20]:
                    try:
                        s = socket.socket()
                        s.settimeout(0.3)
                        r = s.connect_ex((target, p))
                        results.append({"port":p,"open":r==0})
                        s.close()
                    except Exception:
                        results.append({"port":p,"open":False})
            elif traffic_type == "tcp_connect":
                try:
                    s = socket.socket()
                    s.settimeout(2)
                    r = s.connect_ex((target, port))
                    results.append({"port":port,"connected":r==0,"banner":""})
                    if r == 0:
                        try:
                            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = s.recv(256).decode("utf-8","ignore")
                            results[0]["banner"] = banner[:100]
                        except Exception: pass
                    s.close()
                except Exception as e:
                    results.append({"error":str(e)})
            elif traffic_type == "syn_packet":
                pkt = scapy.IP(dst=target)/scapy.TCP(dport=port, flags="S")
                r   = scapy.sr1(pkt, timeout=1, verbose=False)
                results.append({"type":"SYN","dst":target,"port":port,"reply":bool(r),
                                 "flags":r[scapy.TCP].flags if r and scapy.TCP in r else ""})
            elif traffic_type == "flood_test":
                pkts = [scapy.IP(dst=target)/scapy.ICMP() for _ in range(min(count,50))]
                scapy.send(pkts, verbose=False)
                results.append({"sent":len(pkts),"target":target,"type":"ICMP flood test"})
        except Exception as e:
            results.append({"error": str(e)})
        return {"type": traffic_type, "target": target, "results": results}

    # ── Baseline ─────────────────────────────────────────────────────────────
    def start_baseline(self, duration=300):
        self._baseline_building = True
        self._baseline_start    = time.time()
        self._baseline_data     = defaultdict(lambda: {"pkts":[],"ts":time.time()})
        threading.Timer(duration, self._finish_baseline).start()
        return {"status":"learning","duration":duration}

    def _finish_baseline(self):
        baseline = {}
        for ip, data in self._baseline_data.items():
            if data["pkts"]:
                avg = sum(data["pkts"]) / len(data["pkts"])
                baseline[ip] = {"avg_pkts_per_min": avg, "max": max(data["pkts"])}
        self._baseline = baseline
        self._save_json(BASELINE_FILE, baseline)
        self._baseline_building = False

    def get_baseline_status(self):
        elapsed = int(time.time()-self._baseline_start) if self._baseline_start else 0
        return {
            "learning": self._baseline_building,
            "elapsed":  elapsed,
            "ips_learned": len(self._baseline),
            "data": self._baseline,
        }

    # ── TLS Key Log ───────────────────────────────────────────────────────────
    def get_tls_info(self):
        key_count = 0
        if TLS_KEY_LOG.exists():
            key_count = sum(1 for l in TLS_KEY_LOG.read_text().splitlines() if l.strip() and not l.startswith("#"))
        current = os.environ.get("SSLKEYLOGFILE","")
        return {
            "keylog_path": str(TLS_KEY_LOG),
            "key_count": key_count,
            "env_set": bool(current),
            "current_path": current,
            "setup_commands": {
                "firefox": f"SSLKEYLOGFILE={TLS_KEY_LOG} firefox",
                "chrome":  f"SSLKEYLOGFILE={TLS_KEY_LOG} google-chrome",
                "system_wide": f"export SSLKEYLOGFILE={TLS_KEY_LOG}",
                "python":  f"import os; os.environ['SSLKEYLOGFILE']='{TLS_KEY_LOG}'",
            }
        }

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _auto_interface(self):
        try:
            ifaces = scapy.get_if_list() if SCAPY_OK else []
            for i in ifaces:
                if i not in ("lo","any") and not i.startswith("docker"):
                    return i
        except Exception: pass
        return "eth0"

    def _list_interfaces(self):
        try:
            if SCAPY_OK:
                return [i for i in scapy.get_if_list() if i != "any"]
        except Exception: pass
        ifaces = []
        try:
            for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
                name = line.split(":")[0].strip()
                if name: ifaces.append(name)
        except Exception: pass
        return ifaces or ["eth0","wlan0","lo"]

    def _capture_loop(self):
        try:
            scapy.sniff(iface=self._interface, prn=self._process_packet,
                        store=False, stop_filter=lambda _: not self._running)
        except Exception as e:
            print(f"[Net] Capture error: {e}")
            self._running = False

    def _process_packet(self, pkt):
        self.packets_captured += 1
        self._packet_id += 1
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Build packet record
        src_ip = dst_ip = ""
        src_port = dst_port = 0
        proto = "OTHER"
        flags = ""
        info  = ""
        length = len(pkt)
        payload_hex = ""
        payload_ascii = ""
        layers = []

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            layers.append(f"IP src={src_ip} dst={dst_ip} ttl={pkt[IP].ttl} id={pkt[IP].id}")

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            raw_flags = pkt[TCP].flags
            # Handle both int and string flags
            if hasattr(raw_flags, 'flagrepr'):
                flags = str(raw_flags)
            elif isinstance(raw_flags, int):
                fmap = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U",0x40:"E",0x80:"C"}
                flags = "".join(v for k,v in fmap.items() if raw_flags & k)
            else:
                flags = str(raw_flags)
            proto = "TCP"
            info  = f"{src_port} → {dst_port} [{flags}]"
            layers.append(f"TCP sport={src_port} dport={dst_port} flags={flags} seq={pkt[TCP].seq}")

            # HTTP detection
            if dst_port in (80,8080,8000) or src_port in (80,8080,8000):
                try:
                    pay = bytes(pkt[TCP].payload).decode("utf-8","ignore")
                    if pay.startswith(("GET","POST","PUT","DELETE","HEAD","HTTP")):
                        proto = "HTTP"
                        info  = pay.split("\r\n")[0][:80]
                        payload_ascii = pay[:200]
                        layers.append(f"HTTP: {pay.split(chr(10))[0][:60]}")
                        self._check_web_attacks(pay, src_ip, dst_ip, dst_port)
                except Exception: pass

            self._check_tcp(pkt, src_ip, dst_ip, src_port, dst_port, flags)

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto    = "UDP"
            info     = f"{src_port} → {dst_port}"
            layers.append(f"UDP sport={src_port} dport={dst_port}")
            self._check_udp(pkt, src_ip, dst_ip, src_port, dst_port)

        elif ICMP in pkt:
            proto = "ICMP"
            info  = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            layers.append(f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}")
            self._check_icmp(pkt, src_ip, dst_ip)

        elif ARP in pkt:
            proto = "ARP"
            info  = f"who has {pkt[ARP].pdst} tell {pkt[ARP].psrc}"
            layers.append(f"ARP op={pkt[ARP].op} hwsrc={pkt[ARP].hwsrc} psrc={pkt[ARP].psrc}")
            self._check_arp(pkt)

        if DNS in pkt and DNSQR in pkt:
            proto = "DNS"
            qname = pkt[DNSQR].qname.decode("utf-8","ignore").rstrip(".")
            info  = f"Query: {qname}"
            layers.append(f"DNS qname={qname} qtype={pkt[DNSQR].qtype}")
            self._check_dns(pkt, src_ip, dst_ip, qname)

        # Payload hex
        try:
            raw = bytes(pkt)[-32:]
            payload_hex   = raw.hex()
            payload_ascii = raw.decode("latin-1","replace")
        except Exception: pass

        # Threat check
        is_threat = src_ip in self._blocklist

        rec = {
            "id": self._packet_id, "timestamp": ts,
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "protocol": proto, "length": length,
            "flags": flags, "info": info,
            "is_threat": is_threat, "threat_type": "",
            "payload_hex": payload_hex, "payload_ascii": payload_ascii,
            "layers": layers,
        }
        self._packets.append(rec)

        # Exfil tracking
        if src_ip:
            self._exfil_tracker[src_ip]["bytes"] += length
            now = time.time()
            if now - self._exfil_tracker[src_ip]["ts"] > 60:
                if self._exfil_tracker[src_ip]["bytes"] > 100_000_000:
                    self._make_alert("data_exfil","CRITICAL",src_ip,dst_ip,dst_port,proto,
                                     1,f"Large data transfer: {self._exfil_tracker[src_ip]['bytes']//1024//1024}MB to {dst_ip}")
                self._exfil_tracker[src_ip] = {"bytes":0,"ts":now}

        # Baseline anomaly
        if self._baseline_building and src_ip:
            minute = int(time.time()//60)
            self._baseline_data[src_ip]["pkts"].append(minute)
        elif self._baseline and src_ip in self._baseline:
            bl = self._baseline[src_ip]
            minute_rate = self._exfil_tracker[src_ip]["bytes"] / max(1, time.time()-self._exfil_tracker[src_ip]["ts"]) * 60
            if minute_rate > bl.get("avg_pkts_per_min",0) * 5:
                self._make_alert("data_exfil","HIGH",src_ip,dst_ip,0,proto,1,
                                 f"Traffic 5× above baseline for {src_ip}")

    # ── Protocol analysers ────────────────────────────────────────────────────
    def _check_tcp(self, pkt, src_ip, dst_ip, sp, dp, flags):
        now = time.time()
        flag_str = str(flags)

        # SYN scan
        if "S" in flag_str and "A" not in flag_str:
            self._syn_tracker[src_ip][dst_ip].append(now)
            self._syn_tracker[src_ip][dst_ip] = [t for t in self._syn_tracker[src_ip][dst_ip] if now-t<60]
            ports_hit = len(set(str(dp) for c in self._syn_tracker[src_ip].values() for _ in c))
            if ports_hit > 20:
                self._make_alert("syn_scan","HIGH",src_ip,dst_ip,dp,"TCP",
                                 ports_hit,f"SYN scan: {ports_hit} ports in 60s from {src_ip}")

        # Stealth scans
        if flag_str == "" or flag_str == "0":
            self._make_alert("null_scan","MEDIUM",src_ip,dst_ip,dp,"TCP",1,f"NULL scan from {src_ip}")
        elif "F" in flag_str and "P" in flag_str and "U" in flag_str:
            self._make_alert("xmas_scan","MEDIUM",src_ip,dst_ip,dp,"TCP",1,f"XMAS scan from {src_ip}")
        elif "F" in flag_str and "A" not in flag_str and "S" not in flag_str:
            self._make_alert("fin_scan","LOW",src_ip,dst_ip,dp,"TCP",1,f"FIN scan from {src_ip}")

        # Brute force targets
        brute_ports = {22:"ssh_brute",3389:"rdp_brute",21:"ftp_brute",
                       80:"http_brute",443:"http_brute",445:"smb_brute",
                       3306:"mysql_brute",6379:"redis_brute",389:"ldap_brute",
                       88:"kerberoasting",5900:"vnc_brute",25:"smtp_brute",
                       110:"pop3_brute",143:"imap_brute",5985:"winrm_brute"}
        if dp in brute_ports and "S" in flag_str:
            key = f"{src_ip}:{dp}"
            self._brute_tracker[src_ip][dp].append(now)
            self._brute_tracker[src_ip][dp] = [t for t in self._brute_tracker[src_ip][dp] if now-t<60]
            if len(self._brute_tracker[src_ip][dp]) > 10:
                attack = brute_ports[dp]
                sev = "CRITICAL" if dp in (22,3389,445) else "HIGH"
                self._make_alert(attack, sev, src_ip, dst_ip, dp, "TCP",
                                 len(self._brute_tracker[src_ip][dp]),
                                 f"{attack.replace('_',' ').title()}: {len(self._brute_tracker[src_ip][dp])} attempts in 60s")

        # Known C2 ports
        if dp in KNOWN_C2_PORTS:
            self._beacon_tracker[src_ip][dst_ip].append(now)
            times = self._beacon_tracker[src_ip][dst_ip]
            if len(times) >= 5:
                intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
                avg = sum(intervals)/len(intervals)
                variance = sum((x-avg)**2 for x in intervals)/len(intervals)
                if avg > 0 and variance/avg < 0.1 and len(times) >= 5:
                    self._make_alert("c2_beacon","CRITICAL",src_ip,dst_ip,dp,"TCP",
                                     len(times),f"C2 beaconing every {avg:.0f}s to {dst_ip}:{dp}")

        # SMB relay / Responder
        if dp == 445 and sp > 1024 and "S" not in flag_str and "A" in flag_str:
            self._make_alert("smb_relay","HIGH",src_ip,dst_ip,445,"TCP",1,
                             f"Potential SMB relay attack from {src_ip}")

        # Slowloris
        if dp in (80,443,8080):
            now2 = time.time()
            s = self._http_state[src_ip]
            if "S" in flag_str: s["open"] += 1
            if "F" in flag_str or "R" in flag_str: s["open"] = max(0,s["open"]-1)
            if now2 - s["ts"] > 30:
                if s["open"] > 50:
                    self._make_alert("slowloris","HIGH",src_ip,dst_ip,dp,"TCP",s["open"],
                                     f"Slowloris: {s['open']} open connections from {src_ip}")
                s["ts"] = now2; s["open"] = 0

        # Plaintext credentials
        try:
            if dp in (21,23,80,8080,110,143):
                pay = bytes(pkt[TCP].payload).decode("utf-8","ignore").lower()
                if any(k in pay for k in ["password=","pass=","passwd=","authorization: basic","user=","username="]):
                    self._make_alert("plaintext_cred","HIGH",src_ip,dst_ip,dp,"TCP",1,
                                     f"Plaintext credentials on port {dp} from {src_ip}")
        except Exception: pass

    def _check_udp(self, pkt, src_ip, dst_ip, sp, dp):
        # UDP scan
        if dp in [53,67,68,69,123,161,162,500,514]:
            return
        self._syn_tracker[src_ip]["udp"].append(time.time())
        ports = len(self._syn_tracker[src_ip]["udp"])
        if ports > 30:
            self._make_alert("udp_scan","MEDIUM",src_ip,dst_ip,dp,"UDP",ports,
                             f"UDP scan: {ports} ports from {src_ip}")

        # DHCP starvation
        if dp == 67:
            self._dhcp_servers.add(src_ip)
            if len(self._dhcp_servers) > 2:
                self._make_alert("rogue_dhcp","HIGH",src_ip,dst_ip,67,"UDP",1,
                                 f"Rogue DHCP server detected: {src_ip}")
        # SNMP enum
        if dp == 161:
            self._make_alert("snmp_enum","LOW",src_ip,dst_ip,161,"UDP",1,
                             f"SNMP query from {src_ip}")
        # SIP flood
        if dp == 5060:
            self._tgq_tracker[src_ip].append(time.time())
            self._tgq_tracker[src_ip] = [t for t in self._tgq_tracker[src_ip] if time.time()-t<60]
            if len(self._tgq_tracker[src_ip]) > 50:
                self._make_alert("sip_flood","HIGH",src_ip,dst_ip,5060,"UDP",
                                 len(self._tgq_tracker[src_ip]),f"SIP flood from {src_ip}")

    def _check_icmp(self, pkt, src_ip, dst_ip):
        now = time.time()
        key = f"icmp:{src_ip}"
        self._syn_tracker[src_ip]["icmp"].append(now)
        self._syn_tracker[src_ip]["icmp"] = [t for t in self._syn_tracker[src_ip]["icmp"] if now-t<60]
        cnt = len(self._syn_tracker[src_ip]["icmp"])
        if pkt[ICMP].type == 8:  # echo request
            if cnt > 20:
                self._make_alert("ping_sweep","LOW",src_ip,dst_ip,0,"ICMP",cnt,
                                 f"Ping sweep from {src_ip}")
            if cnt > 100:
                self._make_alert("icmp_flood","HIGH",src_ip,dst_ip,0,"ICMP",cnt,
                                 f"ICMP flood: {cnt} packets/min from {src_ip}")
        # ICMP tunnel
        if len(pkt) > 100 and pkt[ICMP].type == 0:
            try:
                pay = bytes(pkt[ICMP].payload)
                if len(pay) > 64:
                    self._make_alert("icmp_tunnel","MEDIUM",src_ip,dst_ip,0,"ICMP",1,
                                     f"Large ICMP payload ({len(pay)}B) — possible tunnel")
            except Exception: pass

    def _check_arp(self, pkt):
        if pkt[ARP].op == 2:  # ARP reply
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in self._arp_table and self._arp_table[ip] != mac:
                self._make_alert("arp_spoof","CRITICAL",ip,pkt[ARP].pdst,0,"ARP",1,
                                 f"ARP spoofing: {ip} changed from {self._arp_table[ip]} to {mac}")
            self._arp_table[ip] = mac

    def _check_dns(self, pkt, src_ip, dst_ip, qname):
        # DNS tunneling — long subdomain
        if len(qname) > 50:
            self._make_alert("dns_tunnel","HIGH",src_ip,dst_ip,53,"DNS",1,
                             f"DNS tunnel: long query {qname[:40]}...")
        # DGA detection (entropy)
        parts = qname.split(".")
        if parts:
            sub = parts[0]
            if len(sub) > 8:
                vowels = sum(1 for c in sub.lower() if c in "aeiou")
                ratio  = vowels / len(sub)
                unique = len(set(sub))
                if ratio < 0.15 and unique > 8:
                    self._make_alert("dga_domain","MEDIUM",src_ip,dst_ip,53,"DNS",1,
                                     f"DGA-like domain: {qname}")
        # LLMNR poisoning
        if dst_ip in ("224.0.0.252","ff02::1:3"):
            self._make_alert("llmnr_poison","HIGH",src_ip,dst_ip,5355,"DNS",1,
                             f"LLMNR/mDNS broadcast from {src_ip} — potential Responder attack")
        # DNS exfil
        self._dns_queries[src_ip].append(time.time())
        self._dns_queries[src_ip] = [t for t in self._dns_queries[src_ip] if time.time()-t<60]
        if len(self._dns_queries[src_ip]) > 100:
            self._make_alert("dns_exfil","HIGH",src_ip,dst_ip,53,"DNS",
                             len(self._dns_queries[src_ip]),
                             f"High DNS query rate: {len(self._dns_queries[src_ip])}/min from {src_ip}")

    def _check_web_attacks(self, payload, src_ip, dst_ip, dst_port):
        pl = payload.lower()
        for pat in SQL_PATTERNS:
            if pat.search(pl):
                self._make_alert("sql_injection","CRITICAL",src_ip,dst_ip,dst_port,"HTTP",1,
                                 f"SQL injection detected from {src_ip}")
                return
        for pat in XSS_PATTERNS:
            if pat.search(pl):
                self._make_alert("xss_attack","HIGH",src_ip,dst_ip,dst_port,"HTTP",1,
                                 f"XSS attempt from {src_ip}")
                return
        for pat in CMD_PATTERNS:
            if pat.search(pl):
                self._make_alert("cmd_injection","CRITICAL",src_ip,dst_ip,dst_port,"HTTP",1,
                                 f"Command injection from {src_ip}")
                return
        # Path traversal
        if "../" in pl or "..%2f" in pl or "%2e%2e" in pl:
            self._make_alert("path_traversal","HIGH",src_ip,dst_ip,dst_port,"HTTP",1,
                             f"Path traversal from {src_ip}")
        # Scanner detection
        scanner_agents = ["nikto","sqlmap","nessus","openvas","masscan","zap","burp"]
        if any(s in pl for s in scanner_agents):
            self._make_alert("web_scanner","MEDIUM",src_ip,dst_ip,dst_port,"HTTP",1,
                             f"Web scanner detected from {src_ip}")
        # Tor traffic
        if TOR_EXIT_PATTERN.search(pl):
            self._make_alert("tor_traffic","MEDIUM",src_ip,dst_ip,dst_port,"HTTP",1,
                             f"Tor-related traffic from {src_ip}")

    def _apply_filter(self, pkts, filt):
        """Wireshark-style filter: ip.src == x, tcp.port == 80, protocol == HTTP"""
        self.add_filter_history(filt)
        result = []
        for p in pkts:
            try:
                f = filt.strip().lower()
                if f.startswith("ip.src =="):
                    val = f.split("==")[1].strip().strip('"\'')
                    if p.get("src_ip","") == val: result.append(p)
                elif f.startswith("ip.dst =="):
                    val = f.split("==")[1].strip().strip('"\'')
                    if p.get("dst_ip","") == val: result.append(p)
                elif f.startswith("tcp.port =="):
                    val = int(f.split("==")[1].strip())
                    if p.get("src_port")==val or p.get("dst_port")==val: result.append(p)
                elif f.startswith("udp.port =="):
                    val = int(f.split("==")[1].strip())
                    if p.get("protocol")=="UDP" and (p.get("src_port")==val or p.get("dst_port")==val): result.append(p)
                elif f.startswith("protocol =="):
                    val = f.split("==")[1].strip().strip('"\'').upper()
                    if p.get("protocol","").upper() == val: result.append(p)
                elif f.startswith("alert =="):
                    if p.get("is_threat"): result.append(p)
                elif f.startswith("ip =="):
                    val = f.split("==")[1].strip().strip('"\'')
                    if p.get("src_ip")==val or p.get("dst_ip")==val: result.append(p)
                elif "contains" in f:
                    parts = f.split("contains")
                    val = parts[1].strip().strip('"\'')
                    if val in str(p.get("info","")).lower() or val in p.get("payload_ascii","").lower():
                        result.append(p)
                else:
                    # Text search fallback
                    if filt.lower() in str(p).lower(): result.append(p)
            except Exception:
                if filt.lower() in str(p).lower(): result.append(p)
        return result

    def _make_alert(self, attack_type, severity, src_ip, dst_ip, port,
                    proto, count, description):
        # Cooldown check
        cooldown_key = f"{attack_type}:{src_ip}"
        now = time.time()
        cooldown_secs = {"syn_scan":30,"ping_sweep":120,"null_scan":60,
                         "fin_scan":60,"xmas_scan":60,"udp_scan":30,
                         "snmp_enum":300,"web_scanner":60}.get(attack_type, 60)
        if cooldown_key in self._cooldown and now - self._cooldown[cooldown_key] < cooldown_secs:
            return None
        self._cooldown[cooldown_key] = now
        mitre_id, mitre_name, tactic = MITRE_MAP.get(attack_type, ("T0000","Unknown","Unknown"))
        alert_id = hashlib.md5(f"{attack_type}{src_ip}{now}".encode()).hexdigest()[:12]
        alert = NetworkAlert(
            id=alert_id,
            timestamp=datetime.now().isoformat(),
            severity=severity,
            attack_type=attack_type,
            attack_name=attack_type.replace("_"," ").title(),
            source_ip=str(src_ip),
            dest_ip=str(dst_ip),
            port=int(port),
            protocol=proto,
            packet_count=count,
            mitre=mitre_id,
            mitre_name=mitre_name,
            tactic=tactic,
            description=description,
        )
        # AI analysis
        alert.ai_analysis = self._ai_explain(alert)
        # Auto-block if blocklist enabled
        if os.environ.get("SOAR_AUTO_BLOCK","false").lower() == "true":
            if SEVERITY_LEVELS.get(severity,0) >= SEVERITY_LEVELS["CRITICAL"]:
                self.block_ip(str(src_ip), reason=f"Auto-block: {attack_type}", method="iptables")
                alert.blocked = True
                alert.action_taken = "Auto-blocked via iptables"
        d = alert.to_dict()
        with self._lock:
            self._alerts.insert(0, d)
            self._alerts = self._alerts[:2000]
            self.alerts_generated += 1
        self._save_json(ALERTS_FILE, self._alerts[:500])
        # Fire alerts via alerting module
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from alerting import fire_alert
            fire_alert(d)
        except Exception: pass
        return alert

    def _ai_explain(self, alert):
        """Try Ollama, fall back to rule-based"""
        try:
            import requests as req
            url   = os.environ.get("OLLAMA_URL","http://localhost:11434")
            model = os.environ.get("OLLAMA_MODEL","llama3.2")
            prompt = (f"You are a SOC analyst. Explain this network alert in 2 sentences for a security manager: "
                      f"Attack={alert.attack_type}, Source={alert.source_ip}, Dest={alert.dest_ip}:{alert.port}, "
                      f"Severity={alert.severity}, MITRE={alert.mitre}. Then give ONE recommended action.")
            r = req.post(f"{url}/api/generate",
                         json={"model":model,"prompt":prompt,"stream":False},
                         timeout=5)
            if r.status_code == 200:
                return r.json().get("response","").strip()[:300]
        except Exception: pass
        # Rule-based fallback
        explanations = {
            "syn_scan":       "An attacker is scanning for open ports — reconnaissance phase before exploitation.",
            "ssh_brute":      "Repeated SSH login attempts — credential stuffing or dictionary attack.",
            "rdp_brute":      "Repeated RDP login attempts — attacker trying to gain remote access.",
            "arp_spoof":      "ARP table poisoning — attacker intercepting traffic between hosts (MITM).",
            "c2_beacon":      "Regular connection to external IP — possible malware checking in with C2 server.",
            "dns_tunnel":     "Long DNS queries — data being smuggled via DNS protocol.",
            "sql_injection":  "SQL injection payload in HTTP request — attacker targeting database.",
            "data_exfil":     "Large outbound data transfer — possible data theft in progress.",
            "icmp_flood":     "High-volume ICMP — DDoS attack or network reconnaissance.",
            "llmnr_poison":   "LLMNR broadcast — Responder tool likely running, harvesting NTLM hashes.",
        }
        base = explanations.get(alert.attack_type, f"Suspicious {alert.attack_type} activity detected.")
        actions = {
            "CRITICAL": "Isolate affected host immediately and investigate.",
            "HIGH":     "Block source IP and review logs.",
            "MEDIUM":   "Monitor and log for pattern analysis.",
            "LOW":      "Note in security log for trend analysis.",
        }
        return f"{base} {actions.get(alert.severity, 'Review and investigate.')}"


# ── Singleton ─────────────────────────────────────────────────────────────────
_ids_engine = None

def get_ids_engine():
    global _ids_engine
    if _ids_engine is None:
        _ids_engine = VoraGuardIDS()
    return _ids_engine

# ── Playbooks (required export) ───────────────────────────────────────────────
PLAYBOOKS = {
    "ssh_brute_response": {
        "name": "SSH Brute Force Response", "trigger": "ssh_brute",
        "steps": [
            {"name": "Block source IP",    "cmd": "iptables -I INPUT -s {src_ip} -j DROP"},
            {"name": "Check failed logins","cmd": "lastb | head -20"},
            {"name": "Lock account",       "cmd": "faillock --user root --lock"},
            {"name": "Check auth log",     "cmd": "tail -50 /var/log/auth.log | grep {src_ip}"},
        ]},
    "arp_spoof_response": {
        "name": "ARP Spoofing Response", "trigger": "arp_spoof",
        "steps": [
            {"name": "Block attacker",    "cmd": "iptables -I INPUT -s {src_ip} -j DROP"},
            {"name": "Flush ARP cache",   "cmd": "ip neigh flush all"},
            {"name": "Check ARP table",   "cmd": "arp -n"},
        ]},
    "c2_beacon_response": {
        "name": "C2 Beacon Response", "trigger": "c2_beacon",
        "steps": [
            {"name": "Block C2 IP",    "cmd": "iptables -I OUTPUT -d {dst_ip} -j DROP"},
            {"name": "Find process",   "cmd": "lsof -i @{dst_ip}"},
            {"name": "Kill process",   "cmd": "kill -9 $(lsof -ti @{dst_ip})"},
        ]},
    "sqli_response": {
        "name": "SQL Injection Response", "trigger": "sql_injection",
        "steps": [
            {"name": "Block source IP", "cmd": "iptables -I INPUT -s {src_ip} -j DROP"},
            {"name": "Check web logs",  "cmd": "grep {src_ip} /var/log/nginx/access.log | tail -20"},
        ]},
    "data_exfil_response": {
        "name": "Data Exfiltration Response", "trigger": "data_exfil",
        "steps": [
            {"name": "Block destination", "cmd": "iptables -I OUTPUT -d {dst_ip} -j DROP"},
            {"name": "Capture evidence",  "cmd": "tcpdump -i any -w /tmp/evidence.pcap host {dst_ip} -c 1000 &"},
        ]},
    "llmnr_poison_response": {
        "name": "LLMNR Poison Response", "trigger": "llmnr_poison",
        "steps": [
            {"name": "Block attacker",  "cmd": "iptables -I INPUT -s {src_ip} -j DROP"},
            {"name": "Disable LLMNR",   "cmd": "echo '[main]\\nLLMNR=no' >> /etc/systemd/resolved.conf && systemctl restart systemd-resolved"},
        ]},
}
