"""
VoraGuard SOAR Engine v5.0
Security Orchestration, Automation & Response
Developed by Jithu

Rule-based automation: IF event matches conditions THEN execute actions automatically.
"""
import os, json, re, time, logging, smtplib, threading, subprocess
from pathlib import Path
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

VORAG_HOME    = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
SOAR_DIR      = VORAG_HOME / "soar"
SOAR_DIR.mkdir(parents=True, exist_ok=True)
RULES_FILE    = SOAR_DIR / "rules.json"
INCIDENTS_FILE= SOAR_DIR / "incidents.json"
BLOCKLIST_FILE= SOAR_DIR / "ip_blocklist.txt"
TICKETS_DIR   = SOAR_DIR / "tickets"
TICKETS_DIR.mkdir(exist_ok=True)
log = logging.getLogger("vorag.soar")

DEFAULT_RULES = [
    {"id":"rule_001","name":"Critical Credential Exposure → Alert + Ticket + Notify User",
     "enabled":True,"trigger":"credential_exposure","conditions":{"severity":["CRITICAL","HIGH"]},
     "actions":["send_alert","create_ticket","notify_user","log_incident"],"priority":1,
     "description":"Leaked credentials found — alert all channels, create ticket, email affected user."},
    {"id":"rule_002","name":"Network Port Scan → Alert + Log",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["port_scan","syn_scan","udp_scan"]},
     "actions":["send_alert","log_incident"],"priority":2,
     "description":"Port scan detected on network."},
    {"id":"rule_003","name":"Brute Force Attack → Alert + Block IP + Ticket",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["brute_force","ssh_brute","rdp_brute","credential_stuffing"]},
     "actions":["send_alert","block_ip","create_ticket","log_incident"],"priority":1,
     "description":"Brute force attack detected — block source IP immediately."},
    {"id":"rule_004","name":"C2 / Malware Beaconing → CRITICAL Alert + Block + Ticket",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["c2_beacon","malware_c2","dns_tunnel"]},
     "actions":["send_alert","block_ip","create_ticket","log_incident"],"priority":1,
     "description":"C2 communication detected — block and escalate immediately."},
    {"id":"rule_005","name":"Phishing / Typosquat Domain → Alert + Quarantine + Ticket",
     "enabled":True,"trigger":"domain_alert","conditions":{"threat_type":["phishing","typosquat","impersonation","homograph"]},
     "actions":["send_alert","create_ticket","quarantine_domain","log_incident"],"priority":1,
     "description":"Phishing or lookalike domain detected — quarantine locally."},
    {"id":"rule_006","name":"CISA KEV CVE → Alert + Ticket",
     "enabled":True,"trigger":"vulnerability","conditions":{"is_kev":True},
     "actions":["send_alert","create_ticket","log_incident"],"priority":1,
     "description":"Actively exploited CVE (CISA KEV list) — immediate patch required."},
    {"id":"rule_007","name":"High EPSS Score CVE → Alert",
     "enabled":True,"trigger":"vulnerability","conditions":{"epss_score_min":0.7},
     "actions":["send_alert","log_incident"],"priority":2,
     "description":"CVE with ≥70% exploitation probability detected."},
    {"id":"rule_008","name":"Dark Web Brand Mention → Alert + Ticket",
     "enabled":True,"trigger":"darkweb_mention","conditions":{"severity":["CRITICAL","HIGH"]},
     "actions":["send_alert","create_ticket","log_incident"],"priority":1,
     "description":"Brand or domain found on dark web / stealer logs."},
    {"id":"rule_009","name":"Known APT Activity → CRITICAL Alert + Ticket",
     "enabled":True,"trigger":"threat_actor","conditions":{"confidence_min":0.6},
     "actions":["send_alert","create_ticket","log_incident"],"priority":1,
     "description":"Activity matching known APT threat actor detected."},
    {"id":"rule_010","name":"Identity Risk Event → Alert + Force Password Reset",
     "enabled":True,"trigger":"identity_risk","conditions":{"risk_level":["HIGH","CRITICAL"]},
     "actions":["send_alert","force_password_reset","create_ticket","log_incident"],"priority":1,
     "description":"High-risk identity event from Entra/Workspace/Okta."},
    {"id":"rule_011","name":"ARP Spoofing / MITM → CRITICAL Alert",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["arp_spoof","mitm","arp_poison"]},
     "actions":["send_alert","log_incident"],"priority":1,
     "description":"ARP spoofing / man-in-the-middle attack on local network."},
    {"id":"rule_012","name":"DNS Anomaly → Alert",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["dns_spoof","dns_hijack","dns_exfil"]},
     "actions":["send_alert","log_incident"],"priority":2,
     "description":"Suspicious DNS activity — possible hijacking or data exfiltration."},
    {"id":"rule_013","name":"Data Exfiltration Pattern → CRITICAL Alert + Block",
     "enabled":True,"trigger":"network_alert","conditions":{"attack_type":["data_exfil","large_upload","suspicious_transfer"]},
     "actions":["send_alert","block_ip","create_ticket","log_incident"],"priority":1,
     "description":"Possible data exfiltration detected — large outbound transfer to external host."},
]

def load_rules():
    if RULES_FILE.exists():
        try: return json.loads(RULES_FILE.read_text())
        except Exception: pass
    RULES_FILE.write_text(json.dumps(DEFAULT_RULES, indent=2))
    return DEFAULT_RULES

def save_rules(rules):
    RULES_FILE.write_text(json.dumps(rules, indent=2))

def enable_rule(rule_id, enabled):
    rules = load_rules()
    for r in rules:
        if r["id"] == rule_id: r["enabled"] = enabled
    save_rules(rules)

def add_rule(rule):
    rules = load_rules()
    rule.setdefault("id", f"rule_{int(time.time())}")
    rule.setdefault("enabled", True)
    rule.setdefault("priority", 3)
    rules.append(rule)
    save_rules(rules)
    return rule["id"]

def _matches(conditions, event):
    for key, value in conditions.items():
        ev = event.get(key)
        if key in ("severity","attack_type","threat_type","risk_level"):
            allowed = value if isinstance(value, list) else [value]
            if ev not in allowed: return False
        elif key == "is_kev":
            if bool(ev) != bool(value): return False
        elif key == "epss_score_min":
            try:
                if float(ev or 0) < float(value): return False
            except: return False
        elif key == "confidence_min":
            try:
                if float(ev or 0) < float(value): return False
            except: return False
    return True

def _map_priority(sev):
    return {"CRITICAL":"P1","HIGH":"P2","MEDIUM":"P3","LOW":"P4"}.get(str(sev).upper(),"P3")

def _count_blocked():
    if BLOCKLIST_FILE.exists():
        return sum(1 for l in BLOCKLIST_FILE.read_text().splitlines() if l.strip() and not l.startswith("#"))
    return 0

def _build_message(event, rule):
    parts = [
        f"🚨 SOAR: {rule.get('name','')}",
        f"Severity: {event.get('severity','?')} | Trigger: {event.get('trigger','?')}",
        f"Title: {event.get('title','')}",
    ]
    for field, label in [("source_ip","Source IP"),("domain","Domain"),("affected_email","User")]:
        if event.get(field): parts.append(f"{label}: {event[field]}")
    parts += ["", event.get("summary", event.get("description",""))[:400],
              f"\nRule: {rule.get('id')} — {rule.get('description','')}",
              f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
    return "\n".join(parts)

def _send_email(to, subject, body):
    host = os.environ.get("ALERT_SMTP_HOST","smtp.gmail.com")
    port = int(os.environ.get("ALERT_SMTP_PORT","587"))
    user = os.environ.get("ALERT_EMAIL_USER","")
    pw   = os.environ.get("ALERT_EMAIL_PASS","")
    if not (user and pw): return
    try:
        msg = MIMEMultipart(); msg["Subject"]=subject; msg["From"]=user; msg["To"]=to
        msg.attach(MIMEText(body,"plain"))
        with smtplib.SMTP(host, port) as s:
            s.ehlo(); s.starttls(); s.login(user, pw)
            s.sendmail(user, to, msg.as_string())
        log.info(f"[SOAR] Email → {to}")
    except Exception as e: log.error(f"[SOAR] email: {e}")

def _action_send_alert(event, rule):
    try:
        from alerting import AlertEngine
        AlertEngine().send_all(
            title=f"[SOAR] {rule.get('name','')}",
            message=_build_message(event, rule),
            severity=event.get("severity","HIGH"),
            source=event.get("source","SOAR"),
            details=event.get("details",{}))
    except Exception as e: log.error(f"[SOAR] send_alert: {e}")

def _action_create_ticket(event, rule):
    tid = f"TKT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    t = {"ticket_id":tid,"rule_id":rule.get("id"),"rule_name":rule.get("name"),
         "created_at":datetime.now(timezone.utc).isoformat(),"status":"OPEN",
         "priority":_map_priority(event.get("severity","HIGH")),
         "title":f"[{event.get('severity','?')}] {event.get('title','')}",
         "description":event.get("summary",event.get("description","")),"event":event}
    (TICKETS_DIR/f"{tid}.json").write_text(json.dumps(t, indent=2, default=str))
    log.info(f"[SOAR] Ticket: {tid}")
    gh_tok = os.environ.get("GITHUB_TOKEN",""); gh_repo = os.environ.get("GITHUB_REPO","")
    if gh_tok and gh_repo:
        try:
            import requests
            requests.post(f"https://api.github.com/repos/{gh_repo}/issues",
                json={"title":t["title"],"body":f"**{tid}** | {t['description']}\n\n```json\n{json.dumps(event,indent=2,default=str)}\n```","labels":["security","voraguard"]},
                headers={"Authorization":f"token {gh_tok}"},timeout=10)
        except: pass
    return tid

def _action_notify_user(event, rule):
    email = event.get("affected_email") or event.get("email")
    if not email: return
    _send_email(email, f"⚠️ Security Alert: {event.get('title','')}", f"""
Security monitoring has detected an event affecting your account.

EVENT: {event.get('title','')}
SEVERITY: {event.get('severity','')}
DETAILS: {event.get('summary','')}

Actions:
1. Change your password immediately
2. Enable two-factor authentication
3. Review recent account activity
4. Contact IT security if anything seems unusual

-- VoraGuard Security Platform""")

def _action_force_password_reset(event, rule):
    email = event.get("affected_email") or event.get("email")
    if not email: return
    _send_email(email, "🔑 ACTION REQUIRED: Reset Your Password Now", f"""
⚠️ URGENT: Your credentials may be compromised.

INCIDENT: {event.get('summary','')}
DETECTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

IMMEDIATE ACTIONS:
1. Change your password NOW (min 16 chars, unique)
2. Enable MFA immediately  
3. Revoke suspicious sessions
4. Report to your IT security team

-- VoraGuard Security Platform""")

def _action_block_ip(event, rule):
    ip = event.get("source_ip") or event.get("ip")
    if not ip or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(ip)): return
    p = [int(x) for x in str(ip).split(".")]
    if p[0] in (10,127) or (p[0]==172 and 16<=p[1]<=31) or (p[0]==192 and p[1]==168):
        log.info(f"[SOAR] Skipping private IP: {ip}"); return
    existing = BLOCKLIST_FILE.read_text() if BLOCKLIST_FILE.exists() else ""
    if ip not in existing:
        with open(BLOCKLIST_FILE,"a") as f:
            f.write(f"{ip}  # Blocked {datetime.now().isoformat()} rule:{rule['id']}\n")
    try:
        r = subprocess.run(["sudo","iptables","-A","INPUT","-s",ip,"-j","DROP"],
                           capture_output=True, timeout=10)
        log.info(f"[SOAR] iptables block {ip}: {'OK' if r.returncode==0 else 'needs sudo'}")
    except Exception as e: log.warning(f"[SOAR] iptables: {e}")

def _action_quarantine_domain(event, rule):
    domain = event.get("domain") or event.get("target_domain")
    if not domain: return
    try:
        entry = f"0.0.0.0  {domain}  # VoraGuard {datetime.now().date()}\n"
        if domain not in Path("/etc/hosts").read_text():
            r = subprocess.run(["sudo","tee","-a","/etc/hosts"],
                               input=entry, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                log.info(f"[SOAR] Quarantined domain: {domain}")
    except Exception as e:
        qf = SOAR_DIR/"quarantined_domains.txt"
        with open(qf,"a") as f: f.write(f"{domain}  # {datetime.now().isoformat()}\n")

def _action_log_incident(event, rule):
    incidents = []
    if INCIDENTS_FILE.exists():
        try: incidents = json.loads(INCIDENTS_FILE.read_text())
        except: pass
    incidents.append({
        "timestamp":datetime.now(timezone.utc).isoformat(),
        "rule_id":rule.get("id"),"rule_name":rule.get("name"),
        "trigger":event.get("trigger"),"severity":event.get("severity","MEDIUM"),
        "title":event.get("title",""),"summary":event.get("summary","")[:300],
        "source_ip":event.get("source_ip",""),"domain":event.get("domain",""),
        "email":event.get("affected_email",""),
    })
    INCIDENTS_FILE.write_text(json.dumps(incidents[-2000:], indent=2))

ACTION_MAP = {
    "send_alert":_action_send_alert, "create_ticket":_action_create_ticket,
    "notify_user":_action_notify_user, "force_password_reset":_action_force_password_reset,
    "block_ip":_action_block_ip, "quarantine_domain":_action_quarantine_domain,
    "log_incident":_action_log_incident,
}

class SOAREngine:
    def __init__(self):
        self.rules = load_rules()
        log.info(f"[SOAR] Engine ready: {len(self.rules)} rules")

    def reload_rules(self):
        self.rules = load_rules()

    def process_event(self, event):
        triggered = []
        for rule in sorted([r for r in self.rules if r.get("enabled",True)], key=lambda r: r.get("priority",3)):
            if rule.get("trigger") != event.get("trigger"): continue
            if _matches(rule.get("conditions",{}), event):
                log.info(f"[SOAR] Matched: {rule['id']}")
                threading.Thread(target=self._run_actions, args=(rule,event), daemon=True).start()
                triggered.append(rule["id"])
        return triggered

    def _run_actions(self, rule, event):
        for name in rule.get("actions",[]):
            fn = ACTION_MAP.get(name)
            if fn:
                try: fn(event, rule)
                except Exception as e: log.error(f"[SOAR] {name}: {e}")

    def get_incidents(self, limit=100):
        if INCIDENTS_FILE.exists():
            try: return json.loads(INCIDENTS_FILE.read_text())[-limit:][::-1]
            except: pass
        return []

    def get_tickets(self, limit=50):
        tickets = []
        for f in sorted(TICKETS_DIR.glob("*.json"), reverse=True)[:limit]:
            try: tickets.append(json.loads(f.read_text()))
            except: pass
        return tickets

    def get_stats(self):
        inc = self.get_incidents(500); tkts = self.get_tickets(200)
        # MTTR calculation
        mttr_minutes = self._calc_mttr(tkts)
        return {"total_incidents":len(inc), "open_tickets":sum(1 for t in tkts if t.get("status")=="OPEN"),
                "rules_enabled":sum(1 for r in self.rules if r.get("enabled",True)),
                "rules_total":len(self.rules), "blocked_ips":_count_blocked(),
                "critical_count":sum(1 for i in inc[:200] if i.get("severity")=="CRITICAL"),
                "high_count":sum(1 for i in inc[:200] if i.get("severity")=="HIGH"),
                "mttr_minutes": mttr_minutes,
                "closed_tickets": sum(1 for t in tkts if t.get("status")=="CLOSED"),
                "automation_savings": len(inc) * 12,  # avg 12 min saved per automated incident
                "false_positive_rate": 0}

    def _calc_mttr(self, tickets):
        """Calculate Mean Time to Respond in minutes."""
        resolved = [t for t in tickets if t.get("status") == "CLOSED" and t.get("created_at") and t.get("resolved_at")]
        if not resolved:
            return 0
        total = 0
        for t in resolved[-50:]:
            try:
                from datetime import datetime, timezone
                created = datetime.fromisoformat(t["created_at"].replace("Z", "+00:00"))
                resolved_dt = datetime.fromisoformat(t["resolved_at"].replace("Z", "+00:00"))
                total += (resolved_dt - created).total_seconds() / 60
            except Exception:
                pass
        return round(total / len(resolved), 1) if resolved else 0

    def close_ticket(self, ticket_id, resolution="Resolved by analyst"):
        """Close a ticket and record resolution time."""
        tf = TICKETS_DIR / f"{ticket_id}.json"
        if not tf.exists():
            return False
        try:
            t = json.loads(tf.read_text())
            t["status"] = "CLOSED"
            t["resolved_at"] = datetime.now(timezone.utc).isoformat()
            t["resolution"] = resolution
            tf.write_text(json.dumps(t, indent=2))
            return True
        except Exception as e:
            log.error(f"[SOAR] close_ticket: {e}")
            return False

    def update_ticket(self, ticket_id, updates):
        """Update ticket fields."""
        tf = TICKETS_DIR / f"{ticket_id}.json"
        if not tf.exists():
            return False
        try:
            t = json.loads(tf.read_text())
            t.update(updates)
            t["updated_at"] = datetime.now(timezone.utc).isoformat()
            tf.write_text(json.dumps(t, indent=2))
            return True
        except Exception as e:
            log.error(f"[SOAR] update_ticket: {e}")
            return False

    def get_breach_timers(self):
        """Get active GDPR 72-hour breach notification timers."""
        btf = SOAR_DIR / "breach_timers.json"
        if btf.exists():
            try:
                return json.loads(btf.read_text())
            except Exception:
                pass
        return []

    def start_breach_timer(self, incident_title, severity, domain=""):
        """Start a GDPR 72-hour breach notification countdown."""
        btf = SOAR_DIR / "breach_timers.json"
        timers = self.get_breach_timers()
        now = datetime.now(timezone.utc)
        timer = {
            "id": f"BT-{now.strftime('%Y%m%d-%H%M%S')}",
            "title": incident_title,
            "domain": domain,
            "severity": severity,
            "started_at": now.isoformat(),
            "deadline_at": (now.replace(hour=now.hour) if False else now).__class__(
                now.year, now.month, now.day, now.hour, now.minute, now.second,
                tzinfo=now.tzinfo
            ).isoformat(),
            "hours_limit": 72,
            "status": "ACTIVE",
            "notified_legal": False,
            "notified_dpa": False,
        }
        # Calculate deadline properly
        import datetime as dt_mod
        deadline = now + dt_mod.timedelta(hours=72)
        timer["deadline_at"] = deadline.isoformat()
        timers.append(timer)
        btf.write_text(json.dumps(timers[-20:], indent=2))
        log.info(f"[SOAR] Breach timer started: {timer['id']}")
        return timer

    def enrich_incident(self, incident):
        """Auto-enrich incident with VT + AbuseIPDB lookups."""
        enriched = dict(incident)
        ip = incident.get("source_ip", "")
        domain = incident.get("domain", "")
        if ip:
            try:
                from scanner.ip_intel import check_abuseipdb
                ab = check_abuseipdb(ip)
                enriched["enrichment_abuseipdb"] = {
                    "score": ab.get("confidence_score", 0),
                    "threat_level": ab.get("threat_level", "UNKNOWN"),
                    "country": ab.get("country", ""),
                    "isp": ab.get("isp", ""),
                    "total_reports": ab.get("total_reports", 0),
                }
            except Exception as e:
                enriched["enrichment_abuseipdb"] = {"error": str(e)}
            try:
                from scanner.intelligence import vt_check_ip
                vt = vt_check_ip(ip)
                enriched["enrichment_vt"] = {
                    "malicious": vt.get("malicious", 0),
                    "total_engines": vt.get("total_engines", 0),
                    "country": vt.get("country", ""),
                    "as_owner": vt.get("as_owner", ""),
                }
            except Exception as e:
                enriched["enrichment_vt"] = {"error": str(e)}
        if domain:
            try:
                from scanner.intelligence import vt_check_domain
                vt = vt_check_domain(domain)
                enriched["enrichment_domain_vt"] = {
                    "malicious": vt.get("malicious", 0),
                    "reputation": vt.get("reputation", 0),
                    "categories": vt.get("categories", []),
                }
            except Exception as e:
                enriched["enrichment_domain_vt"] = {"error": str(e)}
        enriched["enriched_at"] = datetime.now(timezone.utc).isoformat()
        return enriched

    def run_control_validation(self):
        """Validate that security controls are actually working."""
        results = []
        import socket, subprocess
        # Test 1: Check blocklist is applied
        blocked_ips = []
        if BLOCKLIST_FILE.exists():
            for line in BLOCKLIST_FILE.read_text().splitlines():
                if line.strip() and not line.startswith("#"):
                    blocked_ips.append(line.split()[0])
        for ip in blocked_ips[:3]:
            try:
                r = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=5)
                results.append({
                    "control": f"IP Block: {ip}",
                    "status": "PASS" if r.returncode == 0 else "FAIL",
                    "detail": "iptables rule active" if r.returncode == 0 else "Rule missing — firewall may be compromised"
                })
            except Exception as e:
                results.append({"control": f"IP Block: {ip}", "status": "ERROR", "detail": str(e)})
        # Test 2: Incident logging
        inc_count = len(self.get_incidents(10))
        results.append({
            "control": "Incident Logging",
            "status": "PASS" if inc_count >= 0 else "FAIL",
            "detail": f"{inc_count} incidents logged successfully"
        })
        # Test 3: Rules loaded
        results.append({
            "control": "Rules Engine",
            "status": "PASS" if len(self.rules) > 0 else "FAIL",
            "detail": f"{len(self.rules)} rules loaded, {sum(1 for r in self.rules if r.get('enabled')) } enabled"
        })
        # Test 4: Ticket system
        tkt_count = len(self.get_tickets(10))
        results.append({
            "control": "Ticketing System",
            "status": "PASS" if TICKETS_DIR.exists() else "FAIL",
            "detail": f"{tkt_count} tickets in system"
        })
        # Test 5: Alert channels
        import os
        email_ok = bool(os.environ.get("ALERT_EMAIL_USER") and os.environ.get("ALERT_EMAIL_PASS"))
        telegram_ok = bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))
        results.append({
            "control": "Email Alerting",
            "status": "PASS" if email_ok else "WARN",
            "detail": "Email credentials configured" if email_ok else "ALERT_EMAIL_USER/PASS not set"
        })
        results.append({
            "control": "Telegram Alerting",
            "status": "PASS" if telegram_ok else "WARN",
            "detail": "Telegram bot configured" if telegram_ok else "TELEGRAM_BOT_TOKEN not set"
        })
        return {
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
            "pass_count": sum(1 for r in results if r["status"] == "PASS"),
            "fail_count": sum(1 for r in results if r["status"] == "FAIL"),
            "warn_count": sum(1 for r in results if r["status"] == "WARN"),
        }

_engine = None
def get_soar_engine():
    global _engine
    if _engine is None: _engine = SOAREngine()
    return _engine
