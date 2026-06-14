"""
VoraGuard Continuous Monitoring Engine
Background daemon that monitors targets and fires alerts via CLI, email, Slack.

Architecture:
  - SQLite DB: targets, baselines, alerts, scan history
  - Daemon: runs in background, survives terminal close
  - Checks: ports, DNS, SSL, typosquats, VT, AbuseIPDB, OTX, LeakIX
  - Alerts: CLI table, email (SMTP), Slack webhook
"""

import os
import sys
import json
import time
import signal
import sqlite3
import smtplib
import hashlib
import logging
import requests
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, asdict
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
VORAG_HOME   = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
MONITOR_DIR  = VORAG_HOME / "monitor"
DB_PATH      = MONITOR_DIR / "monitor.db"
PID_FILE     = MONITOR_DIR / "monitor.pid"
LOG_FILE     = MONITOR_DIR / "monitor.log"
CONFIG_FILE  = MONITOR_DIR / "config.json"

MONITOR_DIR.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(VORAG_HOME))

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("vorag.monitor")

# ── Colors ────────────────────────────────────────────────────────────────────
R  = "\033[0m"; B  = "\033[1m"; D  = "\033[2m"
CY = "\033[36m"; GR = "\033[32m"; YE = "\033[33m"
RE = "\033[31m"; RD = "\033[91m"; MA = "\033[35m"

# ── Check intervals (seconds) ─────────────────────────────────────────────────
CHECK_INTERVALS = {
    "ports":      1800,   # 30 min
    "dns":        3600,   # 1 hr
    "ssl":        21600,  # 6 hrs
    "typosquats": 21600,  # 6 hrs
    "vt":         21600,  # 6 hrs
    "abuseipdb":  3600,   # 1 hr
    "otx":        43200,  # 12 hrs
    "leakix":     21600,  # 6 hrs
}

# ── Default config ─────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "interval_seconds": 3600,
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addr": "",
    },
    "slack": {
        "enabled": False,
        "webhook_url": "",
    },
    "checks": {
        "ports": True,
        "dns": True,
        "ssl": True,
        "typosquats": True,
        "vt": True,
        "abuseipdb": True,
        "otx": True,
        "leakix": True,
    },
    "alert_levels": ["CRITICAL", "WARNING", "INFO"],
}


# ── Config helpers ─────────────────────────────────────────────────────────────
def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            # Merge with defaults for any missing keys
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
                elif isinstance(v, dict):
                    for kk, vv in v.items():
                        if kk not in cfg[k]:
                            cfg[k][kk] = vv
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT UNIQUE NOT NULL,
            added_at    TEXT NOT NULL,
            active      INTEGER DEFAULT 1,
            interval_s  INTEGER DEFAULT 3600,
            last_scan   TEXT,
            next_scan   TEXT,
            scan_count  INTEGER DEFAULT 0,
            alert_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            check_type  TEXT NOT NULL,
            value_hash  TEXT NOT NULL,
            value_json  TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(domain, check_type)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            check_type  TEXT NOT NULL,
            level       TEXT NOT NULL,
            title       TEXT NOT NULL,
            detail      TEXT,
            old_value   TEXT,
            new_value   TEXT,
            fired_at    TEXT NOT NULL,
            ack         INTEGER DEFAULT 0,
            ack_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            checks_run  TEXT,
            alerts_fired INTEGER DEFAULT 0,
            error       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_domain  ON alerts(domain);
        CREATE INDEX IF NOT EXISTS idx_alerts_ack     ON alerts(ack);
        CREATE INDEX IF NOT EXISTS idx_alerts_level   ON alerts(level);
        CREATE INDEX IF NOT EXISTS idx_history_domain ON scan_history(domain);
        """)
    log.info(f"Database initialised at {DB_PATH}")


# ── Target management ─────────────────────────────────────────────────────────
def add_target(domain: str, interval_s: int = 3600) -> bool:
    domain = domain.lower().strip()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO targets (domain, added_at, interval_s, next_scan) VALUES (?,?,?,?)",
                (domain, datetime.now().isoformat(), interval_s, datetime.now().isoformat())
            )
            conn.execute(
                "UPDATE targets SET active=1, interval_s=? WHERE domain=?",
                (interval_s, domain)
            )
        return True
    except Exception as e:
        log.error(f"add_target error: {e}")
        return False


def remove_target(domain: str) -> bool:
    domain = domain.lower().strip()
    with get_db() as conn:
        conn.execute("UPDATE targets SET active=0 WHERE domain=?", (domain,))
    return True


def list_targets() -> list:
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM targets WHERE active=1 ORDER BY added_at"
        ).fetchall()]


def get_alerts(domain: str = None, level: str = None,
               unacked_only: bool = False, limit: int = 50) -> list:
    with get_db() as conn:
        q = "SELECT * FROM alerts WHERE 1=1"
        p = []
        if domain:
            q += " AND domain=?"; p.append(domain)
        if level:
            q += " AND level=?"; p.append(level)
        if unacked_only:
            q += " AND ack=0"
        q += " ORDER BY fired_at DESC LIMIT ?"
        p.append(limit)
        return [dict(r) for r in conn.execute(q, p).fetchall()]


def ack_alert(alert_id: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE alerts SET ack=1, ack_at=? WHERE id=?",
            (datetime.now().isoformat(), alert_id)
        )


def ack_all_alerts(domain: str = None):
    with get_db() as conn:
        if domain:
            conn.execute(
                "UPDATE alerts SET ack=1, ack_at=? WHERE domain=? AND ack=0",
                (datetime.now().isoformat(), domain)
            )
        else:
            conn.execute(
                "UPDATE alerts SET ack=1, ack_at=? WHERE ack=0",
                (datetime.now().isoformat(),)
            )


# ── Baseline helpers ──────────────────────────────────────────────────────────
def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()[:16]


def get_baseline(domain: str, check_type: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM baselines WHERE domain=? AND check_type=?",
            (domain, check_type)
        ).fetchone()
        if row:
            return {"hash": row["value_hash"], "value": json.loads(row["value_json"])}
    return None


def set_baseline(domain: str, check_type: str, value):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO baselines (domain, check_type, value_hash, value_json, recorded_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(domain, check_type) DO UPDATE SET
                 value_hash=excluded.value_hash,
                 value_json=excluded.value_json,
                 recorded_at=excluded.recorded_at""",
            (domain, check_type, _hash(value), json.dumps(value), datetime.now().isoformat())
        )


# ── Alert filing ──────────────────────────────────────────────────────────────
def fire_alert(domain: str, check_type: str, level: str,
               title: str, detail: str = "",
               old_value=None, new_value=None) -> int:
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO alerts
               (domain, check_type, level, title, detail, old_value, new_value, fired_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (domain, check_type, level, title, detail,
             json.dumps(old_value) if old_value is not None else None,
             json.dumps(new_value) if new_value is not None else None,
             datetime.now().isoformat())
        )
        conn.execute(
            "UPDATE targets SET alert_count = alert_count+1 WHERE domain=?", (domain,)
        )
        return cur.lastrowid


# ── Individual checks ─────────────────────────────────────────────────────────
def _load_env():
    env_file = VORAG_HOME / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.split("#")[0].strip()
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k and v:
                    os.environ.setdefault(k, v)


def check_ports(domain: str) -> list:
    """Run nmap, compare to baseline, return alerts."""
    alerts = []
    try:
        from scanner.core import run_nmap
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = run_nmap(domain, Path(tmp))
            ports = sorted([
                {"port": p["port"], "protocol": p.get("protocol", "tcp"),
                 "service": p.get("service", ""), "version": p.get("version", "")}
                for p in result.open_ports
            ], key=lambda x: x["port"])

        baseline = get_baseline(domain, "ports")
        if baseline is None:
            set_baseline(domain, "ports", ports)
            log.info(f"[{domain}] Ports baseline set: {len(ports)} ports")
        else:
            old_ports = {p["port"] for p in baseline["value"]}
            new_ports = {p["port"] for p in ports}
            opened = new_ports - old_ports
            closed = old_ports - new_ports

            if opened:
                new_details = [p for p in ports if p["port"] in opened]
                alert_id = fire_alert(
                    domain, "ports", "CRITICAL",
                    f"🔴 New port(s) opened: {', '.join(str(p) for p in sorted(opened))}",
                    f"Previously unseen ports now open: {json.dumps(new_details, indent=2)}",
                    old_value=list(old_ports), new_value=list(new_ports)
                )
                alerts.append(alert_id)
                log.warning(f"[{domain}] CRITICAL: New ports opened: {opened}")

            if closed:
                fire_alert(
                    domain, "ports", "INFO",
                    f"ℹ Port(s) closed: {', '.join(str(p) for p in sorted(closed))}",
                    f"Ports no longer open: {closed}",
                    old_value=list(old_ports), new_value=list(new_ports)
                )

            if opened or closed:
                set_baseline(domain, "ports", ports)

    except Exception as e:
        log.error(f"[{domain}] Port check error: {e}")
    return alerts


def check_dns(domain: str) -> list:
    """Check DNS records for changes."""
    alerts = []
    try:
        from scanner.intelligence import check_dns_health
        dns = check_dns_health(domain)

        summary = {
            "ips":   sorted(dns.get("ip_addresses", [])),
            "mx":    sorted(dns.get("mx", {}).get("records", [])),
            "spf":   dns.get("spf", {}).get("record", ""),
            "dmarc": dns.get("dmarc", {}).get("record", ""),
        }

        baseline = get_baseline(domain, "dns")
        if baseline is None:
            set_baseline(domain, "dns", summary)
            log.info(f"[{domain}] DNS baseline set")
        else:
            old = baseline["value"]
            if summary["ips"] != old.get("ips", []):
                fire_alert(
                    domain, "dns", "CRITICAL",
                    f"🔴 DNS A record changed — possible hijack",
                    f"Old IPs: {old['ips']} → New IPs: {summary['ips']}",
                    old_value=old["ips"], new_value=summary["ips"]
                )
                alerts.append("dns_ip")

            if summary["mx"] != old.get("mx", []):
                fire_alert(
                    domain, "dns", "WARNING",
                    f"🟡 MX record changed",
                    f"Old: {old['mx']} → New: {summary['mx']}",
                    old_value=old["mx"], new_value=summary["mx"]
                )
                alerts.append("dns_mx")

            if summary["spf"] != old.get("spf", ""):
                fire_alert(
                    domain, "dns", "WARNING",
                    f"🟡 SPF record changed",
                    f"Old: {old['spf']}\nNew: {summary['spf']}"
                )
                alerts.append("dns_spf")

            if summary != old:
                set_baseline(domain, "dns", summary)

    except Exception as e:
        log.error(f"[{domain}] DNS check error: {e}")
    return alerts


def check_ssl(domain: str) -> list:
    """Check SSL certificate validity and expiry."""
    alerts = []
    try:
        from scanner.intelligence import check_ssl as _check_ssl
        ssl = _check_ssl(domain)

        if not ssl.get("valid"):
            baseline = get_baseline(domain, "ssl_valid")
            if baseline is None or baseline["value"] is True:
                fire_alert(
                    domain, "ssl", "CRITICAL",
                    f"🔴 SSL certificate invalid or missing",
                    str(ssl.get("issues", ["Unknown SSL error"]))
                )
                alerts.append("ssl_invalid")
            set_baseline(domain, "ssl_valid", False)
        else:
            set_baseline(domain, "ssl_valid", True)
            days = ssl.get("expires_in_days", 999)
            if isinstance(days, (int, float)):
                if days < 7:
                    fire_alert(
                        domain, "ssl", "CRITICAL",
                        f"🔴 SSL certificate expires in {days} days — URGENT",
                        f"Issuer: {ssl.get('issuer','')} | Expiry: {ssl.get('expires','')}"
                    )
                    alerts.append("ssl_expiry_critical")
                elif days < 30:
                    fire_alert(
                        domain, "ssl", "WARNING",
                        f"🟡 SSL certificate expires in {days} days",
                        f"Issuer: {ssl.get('issuer','')} | Expiry: {ssl.get('expires','')}"
                    )
                    alerts.append("ssl_expiry_warning")

    except Exception as e:
        log.error(f"[{domain}] SSL check error: {e}")
    return alerts


def check_typosquats(domain: str) -> list:
    """Check for newly registered typosquat domains."""
    alerts = []
    try:
        from scanner.core import run_dnstwist
        result = run_dnstwist(domain)
        current = sorted(set(
            t.get("domain", "") for t in result.typosquats
            if t.get("dns_a") or t.get("dns_aaaa")
        ))

        baseline = get_baseline(domain, "typosquats")
        if baseline is None:
            set_baseline(domain, "typosquats", current)
            log.info(f"[{domain}] Typosquat baseline: {len(current)} registered")
        else:
            old_set = set(baseline["value"])
            new_set = set(current)
            newly_registered = new_set - old_set

            if newly_registered:
                fire_alert(
                    domain, "typosquats", "WARNING",
                    f"🟡 {len(newly_registered)} new typosquat domain(s) registered",
                    f"New domains: {', '.join(sorted(newly_registered))}",
                    old_value=list(old_set), new_value=list(new_set)
                )
                alerts.append("typosquat_new")
                set_baseline(domain, "typosquats", current)

    except Exception as e:
        log.error(f"[{domain}] Typosquat check error: {e}")
    return alerts


def check_vt(domain: str) -> list:
    """Check VirusTotal reputation for changes."""
    alerts = []
    try:
        from scanner.intelligence import vt_check_domain
        vt = vt_check_domain(domain)

        if not vt.get("available"):
            return alerts

        summary = {
            "malicious":  vt.get("malicious", 0),
            "suspicious": vt.get("suspicious", 0),
            "risk_level": vt.get("risk_level", "CLEAN"),
        }

        baseline = get_baseline(domain, "vt")
        if baseline is None:
            set_baseline(domain, "vt", summary)
        else:
            old = baseline["value"]
            if summary["malicious"] > old.get("malicious", 0):
                fire_alert(
                    domain, "vt", "CRITICAL",
                    f"🔴 VirusTotal: {summary['malicious']} engines now flagging domain as malicious",
                    f"Previous: {old['malicious']} | Now: {summary['malicious']}",
                    old_value=old, new_value=summary
                )
                alerts.append("vt_malicious")
                set_baseline(domain, "vt", summary)
            elif summary["suspicious"] > old.get("suspicious", 0) + 2:
                fire_alert(
                    domain, "vt", "WARNING",
                    f"🟡 VirusTotal: suspicious engines increased to {summary['suspicious']}",
                    f"Previous: {old['suspicious']} | Now: {summary['suspicious']}"
                )
                alerts.append("vt_suspicious")
                set_baseline(domain, "vt", summary)

    except Exception as e:
        log.error(f"[{domain}] VT check error: {e}")
    return alerts


def check_abuseipdb(domain: str) -> list:
    """Check AbuseIPDB for new abuse reports against domain IPs."""
    alerts = []
    try:
        import socket
        ips = []
        try:
            ips = [socket.gethostbyname(domain)]
        except Exception:
            return alerts

        api_key = os.environ.get("ABUSEIPDB_API_KEY", "").split("#")[0].strip()
        if not api_key:
            return alerts

        for ip in ips:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 7},
                timeout=10
            )
            if resp.status_code != 200:
                continue

            d = resp.json().get("data", {})
            current = {
                "confidence": d.get("abuseConfidenceScore", 0),
                "reports":    d.get("totalReports", 0),
            }

            baseline = get_baseline(domain, f"abuseipdb_{ip}")
            if baseline is None:
                set_baseline(domain, f"abuseipdb_{ip}", current)
            else:
                old = baseline["value"]
                if current["reports"] > old.get("reports", 0):
                    diff = current["reports"] - old.get("reports", 0)
                    level = "CRITICAL" if current["confidence"] > 50 else "WARNING"
                    fire_alert(
                        domain, "abuseipdb", level,
                        f"{'🔴' if level=='CRITICAL' else '🟡'} AbuseIPDB: {diff} new abuse report(s) for {ip}",
                        f"Confidence: {current['confidence']}% | Total reports: {current['reports']}",
                        old_value=old, new_value=current
                    )
                    alerts.append("abuseipdb_new_report")
                    set_baseline(domain, f"abuseipdb_{ip}", current)

    except Exception as e:
        log.error(f"[{domain}] AbuseIPDB check error: {e}")
    return alerts


def check_otx(domain: str) -> list:
    """Check AlienVault OTX for new threat pulses."""
    alerts = []
    try:
        api_key = os.environ.get("OTX_API_KEY", "").split("#")[0].strip()
        if not api_key:
            return alerts

        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=10
        )
        if resp.status_code != 200:
            return alerts

        d = resp.json()
        current = {
            "pulse_count":    d.get("pulse_info", {}).get("count", 0),
            "malware_count":  len(d.get("pulse_info", {}).get("pulses", [])),
        }

        baseline = get_baseline(domain, "otx")
        if baseline is None:
            set_baseline(domain, "otx", current)
        else:
            old = baseline["value"]
            if current["pulse_count"] > old.get("pulse_count", 0):
                new_pulses = current["pulse_count"] - old.get("pulse_count", 0)
                fire_alert(
                    domain, "otx", "CRITICAL",
                    f"🔴 OTX: {new_pulses} new threat pulse(s) — domain added to threat feed",
                    f"Total pulses: {current['pulse_count']} (was {old['pulse_count']})",
                    old_value=old, new_value=current
                )
                alerts.append("otx_new_pulse")
                set_baseline(domain, "otx", current)

    except Exception as e:
        log.error(f"[{domain}] OTX check error: {e}")
    return alerts


def check_leakix(domain: str) -> list:
    """Check LeakIX for new exposed services or data leaks."""
    alerts = []
    try:
        api_key = os.environ.get("LEAKIX_API_KEY", "").split("#")[0].strip()
        if not api_key:
            return alerts

        resp = requests.get(
            "https://leakix.net/search",
            headers={"api-key": api_key, "Accept": "application/json"},
            params={"scope": "leak", "q": f"host:{domain}"},
            timeout=10
        )
        if resp.status_code not in (200, 206):
            return alerts

        data = resp.json() or []
        current_count = len(data) if isinstance(data, list) else 0

        baseline = get_baseline(domain, "leakix")
        if baseline is None:
            set_baseline(domain, "leakix", {"count": current_count})
        else:
            old_count = baseline["value"].get("count", 0)
            if current_count > old_count:
                fire_alert(
                    domain, "leakix", "CRITICAL",
                    f"🔴 LeakIX: {current_count - old_count} new exposed service(s) detected",
                    f"Total exposed services: {current_count} (was {old_count})"
                )
                alerts.append("leakix_new_leak")
                set_baseline(domain, "leakix", {"count": current_count})

    except Exception as e:
        log.error(f"[{domain}] LeakIX check error: {e}")
    return alerts


# ── Alert delivery ─────────────────────────────────────────────────────────────
def send_email_alert(alert: dict, cfg: dict):
    """Send alert via SMTP email."""
    ecfg = cfg.get("email", {})
    if not ecfg.get("enabled") or not ecfg.get("to_addr"):
        return
    try:
        level_emoji = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(alert["level"], "")
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[VoraGuard] {level_emoji} {alert['level']}: {alert['title']}"
        msg["From"]    = ecfg.get("from_addr", ecfg.get("username", ""))
        msg["To"]      = ecfg["to_addr"]

        text_body = f"""
VoraGuard Continuous Monitoring Alert
=====================================
Level:   {alert['level']}
Domain:  {alert['domain']}
Check:   {alert['check_type']}
Time:    {alert['fired_at']}

{alert['title']}

{alert.get('detail', '')}

Old Value: {alert.get('old_value', 'N/A')}
New Value: {alert.get('new_value', 'N/A')}

-- VoraGuard v3.0 Continuous Monitoring
"""
        html_body = f"""
<html><body style="font-family:monospace;background:#0a0f1e;color:#e2e8f0;padding:24px">
<h2 style="color:{'#ef4444' if alert['level']=='CRITICAL' else '#f59e0b' if alert['level']=='WARNING' else '#22c55e'}">
  {level_emoji} VoraGuard Alert: {alert['level']}
</h2>
<table style="border-collapse:collapse;width:100%">
  <tr><td style="padding:8px;color:#94a3b8">Domain</td><td style="padding:8px;color:#e2e8f0"><b>{alert['domain']}</b></td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Check</td><td style="padding:8px;color:#e2e8f0">{alert['check_type']}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Time</td><td style="padding:8px;color:#e2e8f0">{alert['fired_at']}</td></tr>
</table>
<h3 style="color:#e2e8f0">{alert['title']}</h3>
<p style="color:#94a3b8">{alert.get('detail','')}</p>
<hr style="border-color:#1e293b">
<p style="color:#475569;font-size:12px">VoraGuard v3.0 Continuous Monitoring</p>
</body></html>
"""
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(ecfg["smtp_host"], ecfg["smtp_port"]) as server:
            server.starttls()
            server.login(ecfg["username"], ecfg["password"])
            server.sendmail(msg["From"], msg["To"], msg.as_string())

        log.info(f"Email alert sent to {ecfg['to_addr']}: {alert['title']}")
    except Exception as e:
        log.error(f"Email send failed: {e}")


def send_slack_alert(alert: dict, cfg: dict):
    """Send alert via Slack webhook."""
    scfg = cfg.get("slack", {})
    if not scfg.get("enabled") or not scfg.get("webhook_url"):
        return
    try:
        color = {"CRITICAL": "#ef4444", "WARNING": "#f59e0b", "INFO": "#22c55e"}.get(alert["level"], "#64748b")
        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"VoraGuard Alert: {alert['level']}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Domain:*\n{alert['domain']}"},
                            {"type": "mrkdwn", "text": f"*Check:*\n{alert['check_type']}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{alert['fired_at'][:19]}"},
                            {"type": "mrkdwn", "text": f"*Level:*\n{alert['level']}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*{alert['title']}*\n{alert.get('detail','')[:300]}"}
                    }
                ]
            }]
        }
        requests.post(scfg["webhook_url"], json=payload, timeout=10)
        log.info(f"Slack alert sent: {alert['title']}")
    except Exception as e:
        log.error(f"Slack send failed: {e}")


def deliver_alerts(alert_ids: list, cfg: dict):
    """Deliver all new alerts via configured channels."""
    if not alert_ids:
        return
    with get_db() as conn:
        for aid in alert_ids:
            if not isinstance(aid, int):
                continue
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
            if row:
                alert = dict(row)
                level = alert.get("level", "INFO")
                allowed = cfg.get("alert_levels", ["CRITICAL", "WARNING", "INFO"])
                if level not in allowed:
                    continue
                send_email_alert(alert, cfg)
                send_slack_alert(alert, cfg)


# ── Monitor cycle ─────────────────────────────────────────────────────────────
def run_checks_for_target(domain: str, cfg: dict) -> int:
    """Run all enabled checks for a single target. Returns alert count."""
    _load_env()
    checks_cfg = cfg.get("checks", {})
    all_alert_ids = []
    history_id = None

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scan_history (domain, started_at) VALUES (?,?)",
            (domain, datetime.now().isoformat())
        )
        history_id = cur.lastrowid

    try:
        log.info(f"[{domain}] Starting monitoring cycle...")

        if checks_cfg.get("ports", True):
            log.info(f"[{domain}] Checking ports...")
            all_alert_ids += check_ports(domain)

        if checks_cfg.get("dns", True):
            log.info(f"[{domain}] Checking DNS...")
            all_alert_ids += check_dns(domain)

        if checks_cfg.get("ssl", True):
            log.info(f"[{domain}] Checking SSL...")
            all_alert_ids += check_ssl(domain)

        if checks_cfg.get("typosquats", True):
            log.info(f"[{domain}] Checking typosquats...")
            all_alert_ids += check_typosquats(domain)

        if checks_cfg.get("vt", True):
            log.info(f"[{domain}] Checking VirusTotal...")
            all_alert_ids += check_vt(domain)

        if checks_cfg.get("abuseipdb", True):
            log.info(f"[{domain}] Checking AbuseIPDB...")
            all_alert_ids += check_abuseipdb(domain)

        if checks_cfg.get("otx", True):
            log.info(f"[{domain}] Checking OTX...")
            all_alert_ids += check_otx(domain)

        if checks_cfg.get("leakix", True):
            log.info(f"[{domain}] Checking LeakIX...")
            all_alert_ids += check_leakix(domain)

        deliver_alerts([a for a in all_alert_ids if isinstance(a, int)], cfg)

        now = datetime.now().isoformat()
        interval = cfg.get("interval_seconds", 3600)
        next_scan = (datetime.now() + timedelta(seconds=interval)).isoformat()

        with get_db() as conn:
            conn.execute(
                """UPDATE targets SET last_scan=?, next_scan=?, scan_count=scan_count+1
                   WHERE domain=?""",
                (now, next_scan, domain)
            )
            conn.execute(
                "UPDATE scan_history SET finished_at=?, alerts_fired=? WHERE id=?",
                (now, len(all_alert_ids), history_id)
            )

        log.info(f"[{domain}] Cycle complete — {len(all_alert_ids)} alerts fired")

    except Exception as e:
        log.error(f"[{domain}] Monitor cycle error: {e}")
        if history_id:
            with get_db() as conn:
                conn.execute(
                    "UPDATE scan_history SET error=?, finished_at=? WHERE id=?",
                    (str(e), datetime.now().isoformat(), history_id)
                )

    return len(all_alert_ids)


# ── Daemon ────────────────────────────────────────────────────────────────────
class MonitorDaemon:
    def __init__(self):
        self.running = False
        self._threads = {}

    def start(self):
        if self.is_running():
            print(f"  {YE}⚠{R}  Daemon already running (PID {PID_FILE.read_text().strip()})")
            return False

        pid = os.fork()
        if pid > 0:
            # Parent — write PID and return
            PID_FILE.write_text(str(pid))
            print(f"  {GR}✓{R}  Monitor daemon started (PID {pid})")
            print(f"  {D}Logs: {LOG_FILE}{R}")
            return True

        # Child process — become daemon
        os.setsid()
        sys.stdin  = open(os.devnull, "r")
        sys.stdout = open(LOG_FILE, "a")
        sys.stderr = open(LOG_FILE, "a")

        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT,  self._handle_stop)

        self.running = True
        PID_FILE.write_text(str(os.getpid()))
        log.info(f"Monitor daemon started (PID {os.getpid()})")

        self._run_loop()
        sys.exit(0)

    def _handle_stop(self, signum, frame):
        log.info("Monitor daemon stopping...")
        self.running = False
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    def _run_loop(self):
        """Main daemon loop — checks targets on schedule."""
        _load_env()
        while self.running:
            try:
                cfg     = load_config()
                now     = datetime.now()
                targets = list_targets()

                for t in targets:
                    next_scan = t.get("next_scan")
                    if not next_scan:
                        continue
                    try:
                        ns = datetime.fromisoformat(next_scan)
                    except Exception:
                        ns = now

                    if now >= ns:
                        domain = t["domain"]
                        thread = threading.Thread(
                            target=run_checks_for_target,
                            args=(domain, cfg),
                            daemon=True,
                            name=f"monitor-{domain}"
                        )
                        thread.start()

                time.sleep(60)  # Check schedule every 60s

            except Exception as e:
                log.error(f"Daemon loop error: {e}")
                time.sleep(60)

    def stop(self):
        if not self.is_running():
            print(f"  {D}Daemon is not running{R}")
            return False
        pid = int(PID_FILE.read_text().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            PID_FILE.unlink(missing_ok=True)
            print(f"  {GR}✓{R}  Monitor daemon stopped (PID {pid})")
            return True
        except ProcessLookupError:
            PID_FILE.unlink(missing_ok=True)
            print(f"  {YE}⚠{R}  Process {pid} not found — cleaned up PID file")
            return True
        except Exception as e:
            print(f"  {RE}✗{R}  Stop failed: {e}")
            return False

    def is_running(self) -> bool:
        if not PID_FILE.exists():
            return False
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)  # Signal 0 = check if process exists
            return True
        except (ProcessLookupError, ValueError):
            PID_FILE.unlink(missing_ok=True)
            return False

    def restart(self):
        self.stop()
        time.sleep(1)
        self.start()


# ── CLI display helpers ────────────────────────────────────────────────────────
def print_monitor_status():
    """Print status of all monitored targets."""
    daemon = MonitorDaemon()
    running = daemon.is_running()
    pid = PID_FILE.read_text().strip() if PID_FILE.exists() else "—"

    print(f"\n  {B}Daemon:{R}  {GR+'● Running'+R if running else RE+'○ Stopped'+R}  {D}(PID {pid}){R}")
    print(f"  {B}DB:{R}     {DB_PATH}")
    print(f"  {B}Logs:{R}   {LOG_FILE}\n")

    targets = list_targets()
    if not targets:
        print(f"  {D}No targets monitored. Add one: vorag monitor add example.com{R}\n")
        return

    print(f"  {B}{'Domain':<30} {'Last Scan':<20} {'Next Scan':<20} {'Scans':>6} {'Alerts':>7}{R}")
    print(f"  {'─'*85}")

    for t in targets:
        last = (t.get("last_scan") or "never")[:19]
        next_ = (t.get("next_scan") or "—")[:19]

        # Highlight if overdue
        overdue = ""
        if t.get("next_scan"):
            try:
                if datetime.fromisoformat(t["next_scan"]) < datetime.now():
                    overdue = f" {YE}(overdue){R}"
            except Exception:
                pass

        ac = t.get("alert_count", 0)
        alert_c = RE if ac > 0 else GR
        print(f"  {CY}{t['domain']:<30}{R} {D}{last:<20}{R} {D}{next_:<20}{R}{overdue} "
              f"{t.get('scan_count',0):>6} {alert_c}{ac:>7}{R}")
    print()


def print_alerts_table(alerts: list, title: str = "Alerts"):
    """Print alerts as a formatted table."""
    if not alerts:
        print(f"\n  {GR}✓{R}  No alerts found.\n")
        return

    unacked = [a for a in alerts if not a.get("ack")]
    print(f"\n  {B}{title}{R}  {D}({len(alerts)} total, {len(unacked)} unacknowledged){R}\n")
    print(f"  {B}{'ID':>4} {'Level':<10} {'Domain':<28} {'Check':<14} {'Time':<19} {'Title'}{R}")
    print(f"  {'─'*100}")

    for a in alerts:
        level = a.get("level", "INFO")
        lc = RE if level=="CRITICAL" else YE if level=="WARNING" else GR
        ack_mark = D + "✓" + R if a.get("ack") else " "
        print(f"  {D}{a['id']:>4}{R} {lc}{level:<10}{R} {CY}{a['domain']:<28}{R} "
              f"{D}{a['check_type']:<14}{R} {D}{a['fired_at'][:19]:<19}{R} "
              f"{ack_mark} {a['title'][:50]}")
    print()
