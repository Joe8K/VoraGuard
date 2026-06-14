"""
VoraGuard Alert Manager
Multi-channel alerts: Email, Telegram, Slack, SMS (Fast2SMS), Webhook
"""

import os
import json
import smtplib
import urllib.request
import urllib.parse
import urllib.error
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class AlertConfig:
    # Email
    email_enabled: bool = False
    email_user: str = ""
    email_pass: str = ""
    email_to: List[str] = field(default_factory=list)
    email_from: str = ""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    email_severity_min: str = "HIGH"

    # Telegram
    telegram_enabled: bool = False
    telegram_token: str = ""
    telegram_chat_id: str = ""
    telegram_severity_min: str = "HIGH"

    # Slack
    slack_enabled: bool = False
    slack_webhook: str = ""
    slack_channel: str = "#alerts"
    slack_severity_min: str = "HIGH"

    # SMS (Fast2SMS India)
    sms_enabled: bool = False
    fast2sms_key: str = ""
    sms_numbers: List[str] = field(default_factory=list)
    sms_severity_min: str = "CRITICAL"

    # Webhook (generic)
    webhook_enabled: bool = False
    webhook_url: str = ""
    webhook_severity_min: str = "HIGH"


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴🚨",
    "HIGH":     "🟠⚠️",
    "MEDIUM":   "🟡🔔",
    "LOW":      "🟢ℹ️",
}


class AlertManager:
    def __init__(self):
        self.config = AlertConfig()
        self._load_from_env()
        self._sent_hashes: set = set()
        self._queue: List[Dict] = []
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()
        self.alert_log: List[Dict] = []

    def _load_from_env(self):
        """Load config from environment variables"""
        c = self.config

        # Email
        c.email_user = os.getenv("ALERT_EMAIL_USER", "")
        c.email_pass = os.getenv("ALERT_EMAIL_PASS", "")
        to = os.getenv("ALERT_EMAIL_TO", "")
        c.email_to = [t.strip() for t in to.split(",") if t.strip()] if to else []
        c.email_from = c.email_user
        c.email_enabled = bool(c.email_user and c.email_pass and c.email_to)

        # Telegram
        c.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        c.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        c.telegram_enabled = bool(c.telegram_token and c.telegram_chat_id)

        # Slack
        c.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        c.slack_enabled = bool(c.slack_webhook)

        # SMS
        c.fast2sms_key = os.getenv("FAST2SMS_API_KEY", "")
        nums = os.getenv("SMS_ALERT_NUMBERS", "")
        c.sms_numbers = [n.strip() for n in nums.split(",") if n.strip()] if nums else []
        c.sms_enabled = bool(c.fast2sms_key and c.sms_numbers)

        # Webhook
        c.webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
        c.webhook_enabled = bool(c.webhook_url)

    def reload_config(self):
        self._load_from_env()

    def _dedupe_key(self, alert_data: Dict) -> str:
        return f"{alert_data.get('threat_type','')}:{alert_data.get('src_ip','')}:{alert_data.get('severity','')}"

    def send_alert(self, alert_data: Dict, channels: List[str] = None, force: bool = False):
        """Queue an alert for sending"""
        severity = alert_data.get("severity", "LOW")

        # Dedupe: don't send same alert twice within 5 minutes
        key = self._dedupe_key(alert_data)
        if not force and key in self._sent_hashes:
            return

        self._sent_hashes.add(key)
        # Clear old hashes every 1000
        if len(self._sent_hashes) > 1000:
            self._sent_hashes.clear()

        with self._lock:
            self._queue.append({
                "alert": alert_data,
                "channels": channels or ["all"],
                "queued_at": datetime.now().isoformat(),
            })

    def _process_queue(self):
        """Background thread that sends queued alerts"""
        while True:
            try:
                with self._lock:
                    if self._queue:
                        item = self._queue.pop(0)
                    else:
                        item = None

                if item:
                    self._dispatch(item["alert"], item["channels"])
                else:
                    time.sleep(0.5)
            except Exception:
                time.sleep(1)

    def _should_send(self, severity: str, min_severity: str) -> bool:
        return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(min_severity, 2)

    def _dispatch(self, alert: Dict, channels: List[str]):
        severity = alert.get("severity", "LOW")
        results = {}

        send_all = "all" in channels

        if (send_all or "email" in channels) and self.config.email_enabled:
            if self._should_send(severity, self.config.email_severity_min):
                results["email"] = self._send_email(alert)

        if (send_all or "telegram" in channels) and self.config.telegram_enabled:
            if self._should_send(severity, self.config.telegram_severity_min):
                results["telegram"] = self._send_telegram(alert)

        if (send_all or "slack" in channels) and self.config.slack_enabled:
            if self._should_send(severity, self.config.slack_severity_min):
                results["slack"] = self._send_slack(alert)

        if (send_all or "sms" in channels) and self.config.sms_enabled:
            if self._should_send(severity, self.config.sms_severity_min):
                results["sms"] = self._send_sms(alert)

        if (send_all or "webhook" in channels) and self.config.webhook_enabled:
            if self._should_send(severity, self.config.webhook_severity_min):
                results["webhook"] = self._send_webhook(alert)

        # Log
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert": alert,
            "results": results,
        }
        self.alert_log.insert(0, log_entry)
        if len(self.alert_log) > 500:
            self.alert_log.pop()

    # ─── EMAIL ────────────────────────────────────────────────────────────

    def _send_email(self, alert: Dict) -> Dict:
        try:
            c = self.config
            severity = alert.get("severity", "UNKNOWN")
            threat = alert.get("threat_type", "Unknown Threat")
            src_ip = alert.get("src_ip", "N/A")
            dst_ip = alert.get("dst_ip", "N/A")
            emoji = SEVERITY_EMOJI.get(severity, "⚠️")

            subject = f"{emoji} VoraGuard {severity} Alert: {threat}"

            html_body = f"""
<!DOCTYPE html>
<html>
<head><style>
  body {{ font-family: Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; margin: 0; padding: 0; }}
  .container {{ max-width: 600px; margin: 20px auto; background: #111; border-radius: 12px; overflow: hidden; border: 1px solid #333; }}
  .header {{ background: {'#dc2626' if severity=='CRITICAL' else '#ea580c' if severity=='HIGH' else '#ca8a04' if severity=='MEDIUM' else '#16a34a'}; padding: 24px; text-align: center; }}
  .header h1 {{ margin: 0; color: white; font-size: 24px; }}
  .header p {{ margin: 4px 0 0; color: rgba(255,255,255,0.85); }}
  .body {{ padding: 24px; }}
  .field {{ margin-bottom: 12px; }}
  .label {{ color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
  .value {{ color: #e0e0e0; font-size: 15px; font-weight: 600; margin-top: 2px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .mitre {{ background: #1a1a2e; border: 1px solid #333; border-radius: 8px; padding: 12px; margin-top: 16px; }}
  .footer {{ background: #0a0a0a; padding: 16px 24px; text-align: center; color: #555; font-size: 12px; border-top: 1px solid #222; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 700;
            background: {'#991b1b' if severity=='CRITICAL' else '#9a3412' if severity=='HIGH' else '#854d0e' if severity=='MEDIUM' else '#14532d'};
            color: white; }}
</style></head>
<body>
<div class="container">
  <div class="header">
    <h1>◈ VoraGuard Threat Alert</h1>
    <p>{alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>
  </div>
  <div class="body">
    <div style="margin-bottom:20px;">
      <span class="badge">{severity}</span>
      <span style="margin-left:10px; font-size:20px; font-weight:700; color:#60a5fa;">{threat}</span>
    </div>
    <div class="grid">
      <div class="field"><div class="label">Source IP</div><div class="value" style="color:#f87171;">{src_ip}:{alert.get('src_port','?')}</div></div>
      <div class="field"><div class="label">Destination IP</div><div class="value">{dst_ip}:{alert.get('dst_port','?')}</div></div>
      <div class="field"><div class="label">Protocol</div><div class="value">{alert.get('protocol','N/A')}</div></div>
      <div class="field"><div class="label">Packets/sec</div><div class="value">{alert.get('packet_count','N/A')}</div></div>
    </div>
    <div class="field" style="margin-top:16px;"><div class="label">Description</div><div class="value" style="font-size:14px; font-weight:400;">{alert.get('description','')}</div></div>
    <div class="mitre">
      <div class="label" style="color:#818cf8;">MITRE ATT&CK</div>
      <div style="margin-top:8px;">
        <span style="color:#a78bfa;">Tactic:</span> <span style="color:#e0e0e0;">{alert.get('mitre_tactic','N/A')}</span>
        &nbsp;&nbsp;
        <span style="color:#a78bfa;">Technique:</span> <span style="color:#e0e0e0;">{alert.get('mitre_technique','N/A')}</span>
      </div>
    </div>
    {'<div style="margin-top:12px; padding:8px 12px; background:#1c1c1c; border-radius:6px; border-left:3px solid #22c55e; font-size:13px; color:#86efac;">✅ IP automatically blocked by IPS</div>' if alert.get('blocked') else ''}
    {'<div style="margin-top:8px; padding:8px 12px; background:#1c1c1c; border-radius:6px; border-left:3px solid #3b82f6; font-size:13px; color:#93c5fd;">▶️ Playbook executed automatically</div>' if alert.get('playbook_run') else ''}
  </div>
  <div class="footer">◈ VoraGuard Threat Intelligence Platform · Auto-generated alert · Do not reply</div>
</div>
</body></html>"""

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"VoraGuard Alerts <{c.email_from}>"
            msg["To"] = ", ".join(c.email_to)
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(c.smtp_host, c.smtp_port) as server:
                server.starttls()
                server.login(c.email_user, c.email_pass)
                server.sendmail(c.email_from, c.email_to, msg.as_string())

            return {"status": "sent", "to": c.email_to}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # ─── TELEGRAM ─────────────────────────────────────────────────────────

    def _send_telegram(self, alert: Dict) -> Dict:
        try:
            c = self.config
            severity = alert.get("severity", "UNKNOWN")
            threat = alert.get("threat_type", "Unknown")
            src_ip = alert.get("src_ip", "N/A")
            emoji = SEVERITY_EMOJI.get(severity, "⚠️")

            text = (
                f"{emoji} *VoraGuard {severity} Alert*\n\n"
                f"🎯 *Threat:* `{threat}`\n"
                f"🌐 *Source:* `{src_ip}:{alert.get('src_port','?')}`\n"
                f"📍 *Target:* `{alert.get('dst_ip','N/A')}:{alert.get('dst_port','?')}`\n"
                f"⚡ *Protocol:* `{alert.get('protocol','N/A')}`\n"
                f"🕐 *Time:* `{alert.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}`\n\n"
                f"📋 *MITRE:* `{alert.get('mitre_tactic','N/A')} / {alert.get('mitre_technique','N/A')}`\n"
                f"📝 _{alert.get('description','')}_"
            )
            if alert.get("blocked"):
                text += "\n\n✅ *IP auto-blocked by IPS*"
            if alert.get("playbook_run"):
                text += "\n▶️ *Playbook executed*"

            payload = json.dumps({
                "chat_id": c.telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }).encode()

            req = urllib.request.Request(
                f"https://api.telegram.org/bot{c.telegram_token}/sendMessage",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                return {"status": "sent", "message_id": result.get("result", {}).get("message_id")}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # ─── SLACK ────────────────────────────────────────────────────────────

    def _send_slack(self, alert: Dict) -> Dict:
        try:
            c = self.config
            severity = alert.get("severity", "UNKNOWN")
            threat = alert.get("threat_type", "Unknown")
            emoji = SEVERITY_EMOJI.get(severity, "⚠️")

            color_map = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
            color = color_map.get(severity, "#888888")

            payload = json.dumps({
                "channel": c.slack_channel,
                "username": "VoraGuard",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": color,
                    "title": f"{emoji} {severity} Alert: {threat}",
                    "text": alert.get("description", ""),
                    "fields": [
                        {"title": "Source IP", "value": f"`{alert.get('src_ip','N/A')}:{alert.get('src_port','?')}`", "short": True},
                        {"title": "Target", "value": f"`{alert.get('dst_ip','N/A')}:{alert.get('dst_port','?')}`", "short": True},
                        {"title": "Protocol", "value": alert.get("protocol", "N/A"), "short": True},
                        {"title": "MITRE", "value": f"{alert.get('mitre_tactic','N/A')} / {alert.get('mitre_technique','N/A')}", "short": True},
                        {"title": "IPS Blocked", "value": "✅ Yes" if alert.get("blocked") else "❌ No", "short": True},
                        {"title": "Playbook", "value": "▶️ Executed" if alert.get("playbook_run") else "—", "short": True},
                    ],
                    "footer": "VoraGuard Threat Intelligence",
                    "ts": int(datetime.now().timestamp()),
                }]
            }).encode()

            req = urllib.request.Request(
                c.slack_webhook,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"status": "sent", "response": resp.read().decode()}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # ─── SMS (Fast2SMS) ────────────────────────────────────────────────────

    def _send_sms(self, alert: Dict) -> Dict:
        try:
            c = self.config
            severity = alert.get("severity", "UNKNOWN")
            threat = alert.get("threat_type", "Unknown")
            src_ip = alert.get("src_ip", "N/A")

            message = f"VoraGuard {severity}: {threat} from {src_ip}. Check dashboard immediately."

            numbers = ",".join(c.sms_numbers)
            payload = json.dumps({
                "route": "q",
                "message": message,
                "language": "english",
                "flash": 0,
                "numbers": numbers,
            }).encode()

            req = urllib.request.Request(
                "https://www.fast2sms.com/dev/bulkV2",
                data=payload,
                headers={
                    "authorization": c.fast2sms_key,
                    "Content-Type": "application/json",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                return {"status": "sent" if result.get("return") else "failed", "response": result}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # ─── WEBHOOK ──────────────────────────────────────────────────────────

    def _send_webhook(self, alert: Dict) -> Dict:
        try:
            c = self.config
            payload = json.dumps({
                "source": "voraguard",
                "version": "5.0",
                "timestamp": datetime.now().isoformat(),
                "alert": alert,
            }).encode()

            req = urllib.request.Request(
                c.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json", "X-VoraGuard-Version": "5.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"status": "sent", "http_status": resp.status}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # ─── TEST ─────────────────────────────────────────────────────────────

    def test_all_channels(self) -> Dict:
        """Send a test alert to all configured channels"""
        test_alert = {
            "id": 0,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": "Test Alert",
            "severity": "HIGH",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 22,
            "protocol": "TCP",
            "description": "This is a test alert from VoraGuard. All systems operational.",
            "mitre_tactic": "TA0043",
            "mitre_technique": "T1046",
            "packet_count": 99,
            "blocked": False,
            "playbook_run": False,
        }
        self.send_alert(test_alert, channels=["all"], force=True)
        return {"status": "test_queued", "channels": self._get_enabled_channels()}

    def _get_enabled_channels(self) -> List[str]:
        enabled = []
        if self.config.email_enabled: enabled.append("email")
        if self.config.telegram_enabled: enabled.append("telegram")
        if self.config.slack_enabled: enabled.append("slack")
        if self.config.sms_enabled: enabled.append("sms")
        if self.config.webhook_enabled: enabled.append("webhook")
        return enabled

    def get_status(self) -> Dict:
        return {
            "channels": {
                "email": {"enabled": self.config.email_enabled, "to": self.config.email_to, "min_severity": self.config.email_severity_min},
                "telegram": {"enabled": self.config.telegram_enabled, "chat_id": self.config.telegram_chat_id[:8]+"..." if self.config.telegram_chat_id else "", "min_severity": self.config.telegram_severity_min},
                "slack": {"enabled": self.config.slack_enabled, "channel": self.config.slack_channel, "min_severity": self.config.slack_severity_min},
                "sms": {"enabled": self.config.sms_enabled, "numbers": self.config.sms_numbers, "min_severity": self.config.sms_severity_min},
                "webhook": {"enabled": self.config.webhook_enabled, "url": self.config.webhook_url, "min_severity": self.config.webhook_severity_min},
            },
            "enabled_count": len(self._get_enabled_channels()),
            "queue_size": len(self._queue),
            "total_sent": len(self.alert_log),
        }

    def get_log(self, limit: int = 50) -> List[Dict]:
        return self.alert_log[:limit]


# Global instance
_alert_manager = None

def get_alert_manager() -> AlertManager:
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
