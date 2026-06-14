"""
VoraGuard v5.0 Settings
Complete configuration for all modules.
Developed by Jithu
"""
import os
from dataclasses import dataclass, field

@dataclass
class Settings:
    # ── Core Intelligence APIs ──────────────────────────────────────────
    VT_API_KEY:               str = os.getenv("VT_API_KEY", "")
    HIBP_API_KEY:             str = os.getenv("HIBP_API_KEY", "")

    # ── IP Intelligence ─────────────────────────────────────────────────
    ABUSEIPDB_API_KEY:        str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY:           str = os.getenv("SHODAN_API_KEY", "")
    IPQUALITYSCORE_KEY:       str = os.getenv("IPQUALITYSCORE_KEY", "")
    CRIMINALIP_API_KEY:       str = os.getenv("CRIMINALIP_API_KEY", "")

    # ── Threat Intelligence ─────────────────────────────────────────────
    OTX_API_KEY:              str = os.getenv("OTX_API_KEY", "")
    LEAKIX_API_KEY:           str = os.getenv("LEAKIX_API_KEY", "")
    DEHASHED_EMAIL:           str = os.getenv("DEHASHED_EMAIL", "")
    DEHASHED_API_KEY:         str = os.getenv("DEHASHED_API_KEY", "")

    # ── Brand & Safe Browsing ────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    GITHUB_TOKEN:             str = os.getenv("GITHUB_TOKEN", "")

    # ── Alerting — Slack ─────────────────────────────────────────────────
    SLACK_WEBHOOK_URL:        str = os.getenv("SLACK_WEBHOOK_URL", "")

    # ── Alerting — Email (SMTP) ──────────────────────────────────────────
    ALERT_SMTP_HOST:          str = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
    ALERT_SMTP_PORT:          int = int(os.getenv("ALERT_SMTP_PORT", "587"))
    ALERT_EMAIL_USER:         str = os.getenv("ALERT_EMAIL_USER", "")
    ALERT_EMAIL_PASS:         str = os.getenv("ALERT_EMAIL_PASS", "")
    ALERT_EMAIL_TO:           str = os.getenv("ALERT_EMAIL_TO", "")

    # ── Alerting — Telegram ──────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN:       str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID:         str = os.getenv("TELEGRAM_CHAT_ID", "")

    # ── Alerting — SMS (Fast2SMS India FREE / Twilio) ────────────────────
    # Fast2SMS: https://www.fast2sms.com  — free 50 SMS/day India
    FAST2SMS_API_KEY:         str = os.getenv("FAST2SMS_API_KEY", "")
    SMS_ALERT_NUMBERS:        str = os.getenv("SMS_ALERT_NUMBERS", "")   # comma-separated E.164
    # Twilio (optional)
    TWILIO_ACCOUNT_SID:       str = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN:        str = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_FROM_NUMBER:       str = os.getenv("TWILIO_FROM_NUMBER", "")

    # ── Alerting — Webhook ───────────────────────────────────────────────
    ALERT_WEBHOOK_URL:        str = os.getenv("ALERT_WEBHOOK_URL", "")
    ALERT_WEBHOOK_SECRET:     str = os.getenv("ALERT_WEBHOOK_SECRET", "")

    # ── Takedown ─────────────────────────────────────────────────────────
    PHISHTANK_USERNAME:       str = os.getenv("PHISHTANK_USERNAME", "")
    PHISHTANK_API_KEY:        str = os.getenv("PHISHTANK_API_KEY", "")
    URLHAUS_TOKEN:            str = os.getenv("URLHAUS_TOKEN", "")

    # ── Identity — Microsoft Entra (Azure AD) ────────────────────────────
    # App registration: https://portal.azure.com → Azure AD → App registrations
    AZURE_TENANT_ID:          str = os.getenv("AZURE_TENANT_ID", "")
    AZURE_CLIENT_ID:          str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET:      str = os.getenv("AZURE_CLIENT_SECRET", "")

    # ── Identity — Google Workspace ──────────────────────────────────────
    # Service account JSON path or credentials JSON content
    GOOGLE_WORKSPACE_CREDS:   str = os.getenv("GOOGLE_WORKSPACE_CREDS", "")
    GOOGLE_WORKSPACE_DOMAIN:  str = os.getenv("GOOGLE_WORKSPACE_DOMAIN", "")
    GOOGLE_WORKSPACE_ADMIN:   str = os.getenv("GOOGLE_WORKSPACE_ADMIN", "")

    # ── Identity — Okta ──────────────────────────────────────────────────
    OKTA_DOMAIN:              str = os.getenv("OKTA_DOMAIN", "")          # e.g. yourorg.okta.com
    OKTA_API_TOKEN:           str = os.getenv("OKTA_API_TOKEN", "")

    # ── Telegram Dark Web Monitoring ─────────────────────────────────────
    # Bot must be added to target channels as member
    TELEGRAM_MONITOR_BOT_TOKEN: str = os.getenv("TELEGRAM_MONITOR_BOT_TOKEN", "")
    TELEGRAM_MONITOR_CHANNELS:  str = os.getenv("TELEGRAM_MONITOR_CHANNELS", "")  # comma-separated

    # ── Network Monitor ──────────────────────────────────────────────────
    NETWORK_INTERFACE:        str = os.getenv("NETWORK_INTERFACE", "")    # auto-detect if empty
    NETWORK_MONITOR_DOMAINS:  str = os.getenv("NETWORK_MONITOR_DOMAINS", "")  # comma-separated
    NETWORK_ALERT_MIN_SEVERITY: str = os.getenv("NETWORK_ALERT_MIN_SEVERITY", "MEDIUM")

    # ── AI / Ollama ──────────────────────────────────────────────────────
    OLLAMA_URL:               str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL:             str = os.getenv("OLLAMA_MODEL", "llama3.2")

    # ── SOAR Automation ──────────────────────────────────────────────────
    SOAR_ENABLED:             bool = os.getenv("SOAR_ENABLED", "true").lower() == "true"
    SOAR_AUTO_BLOCK:          bool = os.getenv("SOAR_AUTO_BLOCK", "false").lower() == "true"

    # ── Tool Paths ───────────────────────────────────────────────────────
    NMAP_PATH:                str = os.getenv("NMAP_PATH", "nmap")
    DNSTWIST_PATH:            str = os.getenv("DNSTWIST_PATH", "dnstwist")
    THEHARVESTER_PATH:        str = os.getenv("THEHARVESTER_PATH", "theHarvester")

    # ── Web / Output ─────────────────────────────────────────────────────
    OUTPUT_BASE:              str = os.getenv("VORAGUARD_OUTPUT", "scans")
    WEB_HOST:                 str = os.getenv("WEB_HOST", "0.0.0.0")
    WEB_PORT:                 int = int(os.getenv("WEB_PORT", "5000"))
    SECRET_KEY:               str = os.getenv("SECRET_KEY", "voraguard-change-in-prod")

    # ── Timeouts ─────────────────────────────────────────────────────────
    NMAP_TIMEOUT:             int = 300
    DNSTWIST_TIMEOUT:         int = 120
    HARVESTER_TIMEOUT:        int = 120
    VT_TIMEOUT:               int = 30

    def validate(self) -> list:
        warnings = []
        if not self.VT_API_KEY:
            warnings.append("VT_API_KEY not set — VirusTotal checks skipped")
        if not self.OTX_API_KEY:
            warnings.append("OTX_API_KEY not set — AlienVault OTX skipped")
        if not self.LEAKIX_API_KEY:
            warnings.append("LEAKIX_API_KEY not set — LeakIX dark web skipped")
        if not self.FAST2SMS_API_KEY and not self.TWILIO_ACCOUNT_SID:
            warnings.append("No SMS provider configured — SMS alerts disabled")
        return warnings

    def get_sms_numbers(self) -> list:
        if not self.SMS_ALERT_NUMBERS:
            return []
        return [n.strip() for n in self.SMS_ALERT_NUMBERS.split(",") if n.strip()]

    def get_monitor_domains(self) -> list:
        if not self.NETWORK_MONITOR_DOMAINS:
            return []
        return [d.strip() for d in self.NETWORK_MONITOR_DOMAINS.split(",") if d.strip()]

    def get_telegram_channels(self) -> list:
        if not self.TELEGRAM_MONITOR_CHANNELS:
            return []
        return [c.strip() for c in self.TELEGRAM_MONITOR_CHANNELS.split(",") if c.strip()]

settings = Settings()
