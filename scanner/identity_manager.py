"""
VoraGuard Identity Manager v5.0
Microsoft Entra (Azure AD) + Google Workspace + Okta
Developed by Jithu

Monitors for:
  - Risky sign-ins and users (Entra)
  - Suspicious login activity (Google Workspace)
  - User risk events (Okta)
  - Credential compromise detection
  - MFA gaps and account exposure

All APIs are FREE with valid accounts.
Setup:
  Entra:    Azure portal → App Registration → Graph API permissions
  Workspace: Google Cloud Console → Admin SDK API → OAuth2
  Okta:     developer.okta.com → free developer org → API token
"""
import os, json, time, logging, requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

VORAG_HOME   = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
IDENTITY_DIR = VORAG_HOME / "identity"
IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE   = IDENTITY_DIR / "cache.json"
log          = logging.getLogger("vorag.identity")

HEADERS = {"User-Agent": "VoraGuard/5.0"}

def _get_env(key): return (os.environ.get(key) or "").strip()

# ══════════════════════════════════════════════════════════════════
# MICROSOFT ENTRA (Azure AD) — Microsoft Graph API
# ══════════════════════════════════════════════════════════════════

def _entra_get_token():
    """Get Microsoft Graph API access token via client credentials."""
    tenant = _get_env("ENTRA_TENANT_ID")
    client = _get_env("ENTRA_CLIENT_ID")
    secret = _get_env("ENTRA_CLIENT_SECRET")
    if not all([tenant, client, secret]):
        return None
    try:
        r = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={"grant_type":"client_credentials","client_id":client,
                  "client_secret":secret,"scope":"https://graph.microsoft.com/.default"},
            timeout=15)
        if r.status_code == 200:
            return r.json().get("access_token")
    except Exception as e:
        log.error(f"[Entra] token error: {e}")
    return None

def scan_entra():
    """Scan Microsoft Entra for risky users and sign-ins."""
    token = _entra_get_token()
    if not token:
        return {"provider":"Microsoft Entra","status":"not_configured",
                "message":"Set ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET",
                "setup_url":"https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview",
                "findings":[]}

    findings = []
    headers  = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # ── Risky Users ──────────────────────────────────────────────
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
            "?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"
            "&$select=id,userDisplayName,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime",
            headers=headers, timeout=15)
        if r.status_code == 200:
            for u in r.json().get("value", []):
                rl = u.get("riskLevel","").upper()
                sev = "CRITICAL" if rl in ("HIGH","VERYHIGH") else "HIGH" if rl=="MEDIUM" else "MEDIUM"
                findings.append({
                    "type":       "risky_user",
                    "provider":   "Microsoft Entra",
                    "title":      f"Risky User: {u.get('userDisplayName','')} ({rl} risk)",
                    "summary":    f"User {u.get('userPrincipalName','')} has risk state: {u.get('riskState','')}",
                    "severity":   sev,
                    "user":       u.get("userPrincipalName",""),
                    "risk_level": rl,
                    "risk_state": u.get("riskState",""),
                    "updated":    u.get("riskLastUpdatedDateTime",""),
                    "action":     "Review sign-in history, consider forcing password reset + MFA",
                })
        elif r.status_code == 403:
            findings.append({"type":"config_error","provider":"Microsoft Entra",
                              "title":"Missing permission: IdentityRiskyUser.Read.All",
                              "summary":"Grant IdentityRiskyUser.Read.All in Azure app registration",
                              "severity":"INFO"})
    except Exception as e:
        log.error(f"[Entra] riskyUsers: {e}")

    # ── Risky Sign-ins (last 24h) ────────────────────────────────
    try:
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
            f"?$filter=detectedDateTime ge {since}&$top=20"
            f"&$select=id,userDisplayName,userPrincipalName,riskLevel,riskEventType,detectedDateTime,ipAddress,location",
            headers=headers, timeout=15)
        if r.status_code == 200:
            for d in r.json().get("value", []):
                rl = d.get("riskLevel","").upper()
                sev = "CRITICAL" if rl in ("HIGH","VERYHIGH") else "HIGH" if rl=="MEDIUM" else "MEDIUM"
                loc = d.get("location",{})
                country = loc.get("countryOrRegion","") if loc else ""
                findings.append({
                    "type":       "risky_signin",
                    "provider":   "Microsoft Entra",
                    "title":      f"Risky Sign-in: {d.get('userDisplayName','')} — {d.get('riskEventType','')}",
                    "summary":    f"Risk detection for {d.get('userPrincipalName','')} from IP {d.get('ipAddress','')} ({country})",
                    "severity":   sev,
                    "user":       d.get("userPrincipalName",""),
                    "risk_level": rl,
                    "event_type": d.get("riskEventType",""),
                    "ip":         d.get("ipAddress",""),
                    "country":    country,
                    "detected":   d.get("detectedDateTime",""),
                })
    except Exception as e:
        log.error(f"[Entra] riskDetections: {e}")

    # ── MFA Registration Status ──────────────────────────────────
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
            "?$filter=isMfaRegistered eq false&$top=10",
            headers=headers, timeout=15)
        if r.status_code == 200:
            users_no_mfa = r.json().get("value", [])
            if users_no_mfa:
                findings.append({
                    "type":     "mfa_gap",
                    "provider": "Microsoft Entra",
                    "title":    f"{len(users_no_mfa)} users without MFA registered",
                    "summary":  "Users without MFA: " + ", ".join(u.get("userPrincipalName","") for u in users_no_mfa[:5]),
                    "severity": "HIGH",
                    "count":    len(users_no_mfa),
                    "action":   "Enforce MFA via Conditional Access policy",
                })
    except Exception as e:
        log.debug(f"[Entra] MFA check: {e}")

    status = "ok" if findings else "clean"
    return {"provider":"Microsoft Entra","status":status,
            "scanned_at":datetime.now(timezone.utc).isoformat(),
            "findings":findings, "finding_count":len(findings)}


# ══════════════════════════════════════════════════════════════════
# GOOGLE WORKSPACE — Admin SDK Reports API
# ══════════════════════════════════════════════════════════════════

def scan_google_workspace():
    """Scan Google Workspace for suspicious login activity."""
    import json as _json

    service_account_json = _get_env("GOOGLE_WORKSPACE_SA_JSON")
    admin_email          = _get_env("GOOGLE_WORKSPACE_ADMIN_EMAIL")
    customer_id          = _get_env("GOOGLE_WORKSPACE_CUSTOMER_ID") or "my_customer"

    if not (service_account_json and admin_email):
        return {"provider":"Google Workspace","status":"not_configured",
                "message":"Set GOOGLE_WORKSPACE_SA_JSON (path to service account key) and GOOGLE_WORKSPACE_ADMIN_EMAIL",
                "setup_url":"https://admin.google.com/ac/accountsettings/profile",
                "findings":[]}

    findings = []
    token = None

    # Get OAuth2 token using service account
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly",
                  "https://www.googleapis.com/auth/admin.reports.usage.readonly"]
        creds = service_account.Credentials.from_service_account_file(
            service_account_json, scopes=SCOPES, subject=admin_email)
        service = build("admin", "reports_v1", credentials=creds)

        # Suspicious login activities
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = service.activities().list(
            userKey="all", applicationName="login",
            eventName="suspicious_login",
            startTime=since, maxResults=50
        ).execute()

        for event in result.get("items", []):
            actor = event.get("actor",{})
            ip    = event.get("ipAddress","")
            for ev in event.get("events",[]):
                findings.append({
                    "type":     "suspicious_login",
                    "provider": "Google Workspace",
                    "title":    f"Suspicious Login: {actor.get('email','')}",
                    "summary":  f"Suspicious Google Workspace login for {actor.get('email','')} from IP {ip}",
                    "severity": "HIGH",
                    "user":     actor.get("email",""),
                    "ip":       ip,
                    "event":    ev.get("name",""),
                    "time":     event.get("id",{}).get("time",""),
                })

        # Account disabled/suspended events
        result2 = service.activities().list(
            userKey="all", applicationName="admin",
            eventName="SUSPEND_USER",
            startTime=since, maxResults=20
        ).execute()
        for event in result2.get("items", []):
            actor = event.get("actor",{})
            findings.append({
                "type":     "account_suspended",
                "provider": "Google Workspace",
                "title":    f"Account Suspended: {actor.get('email','')}",
                "summary":  f"User account was suspended — possible security incident",
                "severity": "MEDIUM",
                "user":     actor.get("email",""),
            })

    except ImportError:
        findings.append({"type":"config_error","provider":"Google Workspace",
                         "title":"Missing library: google-auth googleapiclient",
                         "summary":"Run: pip install google-auth google-api-python-client --break-system-packages",
                         "severity":"INFO"})
    except Exception as e:
        findings.append({"type":"scan_error","provider":"Google Workspace",
                         "title":f"Scan error: {str(e)[:100]}","summary":str(e),"severity":"INFO"})

    return {"provider":"Google Workspace","status":"ok" if findings else "clean",
            "scanned_at":datetime.now(timezone.utc).isoformat(),
            "findings":findings, "finding_count":len(findings)}


# ══════════════════════════════════════════════════════════════════
# OKTA — Identity Cloud API
# ══════════════════════════════════════════════════════════════════

def scan_okta():
    """Scan Okta for suspicious user activity and policy violations."""
    okta_domain = _get_env("OKTA_DOMAIN")   # e.g. dev-12345.okta.com
    okta_token  = _get_env("OKTA_API_TOKEN")

    if not (okta_domain and okta_token):
        return {"provider":"Okta","status":"not_configured",
                "message":"Set OKTA_DOMAIN (e.g. dev-12345.okta.com) and OKTA_API_TOKEN",
                "setup_url":"https://developer.okta.com/docs/guides/create-an-api-token/main/",
                "findings":[]}

    findings = []
    base    = f"https://{okta_domain}"
    headers = {"Authorization": f"SSWS {okta_token}", "Accept": "application/json"}
    since   = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # ── Suspicious activity in system log ─────────────────────
    try:
        r = requests.get(
            f"{base}/api/v1/logs",
            params={"since":since, "filter":'outcome.result eq "FAILURE"', "limit":50},
            headers=headers, timeout=15)
        if r.status_code == 200:
            failures = {}
            for event in r.json():
                actor = event.get("actor",{}).get("alternateId","")
                etype = event.get("eventType","")
                if "authentication" in etype.lower() or "login" in etype.lower():
                    failures[actor] = failures.get(actor, 0) + 1
            for user, count in failures.items():
                if count >= 5:
                    sev = "CRITICAL" if count >= 15 else "HIGH" if count >= 8 else "MEDIUM"
                    findings.append({
                        "type":     "auth_failures",
                        "provider": "Okta",
                        "title":    f"Repeated Login Failures: {user} ({count}x in 24h)",
                        "summary":  f"User {user} had {count} authentication failures in the last 24 hours",
                        "severity": sev,
                        "user":     user,
                        "count":    count,
                        "action":   "Review account, check for credential stuffing attack",
                    })
    except Exception as e:
        log.error(f"[Okta] logs: {e}")

    # ── Locked accounts ────────────────────────────────────────
    try:
        r = requests.get(
            f"{base}/api/v1/users",
            params={"filter":'status eq "LOCKED_OUT"', "limit":20},
            headers=headers, timeout=15)
        if r.status_code == 200:
            locked = r.json()
            if locked:
                findings.append({
                    "type":     "locked_accounts",
                    "provider": "Okta",
                    "title":    f"{len(locked)} accounts locked out",
                    "summary":  "Locked users: " + ", ".join(
                        u.get("profile",{}).get("login","") for u in locked[:5]),
                    "severity": "MEDIUM",
                    "count":    len(locked),
                })
    except Exception as e:
        log.error(f"[Okta] locked: {e}")

    # ── Suspicious IP events ───────────────────────────────────
    try:
        r = requests.get(
            f"{base}/api/v1/logs",
            params={"since":since, "filter":'securityContext.isProxy eq true', "limit":20},
            headers=headers, timeout=15)
        if r.status_code == 200:
            proxy_events = r.json()
            for event in proxy_events[:10]:
                actor = event.get("actor",{}).get("alternateId","")
                ip    = event.get("client",{}).get("ipAddress","")
                findings.append({
                    "type":     "proxy_login",
                    "provider": "Okta",
                    "title":    f"Login from proxy/anonymizer: {actor}",
                    "summary":  f"User {actor} authenticated from suspicious IP {ip} (proxy/anonymizer detected)",
                    "severity": "HIGH",
                    "user":     actor,
                    "ip":       ip,
                })
    except Exception as e:
        log.error(f"[Okta] proxy: {e}")

    return {"provider":"Okta","status":"ok" if findings else "clean",
            "scanned_at":datetime.now(timezone.utc).isoformat(),
            "findings":findings, "finding_count":len(findings)}


# ══════════════════════════════════════════════════════════════════
# COMBINED SCAN + SOAR INTEGRATION
# ══════════════════════════════════════════════════════════════════

def scan_all_identity():
    """Scan all configured identity providers and feed events into SOAR."""
    results = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "providers": [],
        "total_findings": 0,
        "critical": 0, "high": 0, "medium": 0,
    }

    scanners = [scan_entra, scan_google_workspace, scan_okta]
    for scanner in scanners:
        try:
            result = scanner()
            results["providers"].append(result)
            for f in result.get("findings", []):
                sev = f.get("severity","MEDIUM")
                results["total_findings"] += 1
                if sev == "CRITICAL": results["critical"] += 1
                elif sev == "HIGH":   results["high"] += 1
                elif sev == "MEDIUM": results["medium"] += 1

                # Feed into SOAR
                if sev in ("CRITICAL","HIGH"):
                    try:
                        from soar_engine import get_soar_engine
                        get_soar_engine().process_event({
                            "trigger":        "identity_risk",
                            "severity":       sev,
                            "risk_level":     sev,
                            "title":          f.get("title",""),
                            "summary":        f.get("summary",""),
                            "source":         result["provider"],
                            "affected_email": f.get("user",""),
                            "details":        f,
                        })
                    except Exception as e:
                        log.error(f"[Identity] SOAR feed: {e}")
        except Exception as e:
            log.error(f"[Identity] scanner {scanner.__name__}: {e}")

    # Cache results
    CACHE_FILE.write_text(json.dumps(results, indent=2, default=str))
    log.info(f"[Identity] Scan complete: {results['total_findings']} findings")
    return results

def get_cached_results():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except: pass
    return None
