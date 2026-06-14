"""
VoraGuard Domain Deep Scan Module
20 new security checks — no overlap with existing modules.
Covers: DNSSEC, AXFR, Dangling CNAME, TTL, NS Redundancy, DKIM,
BIMI, MTA-STS, Open Relay, RBL, Cipher Suites, HSTS Preload,
CT Logs, Cookie Flags, CMS Fingerprint, WAF Detection,
Cloud Asset Discovery, Subdomain Enumeration, SPF Hard Fail,
DMARC Policy Enforcement.
"""
import socket
import ssl
import subprocess
import requests
import re
import json
from datetime import datetime, timezone
from typing import Optional
from utils.logger import get_logger

log = get_logger(__name__)

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (VoraGuard Security Scanner)"}


# ─────────────────────────────────────────────
# 1. DNSSEC VALIDATION
# ─────────────────────────────────────────────
def check_dnssec(domain: str) -> dict:
    result = {"enabled": False, "ds_record": False, "dnskey": False, "rrsig": False, "issues": []}
    try:
        r = subprocess.run(["dig", "+dnssec", "DS", domain], capture_output=True, text=True, timeout=TIMEOUT)
        if "DS" in r.stdout and "RRSIG" in r.stdout:
            result["ds_record"] = True
            result["rrsig"] = True
        r2 = subprocess.run(["dig", "+dnssec", "DNSKEY", domain], capture_output=True, text=True, timeout=TIMEOUT)
        if "DNSKEY" in r2.stdout:
            result["dnskey"] = True
        result["enabled"] = result["ds_record"] and result["dnskey"]
        if not result["enabled"]:
            result["issues"].append("DNSSEC not enabled — vulnerable to DNS spoofing and cache poisoning")
    except Exception as e:
        result["issues"].append(f"DNSSEC check error: {e}")
    return result


# ─────────────────────────────────────────────
# 2. ZONE TRANSFER (AXFR) TEST
# ─────────────────────────────────────────────
def check_zone_transfer(domain: str) -> dict:
    result = {"vulnerable": False, "nameservers_tested": [], "leaked_records": [], "issues": []}
    try:
        ns_r = subprocess.run(["dig", "+short", "NS", domain], capture_output=True, text=True, timeout=TIMEOUT)
        nameservers = [ns.strip().rstrip(".") for ns in ns_r.stdout.splitlines() if ns.strip()]
        result["nameservers_tested"] = nameservers
        for ns in nameservers[:3]:
            try:
                axfr = subprocess.run(["dig", f"@{ns}", domain, "AXFR"], capture_output=True, text=True, timeout=15)
                if "Transfer failed" not in axfr.stdout and axfr.stdout.count(domain) > 5:
                    result["vulnerable"] = True
                    lines = [l.strip() for l in axfr.stdout.splitlines() if domain in l and not l.startswith(";")]
                    result["leaked_records"] = lines[:20]
                    result["issues"].append(f"CRITICAL: Zone transfer allowed on {ns} — all subdomains exposed")
            except Exception:
                pass
        if not result["vulnerable"]:
            result["issues"] = []
    except Exception as e:
        result["issues"].append(f"AXFR check error: {e}")
    return result


# ─────────────────────────────────────────────
# 3. DANGLING CNAME DETECTION
# ─────────────────────────────────────────────
def check_dangling_cnames(domain: str) -> dict:
    result = {"dangling": [], "checked": [], "issues": []}
    subdomains_to_check = [
        f"www.{domain}", f"mail.{domain}", f"api.{domain}",
        f"dev.{domain}", f"staging.{domain}", f"app.{domain}",
        f"cdn.{domain}", f"static.{domain}", f"blog.{domain}"
    ]
    for sub in subdomains_to_check:
        try:
            r = subprocess.run(["dig", "+short", "CNAME", sub], capture_output=True, text=True, timeout=5)
            cname_target = r.stdout.strip().rstrip(".")
            if cname_target:
                result["checked"].append({"subdomain": sub, "cname": cname_target})
                try:
                    socket.gethostbyname(cname_target)
                except socket.gaierror:
                    result["dangling"].append({"subdomain": sub, "cname": cname_target})
                    result["issues"].append(f"CRITICAL: Dangling CNAME — {sub} → {cname_target} (does not resolve, takeover risk)")
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────
# 4. TTL ANALYSIS
# ─────────────────────────────────────────────
def check_ttl_analysis(domain: str) -> dict:
    result = {"records": [], "issues": []}
    record_types = ["A", "MX", "NS", "TXT"]
    for rtype in record_types:
        try:
            r = subprocess.run(["dig", rtype, domain], capture_output=True, text=True, timeout=TIMEOUT)
            for line in r.stdout.splitlines():
                if domain in line and rtype in line and not line.startswith(";"):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            ttl = int(parts[1])
                            result["records"].append({"type": rtype, "ttl": ttl})
                            if ttl < 300:
                                result["issues"].append(f"Very low TTL ({ttl}s) on {rtype} record — may cause instability")
                            elif ttl > 86400:
                                result["issues"].append(f"Very high TTL ({ttl}s) on {rtype} record — slow failover")
                        except ValueError:
                            pass
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────
# 5. NAMESERVER REDUNDANCY
# ─────────────────────────────────────────────
def check_ns_redundancy(domain: str) -> dict:
    result = {"nameservers": [], "unique_asns": [], "redundant": False, "issues": []}
    try:
        r = subprocess.run(["dig", "+short", "NS", domain], capture_output=True, text=True, timeout=TIMEOUT)
        ns_list = [ns.strip().rstrip(".") for ns in r.stdout.splitlines() if ns.strip()]
        result["nameservers"] = ns_list
        if len(ns_list) < 2:
            result["issues"].append("Only one nameserver — single point of failure")
        else:
            result["redundant"] = True
        ips = []
        for ns in ns_list[:4]:
            try:
                ip = socket.gethostbyname(ns)
                ips.append(ip)
            except Exception:
                pass
        octets = set(ip.rsplit(".", 2)[0] for ip in ips)
        result["unique_asns"] = list(octets)
        if len(octets) < 2 and len(ns_list) >= 2:
            result["issues"].append("All nameservers on same subnet — not resilient to network outages")
    except Exception as e:
        result["issues"].append(f"NS redundancy check error: {e}")
    return result


# ─────────────────────────────────────────────
# 6. DKIM SELECTOR DISCOVERY
# ─────────────────────────────────────────────
def check_dkim(domain: str) -> dict:
    result = {"selectors_found": [], "valid_keys": [], "issues": []}
    common_selectors = [
        "default", "google", "mail", "dkim", "k1", "k2", "s1", "s2",
        "selector1", "selector2", "email", "smtp", "mta", "key1", "key2",
        "sendgrid", "mailchimp", "amazonses", "pm", "mandrill"
    ]
    for sel in common_selectors:
        try:
            r = subprocess.run(
                ["dig", "+short", "TXT", f"{sel}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            if "v=DKIM1" in r.stdout or "p=" in r.stdout:
                result["selectors_found"].append(sel)
                if "p=" in r.stdout and 'p=""' not in r.stdout:
                    result["valid_keys"].append(sel)
                elif 'p=""' in r.stdout:
                    result["issues"].append(f"DKIM selector '{sel}' has revoked key (p= empty)")
        except Exception:
            pass
    if not result["selectors_found"]:
        result["issues"].append("No DKIM selectors found — email authentication incomplete")
    return result


# ─────────────────────────────────────────────
# 7. BIMI VALIDATION
# ─────────────────────────────────────────────
def check_bimi(domain: str) -> dict:
    result = {"present": False, "record": "", "has_logo": False, "has_vmc": False, "issues": []}
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", f"default._bimi.{domain}"],
            capture_output=True, text=True, timeout=TIMEOUT
        )
        for line in r.stdout.splitlines():
            if "v=BIMI1" in line:
                result["present"] = True
                result["record"] = line.strip().strip('"')
                if "l=" in line and "l=;" not in line:
                    result["has_logo"] = True
                if "a=" in line and "a=;" not in line:
                    result["has_vmc"] = True
                break
        if not result["present"]:
            result["issues"].append("No BIMI record — brand logo not shown in supported email clients")
        elif result["present"] and not result["has_vmc"]:
            result["issues"].append("BIMI present but no VMC certificate — logo may not display in all clients")
    except Exception as e:
        result["issues"].append(f"BIMI check error: {e}")
    return result


# ─────────────────────────────────────────────
# 8. MTA-STS & TLS-RPT
# ─────────────────────────────────────────────
def check_mta_sts(domain: str) -> dict:
    result = {"mta_sts_present": False, "tls_rpt_present": False, "policy": {}, "issues": []}
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", f"_mta-sts.{domain}"],
            capture_output=True, text=True, timeout=TIMEOUT
        )
        if "v=STSv1" in r.stdout:
            result["mta_sts_present"] = True
            try:
                resp = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=TIMEOUT, headers=HEADERS)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            result["policy"][k.strip()] = v.strip()
            except Exception:
                pass
        else:
            result["issues"].append("MTA-STS not configured — SMTP connections vulnerable to downgrade attacks")
    except Exception:
        pass
    try:
        r2 = subprocess.run(
            ["dig", "+short", "TXT", f"_smtp._tls.{domain}"],
            capture_output=True, text=True, timeout=TIMEOUT
        )
        if "v=TLSRPTv1" in r2.stdout:
            result["tls_rpt_present"] = True
        else:
            result["issues"].append("TLS-RPT not configured — no SMTP TLS failure reporting")
    except Exception:
        pass
    return result


# ─────────────────────────────────────────────
# 9. OPEN RELAY TEST
# ─────────────────────────────────────────────
def check_open_relay(domain: str) -> dict:
    result = {"mx_hosts": [], "open_relay": False, "tested": False, "issues": []}
    try:
        r = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=TIMEOUT)
        mx_hosts = []
        for line in r.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                mx_hosts.append(parts[-1].rstrip("."))
        result["mx_hosts"] = mx_hosts[:3]
        for mx in mx_hosts[:1]:
            try:
                import smtplib
                smtp = smtplib.SMTP(mx, 25, timeout=8)
                smtp.ehlo("voraguard-test.com")
                code, _ = smtp.docmd("MAIL FROM:", "<test@voraguard-test.com>")
                if code == 250:
                    code2, _ = smtp.docmd("RCPT TO:", "<relay-test@external-domain.net>")
                    if code2 == 250:
                        result["open_relay"] = True
                        result["issues"].append(f"CRITICAL: Open relay detected on {mx} — can be abused for spam")
                result["tested"] = True
                smtp.quit()
            except Exception:
                result["tested"] = False
    except Exception as e:
        result["issues"].append(f"Open relay check error: {e}")
    return result


# ─────────────────────────────────────────────
# 10. RBL / BLOCKLIST CHECK
# ─────────────────────────────────────────────
def check_rbl(domain: str) -> dict:
    result = {"ip": "", "listed_on": [], "clean": True, "checked_lists": 0, "issues": []}
    rbl_zones = [
        "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
        "b.barracudacentral.org", "dnsbl-1.uceprotect.net",
        "psbl.surriel.com", "spam.dnsbl.sorbs.net", "dul.dnsbl.sorbs.net",
        "ix.dnsbl.manitu.net", "truncate.gbudb.net",
    ]
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        rev_ip = ".".join(reversed(ip.split(".")))
        result["checked_lists"] = len(rbl_zones)
        for rbl in rbl_zones:
            try:
                lookup = f"{rev_ip}.{rbl}"
                socket.gethostbyname(lookup)
                result["listed_on"].append(rbl)
                result["clean"] = False
            except socket.gaierror:
                pass
        if result["listed_on"]:
            result["issues"].append(f"IP {ip} listed on {len(result['listed_on'])} RBL(s): {', '.join(result['listed_on'])}")
    except Exception as e:
        result["issues"].append(f"RBL check error: {e}")
    return result


# ─────────────────────────────────────────────
# 11. CIPHER SUITE ANALYSIS
# ─────────────────────────────────────────────
def check_cipher_suites(domain: str) -> dict:
    result = {"supported_protocols": [], "weak_ciphers": [], "strong_ciphers": [], "issues": []}
    weak_ciphers = ["RC4", "3DES", "NULL", "EXPORT", "anon", "DES", "MD5"]
    protocols_to_test = [
        ("TLSv1", ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),
    ]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(socket.create_connection((domain, 443), timeout=TIMEOUT), server_hostname=domain)
        cipher = conn.cipher()
        proto = conn.version()
        conn.close()
        result["supported_protocols"].append(proto)
        if cipher:
            cipher_name = cipher[0]
            is_weak = any(w in cipher_name for w in weak_ciphers)
            if is_weak:
                result["weak_ciphers"].append(cipher_name)
                result["issues"].append(f"Weak cipher in use: {cipher_name}")
            else:
                result["strong_ciphers"].append(cipher_name)
        if proto in ["TLSv1", "TLSv1.1", "SSLv3"]:
            result["issues"].append(f"Outdated protocol in use: {proto} — should be TLS 1.2 or 1.3 only")
    except Exception as e:
        result["issues"].append(f"Cipher check error: {e}")
    return result


# ─────────────────────────────────────────────
# 12. HSTS PRELOAD CHECK
# ─────────────────────────────────────────────
def check_hsts(domain: str) -> dict:
    result = {"hsts_present": False, "max_age": 0, "include_subdomains": False,
              "preload": False, "preload_eligible": False, "issues": []}
    try:
        resp = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            result["hsts_present"] = True
            ma = re.search(r"max-age=(\d+)", hsts)
            if ma:
                result["max_age"] = int(ma.group(1))
            result["include_subdomains"] = "includeSubDomains" in hsts
            result["preload"] = "preload" in hsts
            if result["max_age"] >= 31536000 and result["include_subdomains"] and result["preload"]:
                result["preload_eligible"] = True
            elif result["max_age"] < 31536000:
                result["issues"].append(f"HSTS max-age too low ({result['max_age']}s) — minimum 1 year required for preload")
            if not result["include_subdomains"]:
                result["issues"].append("HSTS missing includeSubDomains — subdomains not protected")
            if not result["preload"]:
                result["issues"].append("HSTS missing preload directive — not eligible for browser preload list")
        else:
            result["issues"].append("HSTS header missing — users vulnerable to SSL stripping attacks")
    except Exception as e:
        result["issues"].append(f"HSTS check error: {e}")
    return result


# ─────────────────────────────────────────────
# 13. CERTIFICATE TRANSPARENCY LOG MONITORING
# ─────────────────────────────────────────────
def check_ct_logs(domain: str) -> dict:
    result = {"recent_certs": [], "total_found": 0, "suspicious": [], "issues": []}
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30, headers=HEADERS
        )
        if resp.status_code == 200:
            certs = resp.json()
            result["total_found"] = len(certs)
            seen = set()
            for cert in certs[:50]:
                name = cert.get("name_value", "").strip()
                issuer = cert.get("issuer_name", "")
                entry_ts = cert.get("entry_timestamp", "")
                if name not in seen:
                    seen.add(name)
                    result["recent_certs"].append({
                        "name": name,
                        "issuer": issuer,
                        "issued": entry_ts[:10] if entry_ts else ""
                    })
                    suspicious_issuers = ["Let's Encrypt", "ZeroSSL", "Buypass"]
                    wild = "*" in name
                    unknown_subdomain = name.count(".") > domain.count(".") + 1
                    if wild or (unknown_subdomain and any(s in issuer for s in suspicious_issuers)):
                        result["suspicious"].append({"name": name, "issuer": issuer})
            result["recent_certs"] = result["recent_certs"][:15]
            if result["suspicious"]:
                result["issues"].append(f"{len(result['suspicious'])} suspicious certificates found in CT logs — possible rogue issuance")
    except Exception as e:
        result["issues"].append(f"CT log check error: {e}")
    return result


# ─────────────────────────────────────────────
# 14. COOKIE SECURITY FLAGS
# ─────────────────────────────────────────────
def check_cookie_security(domain: str) -> dict:
    result = {"cookies": [], "insecure_cookies": [], "issues": []}
    try:
        resp = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
        for cookie in resp.cookies:
            info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                "samesite": cookie.get_nonstandard_attr("SameSite") or "Not Set",
                "path": cookie.path,
            }
            result["cookies"].append(info)
            issues_for_cookie = []
            if not cookie.secure:
                issues_for_cookie.append("missing Secure flag")
            if not info["httponly"]:
                issues_for_cookie.append("missing HttpOnly flag")
            if info["samesite"] == "Not Set":
                issues_for_cookie.append("missing SameSite attribute")
            if issues_for_cookie:
                result["insecure_cookies"].append({"name": cookie.name, "issues": issues_for_cookie})
        if result["insecure_cookies"]:
            result["issues"].append(f"{len(result['insecure_cookies'])} cookie(s) missing security flags — session hijacking risk")
    except Exception as e:
        result["issues"].append(f"Cookie check error: {e}")
    return result


# ─────────────────────────────────────────────
# 15. CMS FINGERPRINTING
# ─────────────────────────────────────────────
def check_cms_fingerprint(domain: str) -> dict:
    result = {"cms": None, "version": None, "plugins": [], "issues": []}
    cms_signatures = {
        "WordPress": ["/wp-login.php", "/wp-admin/", "/wp-content/", "wp-includes"],
        "Drupal": ["/sites/default/", "Drupal.settings", "/core/misc/drupal.js"],
        "Joomla": ["/administrator/", "Joomla!", "/components/com_"],
        "Magento": ["/skin/frontend/", "Mage.Cookies", "/js/mage/"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        "Ghost": ["/ghost/api/", "ghost-sdk"],
        "Wix": ["wix.com/", "X-Wix-"],
        "Squarespace": ["squarespace.com", "static.squarespace"],
    }
    try:
        resp = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
        body = resp.text
        resp_headers = str(resp.headers)
        for cms, sigs in cms_signatures.items():
            if any(s in body or s in resp_headers for s in sigs):
                result["cms"] = cms
                if cms == "WordPress":
                    ver = re.search(r'content="WordPress (\d+\.\d+[\.\d]*)"', body)
                    if not ver:
                        ver = re.search(r'\?ver=(\d+\.\d+[\.\d]*)', body)
                    if ver:
                        result["version"] = ver.group(1)
                    plugins = re.findall(r'/wp-content/plugins/([^/\"\']+)', body)
                    result["plugins"] = list(set(plugins))[:10]
                    result["issues"].append(f"WordPress detected{' v'+result['version'] if result['version'] else ''} — ensure plugins are updated and wp-admin is protected")
                else:
                    result["issues"].append(f"{cms} CMS detected — check for known CVEs and version disclosure")
                break
        for path in ["/wp-login.php", "/admin", "/administrator", "/.git/HEAD", "/backup.sql", "/config.bak"]:
            try:
                r2 = requests.get(f"https://{domain}{path}", timeout=5, headers=HEADERS, allow_redirects=False)
                if r2.status_code in [200, 301, 302] and path in ["/.git/HEAD", "/backup.sql", "/config.bak"]:
                    result["issues"].append(f"Sensitive path accessible: {path} (HTTP {r2.status_code})")
            except Exception:
                pass
    except Exception as e:
        result["issues"].append(f"CMS fingerprint error: {e}")
    return result


# ─────────────────────────────────────────────
# 16. WAF DETECTION
# ─────────────────────────────────────────────
def check_waf(domain: str) -> dict:
    result = {"waf_detected": False, "waf_name": None, "confidence": "low", "issues": []}
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai": ["akamai", "akamai-ghost", "x-akamai-transformed"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
        "Sucuri": ["x-sucuri-id", "sucuri-clientside"],
        "F5 BIG-IP": ["bigipserver", "f5-trafficshield", "ts="],
        "Barracuda": ["barra_counter_session", "bni__"],
        "Fortinet": ["fortigate", "fortiWeb"],
    }
    try:
        resp = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        header_str = json.dumps(headers_lower)
        for waf, sigs in waf_signatures.items():
            matches = sum(1 for s in sigs if s.lower() in header_str)
            if matches >= 1:
                result["waf_detected"] = True
                result["waf_name"] = waf
                result["confidence"] = "high" if matches >= 2 else "medium"
                break
        if not result["waf_detected"]:
            result["issues"].append("No WAF detected — web application directly exposed without firewall protection")
    except Exception as e:
        result["issues"].append(f"WAF detection error: {e}")
    return result


# ─────────────────────────────────────────────
# 17. CLOUD ASSET DISCOVERY (S3/Azure/GCP)
# ─────────────────────────────────────────────
def check_cloud_assets(domain: str) -> dict:
    result = {"exposed_buckets": [], "checked": [], "issues": []}
    base = domain.replace("www.", "").split(".")[0]
    bucket_patterns = [
        f"{base}", f"{base}-backup", f"{base}-assets", f"{base}-static",
        f"{base}-media", f"{base}-uploads", f"{base}-dev", f"{base}-staging",
        f"{base}-prod", f"{base}-data", f"{base}-public",
    ]
    cloud_endpoints = []
    for b in bucket_patterns:
        cloud_endpoints.append(("S3", f"https://{b}.s3.amazonaws.com"))
        cloud_endpoints.append(("S3", f"https://s3.amazonaws.com/{b}"))
        cloud_endpoints.append(("Azure", f"https://{b}.blob.core.windows.net"))
        cloud_endpoints.append(("GCP", f"https://storage.googleapis.com/{b}"))
    for provider, url in cloud_endpoints[:20]:
        result["checked"].append(url)
        try:
            resp = requests.get(url, timeout=5, headers=HEADERS)
            if resp.status_code == 200:
                result["exposed_buckets"].append({"provider": provider, "url": url, "status": "OPEN"})
                result["issues"].append(f"CRITICAL: Open {provider} bucket — {url}")
            elif resp.status_code == 403:
                result["exposed_buckets"].append({"provider": provider, "url": url, "status": "EXISTS_PRIVATE"})
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────
# 18. SUBDOMAIN ENUMERATION (PASSIVE)
# ─────────────────────────────────────────────
def check_subdomains(domain: str) -> dict:
    result = {"subdomains": [], "total": 0, "live": [], "issues": []}
    found = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30, headers=HEADERS
        )
        if resp.status_code == 200:
            for cert in resp.json():
                names = cert.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if domain in name and name != domain:
                        found.add(name)
    except Exception:
        pass
    try:
        resp2 = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=10, headers=HEADERS
        )
        if resp2.status_code == 200:
            for line in resp2.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if domain in sub:
                        found.add(sub)
    except Exception:
        pass
    result["subdomains"] = sorted(list(found))[:50]
    result["total"] = len(found)
    live = []
    for sub in result["subdomains"][:20]:
        try:
            socket.gethostbyname(sub)
            live.append(sub)
        except Exception:
            pass
    result["live"] = live
    if len(live) > 10:
        result["issues"].append(f"Large attack surface: {len(live)} live subdomains discovered")
    return result


# ─────────────────────────────────────────────
# 19. SPF HARD FAIL CHECK
# ─────────────────────────────────────────────
def check_spf_hard_fail(domain: str) -> dict:
    result = {"spf_record": "", "policy": "none", "hard_fail": False,
              "lookup_count": 0, "issues": []}
    try:
        r = subprocess.run(["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=TIMEOUT)
        for line in r.stdout.splitlines():
            if "v=spf1" in line:
                record = line.strip().strip('"')
                result["spf_record"] = record
                if record.endswith("-all"):
                    result["hard_fail"] = True
                    result["policy"] = "hard_fail (-all)"
                elif record.endswith("~all"):
                    result["policy"] = "soft_fail (~all)"
                    result["issues"].append("SPF uses ~all (soft fail) — spoofed emails may still be delivered. Use -all for hard fail.")
                elif record.endswith("+all"):
                    result["policy"] = "pass_all (+all) — CRITICAL"
                    result["issues"].append("CRITICAL: SPF uses +all — allows anyone to send email as this domain")
                elif record.endswith("?all"):
                    result["policy"] = "neutral (?all)"
                    result["issues"].append("SPF uses ?all (neutral) — provides no protection against spoofing")
                lookups = len(re.findall(r'\b(?:include|a|mx|ptr|exists|redirect)\b', record))
                result["lookup_count"] = lookups
                if lookups > 10:
                    result["issues"].append(f"SPF has {lookups} DNS lookups — exceeds limit of 10, may cause failures")
                break
        if not result["spf_record"]:
            result["issues"].append("No SPF record found")
    except Exception as e:
        result["issues"].append(f"SPF hard fail check error: {e}")
    return result


# ─────────────────────────────────────────────
# 20. DMARC POLICY ENFORCEMENT
# ─────────────────────────────────────────────
def check_dmarc_policy(domain: str) -> dict:
    result = {"record": "", "policy": "none", "subdomain_policy": "none",
              "pct": 100, "rua": [], "ruf": [], "strict_alignment": False, "issues": []}
    try:
        r = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=TIMEOUT
        )
        for line in r.stdout.splitlines():
            if "v=DMARC1" in line:
                record = line.strip().strip('"')
                result["record"] = record
                p = re.search(r'\bp=(\w+)', record)
                if p:
                    result["policy"] = p.group(1)
                sp = re.search(r'\bsp=(\w+)', record)
                if sp:
                    result["subdomain_policy"] = sp.group(1)
                pct = re.search(r'\bpct=(\d+)', record)
                if pct:
                    result["pct"] = int(pct.group(1))
                rua = re.findall(r'rua=([^;]+)', record)
                if rua:
                    result["rua"] = [r.strip() for r in rua[0].split(",")]
                ruf = re.findall(r'ruf=([^;]+)', record)
                if ruf:
                    result["ruf"] = [r.strip() for r in ruf[0].split(",")]
                adkim = re.search(r'adkim=s', record)
                aspf = re.search(r'aspf=s', record)
                result["strict_alignment"] = bool(adkim and aspf)
                if result["policy"] == "none":
                    result["issues"].append("DMARC policy is 'none' — emails are monitored but not rejected/quarantined")
                elif result["policy"] == "quarantine":
                    result["issues"].append("DMARC policy is 'quarantine' — consider upgrading to 'reject' for full protection")
                if result["pct"] < 100:
                    result["issues"].append(f"DMARC pct={result['pct']}% — policy not applied to all emails")
                if not result["rua"]:
                    result["issues"].append("No DMARC aggregate reporting address (rua) — not receiving spoofing reports")
                break
        if not result["record"]:
            result["issues"].append("No DMARC record found — domain can be freely spoofed in email")
    except Exception as e:
        result["issues"].append(f"DMARC policy check error: {e}")
    return result


# ─────────────────────────────────────────────
# MASTER RUNNER
# ─────────────────────────────────────────────
def run_domain_deep_scan(domain: str) -> dict:
    """Run all 20 deep scan checks. Returns unified dict."""
    log.info(f"[DeepScan] Starting 20-check deep scan for {domain}")
    results = {}
    checks = [
        ("dnssec",          check_dnssec),
        ("zone_transfer",   check_zone_transfer),
        ("dangling_cnames", check_dangling_cnames),
        ("ttl_analysis",    check_ttl_analysis),
        ("ns_redundancy",   check_ns_redundancy),
        ("dkim",            check_dkim),
        ("bimi",            check_bimi),
        ("mta_sts",         check_mta_sts),
        ("open_relay",      check_open_relay),
        ("rbl_check",       check_rbl),
        ("cipher_suites",   check_cipher_suites),
        ("hsts",            check_hsts),
        ("ct_logs",         check_ct_logs),
        ("cookie_security", check_cookie_security),
        ("cms_fingerprint", check_cms_fingerprint),
        ("waf_detection",   check_waf),
        ("cloud_assets",    check_cloud_assets),
        ("subdomains",      check_subdomains),
        ("spf_hard_fail",   check_spf_hard_fail),
        ("dmarc_policy",    check_dmarc_policy),
    ]
    all_issues = []
    for key, fn in checks:
        try:
            log.info(f"[DeepScan] Running {key}...")
            r = fn(domain)
            results[key] = r
            issues = r.get("issues", [])
            for issue in issues:
                all_issues.append({"check": key, "issue": issue})
        except Exception as e:
            results[key] = {"error": str(e), "issues": []}
            log.error(f"[DeepScan] {key} failed: {e}")

    results["summary"] = {
        "total_checks": len(checks),
        "total_issues": len(all_issues),
        "all_issues": all_issues,
        "critical_count": sum(1 for i in all_issues if "CRITICAL" in i["issue"].upper()),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    log.info(f"[DeepScan] Complete — {len(all_issues)} issues found across {len(checks)} checks")
    return results
