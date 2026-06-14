"""VoraGuard Alert Manager v6.0"""
import os, json, smtplib, requests, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home()/"voraguard"))
ALERT_DIR  = VORAG_HOME/"alerts"
ALERT_DIR.mkdir(parents=True, exist_ok=True)
ALERT_LOG  = ALERT_DIR/"alert_history.json"
log = logging.getLogger("vorag.alerts")
def _env(k,d=""): return os.environ.get(k,d)
def _fmt(a):
    return "[VoraGuard "+a.get("severity","")+"] "+a.get("attack_name","")+" | "+a.get("source_ip","")+" -> "+a.get("dest_ip","")+":"+str(a.get("port",""))+" | MITRE:"+a.get("mitre","")+" | "+str(a.get("timestamp",""))[:19]
def fire_alert(a):
    sev=a.get("severity","LOW")
    sm={"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    if sm.get(sev,0)<sm.get(_env("ALERT_MIN_SEVERITY","HIGH"),3): return
    msg=_fmt(a); res={}
    if _env("TELEGRAM_BOT_TOKEN") and _env("TELEGRAM_CHAT_ID"): res["telegram"]=_telegram(msg,a)
    if _env("SLACK_WEBHOOK_URL"): res["slack"]=_slack(msg,a)
    if _env("DISCORD_WEBHOOK_URL"): res["discord"]=_discord(msg,a)
    if _env("ALERT_EMAIL_USER") and _env("ALERT_EMAIL_TO"): res["email"]=_email(msg,a)
    if _env("ALERT_WEBHOOK_URL"): res["webhook"]=_webhook(a)
    _log(a,res); return res
def _telegram(msg,a):
    try:
        r=requests.post("https://api.telegram.org/bot"+_env("TELEGRAM_BOT_TOKEN")+"/sendMessage",json={"chat_id":_env("TELEGRAM_CHAT_ID"),"text":msg},timeout=8)
        return "sent" if r.status_code==200 else "error:"+str(r.status_code)
    except Exception as e: return "error:"+str(e)
def _slack(msg,a):
    try:
        c={"CRITICAL":"#ff0000","HIGH":"#ff6600","MEDIUM":"#ffaa00","LOW":"#00cc00"}.get(a.get("severity",""),"#808080")
        r=requests.post(_env("SLACK_WEBHOOK_URL"),json={"attachments":[{"color":c,"title":"VoraGuard Alert","text":msg}]},timeout=8)
        return "sent" if r.status_code==200 else "error:"+str(r.status_code)
    except Exception as e: return "error:"+str(e)
def _discord(msg,a):
    try:
        c={"CRITICAL":16711680,"HIGH":16744192,"MEDIUM":16763904,"LOW":52224}.get(a.get("severity",""),8421504)
        r=requests.post(_env("DISCORD_WEBHOOK_URL"),json={"embeds":[{"title":"VoraGuard Alert","description":msg,"color":c}]},timeout=8)
        return "sent" if r.status_code in(200,204) else "error:"+str(r.status_code)
    except Exception as e: return "error:"+str(e)
def _email(msg,a):
    try:
        m=MIMEMultipart(); m["From"]=_env("ALERT_EMAIL_USER"); m["To"]=_env("ALERT_EMAIL_TO"); m["Subject"]="[VoraGuard] "+a.get("severity","")+": "+a.get("attack_name","")
        m.attach(MIMEText(msg,"plain"))
        with smtplib.SMTP(_env("ALERT_EMAIL_HOST","smtp.gmail.com"),int(_env("ALERT_EMAIL_PORT","587")),timeout=10) as s:
            s.starttls(); s.login(_env("ALERT_EMAIL_USER"),_env("ALERT_EMAIL_PASS")); s.send_message(m)
        return "sent"
    except Exception as e: return "error:"+str(e)
def _sms(msg):
    try:
        r=requests.post("https://www.fast2sms.com/dev/bulkV2",headers={"authorization":_env("FAST2SMS_API_KEY")},json={"route":"v3","sender_id":"TXTIND","message":msg[:160],"language":"english","flash":0,"numbers":_env("SMS_ALERT_NUMBERS")},timeout=10)
        return "sent" if r.status_code==200 else "error:"+str(r.status_code)
    except Exception as e: return "error:"+str(e)
def _webhook(data):
    try:
        r=requests.post(_env("ALERT_WEBHOOK_URL"),json=data,timeout=8)
        return "sent" if r.status_code in(200,201,204) else "error:"+str(r.status_code)
    except Exception as e: return "error:"+str(e)
def _log(a,res):
    try:
        logs=json.loads(ALERT_LOG.read_text()) if ALERT_LOG.exists() else []
        logs.insert(0,{**a,"channels":res,"logged_at":datetime.now().isoformat()})
        ALERT_LOG.write_text(json.dumps(logs[:500],indent=2,default=str))
    except: pass
def get_alert_history(limit=50):
    try:
        if ALERT_LOG.exists(): return json.loads(ALERT_LOG.read_text())[:limit]
    except: pass
    return []
def get_alert_status():
    cfg=[]
    if _env("TELEGRAM_BOT_TOKEN") and _env("TELEGRAM_CHAT_ID"): cfg.append("telegram")
    if _env("DISCORD_WEBHOOK_URL"): cfg.append("discord")
    if _env("ALERT_EMAIL_USER"): cfg.append("email")
    if _env("ALERT_WEBHOOK_URL"): cfg.append("webhook")
    h=get_alert_history(10)
    return {"configured_channels":cfg,"total_channels":len(cfg),"min_severity":_env("ALERT_MIN_SEVERITY","HIGH"),
            "recent_alerts":len(h),"last_alert":h[0].get("logged_at","Never") if h else "Never",
            "setup":{"telegram":"Set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in ~/voraguard/.env","slack":"Set SLACK_WEBHOOK_URL","discord":"Set DISCORD_WEBHOOK_URL","email":"Set ALERT_EMAIL_USER ALERT_EMAIL_PASS ALERT_EMAIL_TO"}}
def test_alert(channel=None):
    d={"id":"test001","severity":"HIGH","attack_type":"syn_scan","attack_name":"SYN Scan Test","source_ip":"192.168.1.99","dest_ip":"10.0.0.1","port":22,"protocol":"TCP","mitre":"T1046","tactic":"Reconnaissance","description":"Test alert","timestamp":datetime.now().isoformat()}
    if channel:
        msg=_fmt(d)
        if channel=="telegram": return _telegram(msg,d)
        if channel=="slack": return _slack(msg,d)
        if channel=="discord": return _discord(msg,d)
        if channel=="email": return _email(msg,d)
    return fire_alert(d)
