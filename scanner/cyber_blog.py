"""
VoraGuard Cyber Blog Engine v2 — 29 Live Sources, Today-Only Filter
"""
import os,re,sys,json,time,email.utils,logging,requests
import xml.etree.ElementTree as ET
from datetime import datetime,timezone,timedelta
from pathlib import Path

VORAG_HOME=Path(os.environ.get("VORAG_HOME",Path.home()/"voraguard"))
BLOG_DIR=VORAG_HOME/"blogs"
BLOG_DIR.mkdir(parents=True,exist_ok=True)
log=logging.getLogger("vorag.blog")

LANGUAGES={
    "english":"English","eng":"English","hindi":"Hindi","hin":"Hindi",
    "malayalam":"Malayalam","mal":"Malayalam","tamil":"Tamil","tam":"Tamil",
    "telugu":"Telugu","tel":"Telugu","arabic":"Arabic","ara":"Arabic",
    "french":"French","fra":"French","german":"German","deu":"German",
    "spanish":"Spanish","esp":"Spanish","portuguese":"Portuguese","por":"Portuguese",
    "japanese":"Japanese","jpn":"Japanese","chinese":"Chinese","chi":"Chinese",
    "korean":"Korean","kor":"Korean","russian":"Russian","rus":"Russian",
    "turkish":"Turkish","tur":"Turkish","urdu":"Urdu","urd":"Urdu",
    "bengali":"Bengali","ben":"Bengali","kannada":"Kannada","kan":"Kannada",
    "marathi":"Marathi","mar":"Marathi","punjabi":"Punjabi","pun":"Punjabi",
    "gujarati":"Gujarati","guj":"Gujarati","odia":"Odia","ori":"Odia",
    "thai":"Thai","tha":"Thai","vietnamese":"Vietnamese","vie":"Vietnamese",
    "indonesian":"Indonesian","ind":"Indonesian","persian":"Persian","fas":"Persian",
}
LANG_ISO={
    "English":"en","Hindi":"hi","Malayalam":"ml","Tamil":"ta","Telugu":"te",
    "Arabic":"ar","French":"fr","German":"de","Spanish":"es","Portuguese":"pt",
    "Japanese":"ja","Chinese":"zh","Korean":"ko","Russian":"ru","Turkish":"tr",
    "Urdu":"ur","Bengali":"bn","Kannada":"kn","Marathi":"mr","Punjabi":"pa",
    "Gujarati":"gu","Odia":"or","Thai":"th","Vietnamese":"vi",
    "Indonesian":"id","Persian":"fa",
}

def resolve_lang(lang_input:str)->tuple:
    key=lang_input.lower().strip()
    name=LANGUAGES.get(key,"English")
    iso=LANG_ISO.get(name,"en")
    return name,iso

MITRE_TAGS={
    "T1566":("Phishing",["phishing","spear phish","spearphish","email attack"]),
    "T1190":("Exploit Public App",["exploit","cve-","zero-day","0-day","rce","remote code execution"]),
    "T1486":("Ransomware",["ransomware","encrypt files","ransom","lockbit","blackcat","cl0p","akira","rhysida"]),
    "T1078":("Valid Accounts",["credential","stolen cred","password spray","brute force"]),
    "T1059":("Command & Scripting",["powershell","bash shell","python script","cmd.exe"]),
    "T1071":("C2 Communication",["c2","command and control","cobalt strike","beacon"]),
    "T1498":("DDoS",["ddos","denial of service","botnet flood"]),
    "T1195":("Supply Chain",["supply chain","third party","dependency confusion","npm package","pypi"]),
    "T1046":("Network Scanning",["scan","shodan","internet-facing","open port exposed"]),
    "T1133":("External Remote Svcs",["vpn exploit","rdp attack","ssh bruteforce","citrix exploit"]),
    "T1505":("Web Shell",["webshell","web shell","sql injection","sqli","xss attack"]),
    "T1003":("Credential Dumping",["lsass","mimikatz","credential dump","ntlm"]),
}

def tag_mitre(text:str)->list:
    tl=text.lower()
    return [(tid,tname) for tid,(tname,kws) in MITRE_TAGS.items() if any(k in tl for k in kws)][:3]

def _is_recent(date_str:str,hours:int=36)->bool:
    if not date_str: return False
    now=datetime.now(timezone.utc)
    cutoff=now-timedelta(hours=hours)
    parsed=None
    try:
        parsed=datetime(*email.utils.parsedate(date_str)[:6],tzinfo=timezone.utc)
    except Exception:
        pass
    if parsed is None:
        for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%Y-%m-%d"):
            try:
                parsed=datetime.strptime(date_str[:19].replace("Z","").replace("T"," ")[:len(fmt)],fmt).replace(tzinfo=timezone.utc)
                break
            except Exception:
                continue
    if parsed is None: return False
    return parsed>=cutoff

HDRS={"User-Agent":"VoraGuard/3.0 CyberBlog"}

def _get(url,params=None,timeout=12):
    try: return requests.get(url,headers=HDRS,params=params or {},timeout=timeout)
    except Exception as e: log.debug(f"GET {url}: {e}"); return None

def _post(url,data=None,timeout=12):
    try: return requests.post(url,data=data or {},headers=HDRS,timeout=timeout)
    except Exception as e: log.debug(f"POST {url}: {e}"); return None

def _parse_rss(content:bytes,src:str,cat:str,hours:int=36)->list:
    items=[]
    try:
        root=ET.fromstring(content)
        ns={"atom":"http://www.w3.org/2005/Atom","dc":"http://purl.org/dc/elements/1.1/"}
        entries=root.findall(".//item") or root.findall(".//atom:entry",ns)
        for e in entries:
            title=(e.findtext("title") or e.findtext("atom:title",namespaces=ns) or "").strip()
            title=re.sub(r'<[^>]+>','',title)
            pubdate=(e.findtext("pubDate") or e.findtext("dc:date",namespaces=ns) or
                     e.findtext("atom:updated",namespaces=ns) or e.findtext("atom:published",namespaces=ns) or "")
            if not _is_recent(pubdate,hours): continue
            summary=re.sub(r'<[^>]+>','',(e.findtext("description") or
                           e.findtext("atom:summary",namespaces=ns) or "").strip())[:500]
            link=(e.findtext("link") or "")
            if not title: continue
            tl=title.lower()+" "+summary.lower()
            sev=("CRITICAL" if any(k in tl for k in ["critical","zero-day","0-day","ransomware","nation-state","apt","actively exploit"])
                 else "HIGH" if any(k in tl for k in ["exploit","vulnerability","cve-","rce","backdoor","malware","attack","breach"])
                 else "MEDIUM" if any(k in tl for k in ["patch","update","warning","phishing"])
                 else "LOW")
            items.append({"source":src,"category":cat,"type":"news","title":title,
                          "summary":summary[:400],"url":link,"date":pubdate[:25],
                          "severity":sev,"mitre":tag_mitre(title+" "+summary),"today":True})
    except Exception as e: log.debug(f"RSS {src}: {e}")
    return items

RSS_SOURCES=[
    ("BleepingComputer","https://www.bleepingcomputer.com/feed/","global_news"),
    ("The Hacker News","https://feeds.feedburner.com/TheHackersNews","global_news"),
    ("Krebs on Security","https://krebsonsecurity.com/feed/","global_news"),
    ("Dark Reading","https://www.darkreading.com/rss.xml","global_news"),
    ("The Record","https://therecord.media/feed","global_news"),
    ("SecurityWeek","https://www.securityweek.com/feed/","global_news"),
    ("SANS ISC","https://isc.sans.edu/rssfeed_full.xml","threat_intel"),
    ("Cisco Talos","https://blog.talosintelligence.com/feeds/posts/default","threat_intel"),
    ("Unit 42 (Palo Alto)","https://unit42.paloaltonetworks.com/feed/","threat_intel"),
    ("Mandiant","https://www.mandiant.com/resources/blog/rss.xml","threat_intel"),
    ("Check Point Research","https://research.checkpoint.com/feed/","threat_intel"),
    ("CrowdStrike","https://www.crowdstrike.com/blog/feed/","threat_intel"),
    ("Kaspersky Securelist","https://securelist.com/feed/","threat_intel"),
    ("Sophos","https://news.sophos.com/en-us/feed/","threat_intel"),
    ("Microsoft MSRC","https://msrc.microsoft.com/blog/feed","threat_intel"),
    ("Google Project Zero","https://googleprojectzero.blogspot.com/feeds/posts/default","threat_intel"),
    ("Trend Micro","https://blog.trendmicro.com/feed/","threat_intel"),
    ("Malwarebytes","https://blog.malwarebytes.com/feed/","threat_intel"),
    ("ESET WeLiveSecurity","https://www.welivesecurity.com/en/feed/","threat_intel"),
    ("CERT-In India","https://www.cert-in.org.in/RSS/advisories.xml","india"),
    ("Indian Express Tech","https://indianexpress.com/section/technology/feed/","india"),
    ("Economic Times Tech","https://economictimes.indiatimes.com/tech/rss/latest","india"),
    ("NDTV Tech","https://feeds.feedburner.com/ndtvnews-tech-news","india"),
    ("Recorded Future Blog","https://www.recordedfuture.com/feed","threat_intel"),
    ("Threatpost","https://threatpost.com/feed/","global_news"),
    ("Cyware","https://cyware.com/news/rss","global_news"),
    ("SecurityAffairs","https://securityaffairs.com/feed","global_news"),
    ("HackerNews","https://thehackernews.com/feeds/posts/default","global_news"),
    ("GBHackers","https://gbhackers.com/feed/","global_news"),
]

def fetch_all_rss(hours:int=36)->list:
    log.info(f"[RSS] Fetching {len(RSS_SOURCES)} feeds...")
    all_items=[]
    for name,url,cat in RSS_SOURCES:
        r=_get(url,timeout=10)
        if r and r.status_code==200:
            items=_parse_rss(r.content,name,cat,hours)
            all_items.extend(items)
            if items: log.debug(f"  {name}: {len(items)} today")
        time.sleep(0.1)
    log.info(f"[RSS] Total: {len(all_items)} today items")
    return all_items

def fetch_cisa_kev(hours:int=36)->list:
    log.info("[API] CISA KEV...")
    items=[]
    r=_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",timeout=15)
    if not r or r.status_code!=200: return items
    try:
        for v in r.json().get("vulnerabilities",[]):
            da=v.get("dateAdded","")
            if not _is_recent(da,hours): continue
            items.append({"source":"CISA KEV","category":"exploited_vuln","type":"exploited_vulnerability",
                "title":f"{v.get('cveID','')} — {v.get('vulnerabilityName','')}",
                "summary":v.get("shortDescription","")[:400],
                "severity":"CRITICAL","cve":v.get("cveID",""),
                "action":v.get("requiredAction",""),"due_date":v.get("dueDate",""),
                "date":da,"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "mitre":tag_mitre(v.get("shortDescription","")),"today":True})
    except Exception as e: log.error(f"CISA KEV: {e}")
    log.info(f"[API] CISA KEV: {len(items)} today")
    return items

def fetch_nvd_today(hours:int=36)->list:
    log.info("[API] NVD CVEs today...")
    items=[]
    now=datetime.now(timezone.utc)
    r=_get("https://services.nvd.nist.gov/rest/json/cves/2.0",
           params={"pubStartDate":(now-timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                   "pubEndDate":now.strftime("%Y-%m-%dT%H:%M:%S.000"),"resultsPerPage":20},timeout=15)
    if not r or r.status_code!=200: return items
    try:
        for vuln in r.json().get("vulnerabilities",[]):
            cve=vuln.get("cve",{})
            cid=cve.get("id","")
            desc=next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"),"")
            score,sev=0,"MEDIUM"
            for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                m=cve.get("metrics",{})
                if key in m and m[key]:
                    d=m[key][0].get("cvssData",{})
                    score=d.get("baseScore",0); sev=str(d.get("baseSeverity","MEDIUM")).upper(); break
            refs=cve.get("references",[])
            url=refs[0].get("url","") if refs else ""
            items.append({"source":"NVD","category":"cve","type":"cve",
                "title":f"{cid} [CVSS {score}] — {desc[:80]}","summary":desc[:400],
                "severity":sev if sev in ("CRITICAL","HIGH","MEDIUM","LOW") else "MEDIUM",
                "cvss_score":score,"cve":cid,"date":cve.get("published","")[:10],
                "url":url or f"https://nvd.nist.gov/vuln/detail/{cid}",
                "mitre":tag_mitre(desc),"today":True})
    except Exception as e: log.error(f"NVD: {e}")
    log.info(f"[API] NVD: {len(items)} today")
    return items

def fetch_cisa_advisories(hours:int=36)->list:
    log.info("[API] CISA Advisories...")
    r=_get("https://www.cisa.gov/cybersecurity-advisories/all.xml",timeout=12)
    if not r or r.status_code!=200: return []
    items=_parse_rss(r.content,"CISA Advisory","gov_advisory",hours)
    for i in items: i["severity"]="HIGH"; i["type"]="government_advisory"
    log.info(f"[API] CISA: {len(items)} today")
    return items

def fetch_otx_today(hours:int=36)->list:
    log.info("[API] OTX today...")
    items=[]
    api_key=(os.environ.get("OTX_API_KEY") or "").split("#")[0].strip()
    if not api_key: return items
    r=_get("https://otx.alienvault.com/api/v1/pulses/activity",
           params={"limit":20,"modified_since":(datetime.now(timezone.utc)-timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")},
           timeout=15)
    if not r or r.status_code!=200:
        r=_get("https://otx.alienvault.com/api/v1/pulses/subscribed",
               params={"limit":20,"page":1},timeout=15)
    if not r or r.status_code!=200: return items
    try:
        for p in r.json().get("results",[]):
            created=p.get("created","") or p.get("modified","")
            if not _is_recent(created,hours): continue
            fams=p.get("malware_families",[])[:3]
            ctrs=p.get("targeted_countries",[])[:5]
            iocs=len(p.get("indicators",[]))
            text=p.get("name","")+" "+(p.get("description","") or "")
            items.append({"source":"AlienVault OTX","category":"threat_intel","type":"threat_pulse",
                "title":p.get("name",""),"summary":(p.get("description","") or "")[:400],
                "severity":"CRITICAL" if fams else "HIGH","date":created[:10],
                "malware":fams,"countries":ctrs,"ioc_count":iocs,"tlp":p.get("tlp","white"),
                "url":f"https://otx.alienvault.com/pulse/{p.get('id','')}",
                "mitre":tag_mitre(text),"today":True})
    except Exception as e: log.error(f"OTX: {e}")
    log.info(f"[API] OTX: {len(items)} today")
    return items

def fetch_urlhaus_today()->list:
    log.info("[API] URLhaus 24h...")
    items=[]
    r=_get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/",timeout=12)
    if not r or r.status_code!=200: return items
    try:
        for u in r.json().get("urls",[]):
            da=u.get("date_added","")
            if not _is_recent(da,36): continue
            tags=u.get("tags") or []
            items.append({"source":"URLhaus","category":"malware","type":"malware_url",
                "title":f"Live malware URL: {u.get('host','')} [{', '.join(tags) or u.get('threat','')}]",
                "summary":f"URL: {u.get('url','')[:80]} | Status: {u.get('url_status','')}",
                "severity":"HIGH","date":da[:10],"url":u.get("urlhaus_reference",""),
                "tags":tags,"mitre":[("T1588","Malware Distribution")],"today":True})
    except Exception as e: log.error(f"URLhaus: {e}")
    log.info(f"[API] URLhaus: {len(items)} today")
    return items

def fetch_malwarebazaar_today()->list:
    log.info("[API] MalwareBazaar 24h...")
    items=[]
    try:
        r=requests.post("https://mb-api.abuse.ch/api/v1/",data={"query":"get_recent","selector":"100"},
                        headers=HDRS,timeout=12)
        if not r or r.status_code!=200: return items
        for s in r.json().get("data",[]):
            seen=s.get("first_seen","")
            if not _is_recent(seen,36): continue
            fam=s.get("signature","Unknown"); ftype=s.get("file_type",""); tags=s.get("tags") or []
            items.append({"source":"MalwareBazaar","category":"malware","type":"malware_sample",
                "title":f"New malware: {fam} ({ftype})",
                "summary":f"File: {s.get('file_name','')[:40]} | Tags: {', '.join(tags[:4])} | SHA256: {s.get('sha256_hash','')[:16]}...",
                "severity":"HIGH","date":seen[:10],"family":fam,
                "url":f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash','')}",
                "mitre":[("T1588","Acquire Malware")],"today":True})
    except Exception as e: log.error(f"MalwareBazaar: {e}")
    log.info(f"[API] MalwareBazaar: {len(items)} today")
    return items

def fetch_shodan_trends()->list:
    log.info("[API] Shodan...")
    items=[]
    api_key=(os.environ.get("SHODAN_API_KEY") or "").split("#")[0].strip()
    if not api_key: return items
    queries=[
        ("vuln:CVE-2024 country:IN","Vulnerable Indian hosts (2024 CVEs)"),
        ("port:3389 country:IN","RDP exposed India"),
        ("has_vuln:true country:IN","All vulnerable hosts India"),
        ("port:3389","RDP exposed globally"),
        ("port:6379 protected-mode no","Unsecured Redis globally"),
    ]
    for query,label in queries[:4]:
        r=_get("https://api.shodan.io/shodan/host/count",
               params={"key":api_key,"query":query},timeout=10)
        if r and r.status_code==200:
            count=r.json().get("total",0)
            items.append({"source":"Shodan","category":"internet_exposure","type":"exposure",
                "title":f"{count:,} hosts: {label}","summary":f"Query: {query}",
                "severity":"HIGH" if count>50000 else "MEDIUM",
                "date":datetime.now().strftime("%Y-%m-%d"),"count":count,
                "url":f"https://www.shodan.io/search?query={requests.utils.quote(query)}",
                "mitre":[("T1046","Network Service Scanning")],"today":True})
        time.sleep(0.5)
    log.info(f"[API] Shodan: {len(items)}")
    return items

def translate(text:str,target_iso:str)->str:
    if target_iso=="en" or not text.strip(): return text
    try:
        r=requests.get("https://translate.googleapis.com/translate_a/single",
            params={"client":"gtx","sl":"en","tl":target_iso,"dt":"t","q":text[:4500]},
            headers={"User-Agent":"Mozilla/5.0"},timeout=10)
        if r.status_code==200:
            out="".join(c[0] for c in r.json()[0] if c and c[0])
            return out if out else text
    except Exception: pass
    return text

def _build_blog(all_items:list,lang_name:str,lang_iso:str,date_str:str)->dict:
    cats={"breaking":[],"exploited":[],"cves_today":[],"ransomware":[],"apt_nation":[],
          "india":[],"malware":[],"vendor_intel":[],"advisories":[],"exposure":[],"general":[]}
    for item in all_items:
        cat=item.get("category",""); sev=item.get("severity","MEDIUM")
        tl=(item.get("title","")+" "+item.get("summary","")).lower()
        src=item.get("source","").lower()
        if cat=="exploited_vuln": cats["exploited"].append(item)
        elif cat=="cve": cats["cves_today"].append(item)
        elif cat=="malware": cats["malware"].append(item)
        elif cat=="internet_exposure": cats["exposure"].append(item)
        elif cat=="gov_advisory" or "cert" in src or "cisa" in src: cats["advisories"].append(item)
        elif cat=="india" or any(k in tl for k in ["india","indian","cert-in","nciipc","meity"]):
            cats["india"].append(item)
        elif any(k in tl for k in ["ransomware","lockbit","blackcat","cl0p","akira","rhysida","play ransom"]):
            cats["ransomware"].append(item)
        elif any(k in tl for k in ["apt","nation-state","state-sponsored","lazarus","volt typhoon",
                                    "fancy bear","sandworm","cyber espionage","intelligence operation"]):
            cats["apt_nation"].append(item)
        elif cat=="threat_intel" or any(k in src for k in ["talos","unit 42","mandiant","crowdstrike",
                                        "kaspersky","check point","sophos","eset","trend micro",
                                        "malwarebytes","google project","recorded future"]):
            cats["vendor_intel"].append(item)
        elif sev=="CRITICAL": cats["breaking"].append(item)
        else: cats["general"].append(item)
    sev_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    for k in cats: cats[k].sort(key=lambda x:sev_order.get(x.get("severity","MEDIUM"),2))

    total=len(all_items)
    critical=sum(1 for i in all_items if i.get("severity")=="CRITICAL")
    high=sum(1 for i in all_items if i.get("severity")=="HIGH")
    sources=sorted(set(i.get("source","") for i in all_items))
    top3=[i["title"] for i in all_items if i.get("severity")=="CRITICAL"][:3]
    summary_en=(f"Cyber threat intelligence digest for {date_str}. {total} live items from {len(sources)} sources. "
                f"{critical} CRITICAL and {high} HIGH severity events in the last 36 hours. "
                f"Top threats: {'; '.join(top3) if top3 else 'No new CRITICAL threats in this window'}. "
                f"All items are from today only — no recycled or old news.")
    section_defs=[
        ("🔴 BREAKING — Active Threats Today",           cats["breaking"],     6),
        ("🚨 CISA KEV — Actively Exploited (Patch NOW)", cats["exploited"],    8),
        ("🦠 Ransomware & Extortion Campaigns",          cats["ransomware"],   6),
        ("🕵 APT & Nation-State Operations",             cats["apt_nation"],   6),
        ("🇮🇳 India Cyber Threat Landscape",             cats["india"],        8),
        ("🔓 New CVEs Today (NVD — Last 36h)",           cats["cves_today"],   8),
        ("☣️  Live Malware (URLhaus + MalwareBazaar)",   cats["malware"],      6),
        ("🏛️  Government Advisories",                    cats["advisories"],   6),
        ("🌐 Internet Exposure (Shodan)",                 cats["exposure"],     4),
        ("🔬 Vendor Threat Intel (Talos/Unit42/Mandiant/etc)", cats["vendor_intel"],8),
        ("📰 Cyber Security Headlines",                  cats["general"],      8),
    ]
    sections_en=[{"title_en":t,"items":i[:n],"count":len(i)} for t,i,n in section_defs if i]
    if lang_iso!="en":
        log.info(f"[Blog] Translating to {lang_name}...")
        summary_out=translate(summary_en,lang_iso)
        sections_out=[{"title":translate(s["title_en"],lang_iso),"title_en":s["title_en"],
                        "items":s["items"],"count":s["count"]} for s in sections_en]
    else:
        summary_out=summary_en
        sections_out=[{"title":s["title_en"],"title_en":s["title_en"],
                        "items":s["items"],"count":s["count"]} for s in sections_en]
    return {"date":date_str,"language":lang_name,"language_iso":lang_iso,
            "total_items":total,"total_critical":critical,"total_high":high,
            "sources_count":len(sources),"sources_used":sources,
            "executive_summary":summary_out,"executive_summary_en":summary_en,
            "sections":sections_out,"raw_items":all_items,"hours_window":36,"today_only":True}

def generate_blog(lang:str="english",force_refresh:bool=False,hours:int=36)->dict:
    lang_name,lang_iso=resolve_lang(lang)
    date_str=datetime.now().strftime("%Y-%m-%d")
    blog_id=datetime.now().strftime("%Y%m%d_%H%M%S")
    cache_file=BLOG_DIR/f"cache_{date_str}_{lang_iso}.json"
    if not force_refresh and cache_file.exists():
        age=time.time()-cache_file.stat().st_mtime
        if age<3600:
            try:
                c=json.loads(cache_file.read_text())
                c["from_cache"]=True; c["cache_age_min"]=int(age//60); return c
            except Exception: pass
    log.info(f"[Blog] Generating | lang={lang_name} | {date_str}")
    all_items=[]
    for f in [lambda:fetch_all_rss(hours),lambda:fetch_cisa_kev(hours),
              lambda:fetch_nvd_today(hours),lambda:fetch_cisa_advisories(hours),
              lambda:fetch_otx_today(hours),lambda:fetch_urlhaus_today(),
              lambda:fetch_malwarebazaar_today(),lambda:fetch_shodan_trends()]:
        try: all_items.extend(f())
        except Exception as e: log.error(f"Fetcher: {e}")
    seen=set(); deduped=[]
    for item in all_items:
        key=re.sub(r'[^a-z0-9]','',item.get("title","").lower())[:60]
        if key not in seen: seen.add(key); deduped.append(item)
    log.info(f"[Blog] {len(all_items)} raw → {len(deduped)} deduped")
    blog=_build_blog(deduped,lang_name,lang_iso,date_str)
    blog["blog_id"]=blog_id
    blog["generated_at"]=datetime.now(timezone.utc).isoformat()
    blog["from_cache"]=False; blog["cache_age_min"]=0
    jp=BLOG_DIR/f"blog_{blog_id}_{lang_iso}.json"
    jp.write_text(json.dumps(blog,indent=2,default=str))
    blog["json_path"]=str(jp)
    cache_file.write_text(json.dumps(blog,indent=2,default=str))
    return blog

SEV_COLOR={"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#f59e0b","LOW":"#22c55e"}
SEV_BG={"CRITICAL":"rgba(239,68,68,0.1)","HIGH":"rgba(249,115,22,0.08)",
        "MEDIUM":"rgba(245,158,11,0.08)","LOW":"rgba(34,197,94,0.08)"}

def generate_blog_html(blog:dict)->str:
    lang=blog.get("language","English"); lang_iso=blog.get("language_iso","en")
    date_str=blog.get("date",""); sections=blog.get("sections",[])
    summary=blog.get("executive_summary",""); total=blog.get("total_items",0)
    critical=blog.get("total_critical",0); high=blog.get("total_high",0)
    sources=blog.get("sources_used",[]); blog_id=blog.get("blog_id","")
    cached=blog.get("from_cache",False); cache_age=blog.get("cache_age_min",0)
    gen_at=blog.get("generated_at","")[:19]; hours_win=blog.get("hours_window",36)
    rtl_langs={"ar","ur","fa","he"}; direction="rtl" if lang_iso in rtl_langs else "ltr"
    live_badge=(f'<span class="live-badge">📦 Cached ({cache_age}min)</span>' if cached
                else '<span class="live-badge live">🔴 LIVE</span>')

    def item_html(item):
        sev=item.get("severity","MEDIUM"); col=SEV_COLOR.get(sev,"#64748b")
        bg=SEV_BG.get(sev,"rgba(100,116,139,0.05)")
        src=item.get("source",""); url=item.get("url",""); title=item.get("title","")
        smry=item.get("summary","")[:300]; dt=item.get("date","")[:10]
        cve=item.get("cve",""); act=item.get("action",""); due=item.get("due_date","")
        mitre=item.get("mitre",[]); ctrs=item.get("countries",[]); malware=item.get("malware",[])
        mitre_t="".join(f'<span class="mitre-tag">{t[0]}: {t[1]}</span>' for t in mitre)
        ctr_t="".join(f'<span class="country-tag">🎯{c}</span>' for c in ctrs[:3])
        mal_t="".join(f'<span class="malware-tag">☣️{m}</span>' for m in malware[:2])
        ttl_html=f'<a href="{url}" target="_blank">{title}</a>' if url else title
        iocs=item.get("ioc_count",0)
        return (f'<div class="item-card" style="border-left:3px solid {col};background:{bg}">'
                f'<div class="item-meta"><span class="sev-badge" style="background:{col}">{sev}</span>'
                f'<span class="item-src">{src}</span><span class="item-date">{dt}</span>'
                f'{"<span class=cve-tag>"+cve+"</span>" if cve else ""}</div>'
                f'<div class="item-title">{ttl_html}</div>'
                f'{"<div class=item-summary>"+smry+"</div>" if smry else ""}'
                f'<div class="item-tags">{mitre_t}{ctr_t}{mal_t}'
                f'{"<span class=ioc-tag>📌 "+str(iocs)+" IOCs</span>" if iocs else ""}</div>'
                f'{"<div class=item-action>⚡ "+act+"</div>" if act else ""}'
                f'{"<div class=item-due>📅 CISA Deadline: "+due+"</div>" if due else ""}'
                f'</div>')

    def section_html(sec):
        items=sec.get("items",[]); title=sec.get("title",""); count=sec.get("count",len(items))
        if not items: return ""
        cards="".join(item_html(i) for i in items)
        return (f'<section class="blog-section">'
                f'<h2 class="section-title">{title} <span class="section-count">{count} items</span></h2>'
                f'<div class="items-list">{cards}</div></section>')

    sec_html="".join(section_html(s) for s in sections)
    src_pills="".join(f'<span class="src-pill">{s}</span>' for s in sources)

    return f"""<!DOCTYPE html>
<html lang="{lang_iso}" dir="{direction}">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoraGuard Cyber Intel — {date_str} [{lang}]</title>
<style>
:root{{--bg:#080d1a;--bg2:#0c1222;--bg3:#111827;--bg4:#1e293b;--border:rgba(148,163,184,0.08);--text:#e2e8f0;--muted:#64748b;--cyan:#22d3ee;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.65;}}
a{{color:var(--cyan);text-decoration:none;}}a:hover{{text-decoration:underline;}}
.topbar{{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 40px;display:flex;align-items:center;gap:16px;font-size:12px;color:var(--muted);}}
.brand{{font-weight:800;color:var(--cyan);font-size:14px;}}
.live-badge{{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;background:rgba(100,116,139,0.15);color:var(--muted);}}
.live-badge.live{{background:rgba(239,68,68,0.15);color:#ef4444;animation:pulse 2s infinite;}}
@keyframes pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.6;}}}}
.hero{{background:linear-gradient(135deg,#0c1222,#0f0c2a,#0c1222);padding:36px 40px 28px;border-bottom:1px solid var(--border);}}
.hero-title{{font-size:28px;font-weight:900;background:linear-gradient(90deg,#22d3ee,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
.hero-sub{{color:var(--muted);font-size:13px;margin-top:6px;margin-bottom:22px;}}
.hero-stats{{display:flex;gap:12px;flex-wrap:wrap;}}
.stat{{background:var(--bg3);border:1px solid var(--border);border-radius:12px;padding:12px 20px;min-width:80px;text-align:center;}}
.stat-num{{font-size:28px;font-weight:800;}}.stat-label{{font-size:10px;color:var(--muted);margin-top:2px;}}
.summary{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:18px 26px;margin:20px 40px;font-size:14px;color:#94a3b8;line-height:1.75;}}
.summary strong{{color:var(--text);}}
.sources-bar{{margin:0 40px 6px;display:flex;flex-wrap:wrap;gap:5px;align-items:center;font-size:11px;}}
.src-label{{color:var(--muted);margin-right:4px;font-weight:600;}}
.src-pill{{background:var(--bg3);color:var(--muted);padding:2px 7px;border-radius:999px;font-size:10px;border:1px solid var(--border);}}
.content{{max-width:960px;margin:0 auto;padding:8px 40px 60px;}}
.blog-section{{margin-bottom:40px;}}
.section-title{{font-size:17px;font-weight:700;color:var(--cyan);border-bottom:1px solid var(--border);padding-bottom:10px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;}}
.section-count{{font-size:11px;color:var(--muted);font-weight:400;}}
.items-list{{display:flex;flex-direction:column;gap:10px;}}
.item-card{{border-radius:10px;padding:14px 18px;transition:filter 0.15s;}}
.item-card:hover{{filter:brightness(1.1);}}
.item-meta{{display:flex;align-items:center;gap:8px;margin-bottom:7px;flex-wrap:wrap;}}
.sev-badge{{font-size:10px;font-weight:800;padding:2px 8px;border-radius:999px;color:#fff;letter-spacing:0.5px;}}
.item-src{{font-size:11px;color:var(--muted);}}.item-date{{font-size:11px;color:var(--muted);margin-left:auto;}}
.cve-tag{{font-size:11px;background:rgba(239,68,68,0.15);color:#ef4444;padding:2px 8px;border-radius:4px;font-weight:600;}}
.item-title{{font-size:14px;font-weight:600;color:var(--text);margin-bottom:5px;line-height:1.45;}}
.item-summary{{font-size:13px;color:#94a3b8;margin-bottom:6px;line-height:1.55;}}
.item-tags{{display:flex;flex-wrap:wrap;gap:5px;margin:5px 0;}}
.mitre-tag{{font-size:10px;background:rgba(129,140,248,0.15);color:#818cf8;padding:2px 7px;border-radius:4px;}}
.country-tag{{font-size:10px;background:rgba(34,211,238,0.1);color:#22d3ee;padding:2px 7px;border-radius:4px;}}
.malware-tag{{font-size:10px;background:rgba(239,68,68,0.12);color:#f87171;padding:2px 7px;border-radius:4px;}}
.ioc-tag{{font-size:10px;background:rgba(249,115,22,0.1);color:#fb923c;padding:2px 7px;border-radius:4px;}}
.item-action{{font-size:12px;color:#fbbf24;background:rgba(251,191,36,0.07);border-radius:6px;padding:5px 10px;margin-top:7px;}}
.item-due{{font-size:12px;color:#ef4444;background:rgba(239,68,68,0.07);border-radius:6px;padding:5px 10px;margin-top:4px;font-weight:600;}}
.footer{{text-align:center;padding:24px 40px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);line-height:1.8;}}
.no-items{{color:var(--muted);font-style:italic;font-size:13px;padding:24px 0;text-align:center;}}
@media(max-width:600px){{.hero,.summary,.sources-bar,.content{{padding-left:16px;padding-right:16px;}}}}
</style></head><body>
<div class="topbar">
  <span class="brand">⚔ VoraGuard</span>
  <span>Cyber Intelligence Blog</span>
  <span style="margin-left:auto;display:flex;gap:12px;align-items:center;">
    {live_badge}
    <span>Lang: <b style="color:var(--cyan)">{lang}</b></span>
    <span>{gen_at} UTC</span>
  </span>
</div>
<div class="hero">
  <div class="hero-title">Cyber Threat Intelligence — {date_str}</div>
  <div class="hero-sub">Last {hours_win}h only · {total} live items · {len(sources)} sources · MITRE ATT&amp;CK tagged · Today only — no recycled news</div>
  <div class="hero-stats">
    <div class="stat"><div class="stat-num" style="color:#ef4444">{critical}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat"><div class="stat-num" style="color:#f97316">{high}</div><div class="stat-label">HIGH</div></div>
    <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">TOTAL</div></div>
    <div class="stat"><div class="stat-num" style="color:#22d3ee">{len(sections)}</div><div class="stat-label">SECTIONS</div></div>
    <div class="stat"><div class="stat-num" style="color:#818cf8">{len(sources)}</div><div class="stat-label">SOURCES</div></div>
  </div>
</div>
<div class="summary"><strong>Executive Summary:</strong> {summary}</div>
<div class="sources-bar"><span class="src-label">Active sources:</span>{src_pills}</div>
<div class="content">
{sec_html if sec_html else '<div class="no-items">No items in the last 36h window. Run with --refresh or check: vorag keys</div>'}
</div>
<div class="footer">
  VoraGuard v3.0 · Cyber Intelligence Blog · {date_str} · {lang}<br>
  {', '.join(sources[:10])}{'...' if len(sources)>10 else ''}<br>
  MITRE ATT&amp;CK tagged · Last {hours_win}h only · Blog ID: {blog_id}
</div></body></html>"""

def save_blog_html(blog:dict)->str:
    path=BLOG_DIR/f"blog_{blog.get('blog_id','x')}_{blog.get('language_iso','en')}.html"
    path.write_text(generate_blog_html(blog),encoding="utf-8")
    return str(path)
