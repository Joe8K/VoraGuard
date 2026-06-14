"""
VoraGuard Threat Actor Intelligence v6.0 - Live MITRE ATT&CK
Sources: MITRE ATT&CK STIX, AlienVault OTX, built-in DB
Developed by Jithu
"""
import os, re, json, time, logging, requests
from datetime import datetime, timezone
from pathlib import Path

VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))
ACTOR_DIR  = VORAG_HOME / "actors"
ACTOR_DIR.mkdir(parents=True, exist_ok=True)
ACTOR_DB   = ACTOR_DIR / "actor_db.json"
MITRE_CACHE= ACTOR_DIR / "mitre_groups.json"
log = logging.getLogger("vorag.actors")
HDR = {"User-Agent": "VoraGuard/6.0 ThreatIntel"}

# ── Built-in comprehensive actor DB ──────────────────────────────────────
BUILTIN_ACTORS = {
    "APT28": {
        "name":"APT28","aliases":["Fancy Bear","Sofacy","Strontium","Pawn Storm","Sednit","IRON TWILIGHT"],
        "country":"Russia","sponsor":"GRU (Russian Military Intelligence)","motivation":"Espionage, Sabotage",
        "active_since":"2004","risk":"CRITICAL","mitre_id":"G0007",
        "targets":["Government","Military","Defense","Political Parties","Media","NATO members"],
        "ttps":["T1566","T1078","T1190","T1059","T1071","T1027","T1082","T1016","T1057"],
        "tools":["X-Agent","Sofacy","CHOPSTICK","CORESHELL","Mimikatz","Empire"],
        "campaigns":["Olympic Destroyer","Operation Grizzly Steppe","DNC Hack 2016","Bundestag Hack"],
        "description":"Russian GRU Unit 26165. One of the most sophisticated APTs. Known for election interference, NATO targeting, and destructive attacks.",
    },
    "APT29": {
        "name":"APT29","aliases":["Cozy Bear","The Dukes","Nobelium","Midnight Blizzard","IRON HEMLOCK"],
        "country":"Russia","sponsor":"SVR (Russian Foreign Intelligence)","motivation":"Espionage, Intelligence Collection",
        "active_since":"2008","risk":"CRITICAL","mitre_id":"G0016",
        "targets":["Government","Think Tanks","Healthcare","Technology","Supply Chain"],
        "ttps":["T1566.001","T1078","T1195","T1090","T1027","T1059.001","T1071.001","T1560"],
        "tools":["SUNBURST","Cobalt Strike","MiniDuke","CosmicDuke","WellMess","BEATDROP"],
        "campaigns":["SolarWinds Supply Chain","Democratic Party Breach","COVID-19 Vaccine Research"],
        "description":"Russian SVR foreign intelligence. Highly sophisticated, long-term espionage. Responsible for SolarWinds supply chain attack affecting 18,000+ organizations.",
    },
    "Lazarus Group": {
        "name":"Lazarus Group","aliases":["Hidden Cobra","Guardians of Peace","ZINC","Nickel Academy","APT38"],
        "country":"North Korea","sponsor":"RGB (Reconnaissance General Bureau)","motivation":"Financial, Espionage, Disruption",
        "active_since":"2009","risk":"CRITICAL","mitre_id":"G0032",
        "targets":["Financial Institutions","Cryptocurrency","Defense","Government","Healthcare"],
        "ttps":["T1566","T1059","T1486","T1041","T1071","T1078","T1190","T1210"],
        "tools":["HOPLIGHT","ELECTRICFISH","BADCALL","FastCash","AppleJeus","WannaCry"],
        "campaigns":["Bangladesh Bank Heist ($81M)","WannaCry Ransomware","Sony Pictures Hack","Ronin Network ($625M crypto)"],
        "description":"North Korean state-sponsored group. Primary mission: generate foreign currency through cybercrime. Most prolific crypto theft group globally.",
    },
    "FIN7": {
        "name":"FIN7","aliases":["Carbanak","Navigator Group","ITG14","Carbon Spider"],
        "country":"Russia/Ukraine","sponsor":"Criminal Organization","motivation":"Financial",
        "active_since":"2013","risk":"CRITICAL","mitre_id":"G0046",
        "targets":["Retail","Hospitality","Restaurant","Financial Services","POS Systems"],
        "ttps":["T1566.001","T1059.005","T1059.001","T1071","T1027","T1056","T1074"],
        "tools":["CARBANAK","GRIFFON","BOOSTWRITE","RDFSNIFFER","Cobalt Strike","Metasploit"],
        "campaigns":["Chipotle Breach","Arby\'s Breach","Red Robin Breach","Chili\'s Breach"],
        "description":"Most prolific financially-motivated threat group. Stolen over $1 billion from 100+ US companies. Operates as a structured criminal enterprise.",
    },
    "APT41": {
        "name":"APT41","aliases":["Double Dragon","Winnti","Barium","Wicked Panda","Earth Baku"],
        "country":"China","sponsor":"MSS (Ministry of State Security)","motivation":"Espionage + Financial",
        "active_since":"2012","risk":"CRITICAL","mitre_id":"G0096",
        "targets":["Healthcare","Telecom","Technology","Video Games","Government","Supply Chain"],
        "ttps":["T1190","T1195","T1059","T1078","T1027","T1071","T1486","T1560"],
        "tools":["MESSAGETAP","POISONPLUG","Shadowpad","Deadeye","KeyBoy","HIGHNOON"],
        "campaigns":["Supply Chain Compromise 2017","COVID-19 Research Theft","US State Networks 2020"],
        "description":"Unique dual-mission group conducting state-sponsored espionage AND financially motivated cybercrime simultaneously. Indicted by US DOJ in 2020.",
    },
    "Sandworm": {
        "name":"Sandworm","aliases":["Voodoo Bear","ELECTRUM","Telebots","Iron Viking","Seashell Blizzard"],
        "country":"Russia","sponsor":"GRU Unit 74455","motivation":"Sabotage, Disruption",
        "active_since":"2009","risk":"CRITICAL","mitre_id":"G0034",
        "targets":["Critical Infrastructure","Energy","Government","Ukraine","NATO"],
        "ttps":["T1486","T1561","T1529","T1071","T1059","T1078","T1190","T1195"],
        "tools":["NotPetya","Industroyer","BlackEnergy","KillDisk","Olympic Destroyer","Cyclops Blink"],
        "campaigns":["Ukraine Power Grid Attacks","NotPetya ($10B damage)","Olympic Destroyer","Viasat Attack"],
        "description":"Most destructive threat actor in history. Responsible for NotPetya — the costliest cyberattack ever. Targets critical infrastructure for maximum disruption.",
    },
    "APT10": {
        "name":"APT10","aliases":["Stone Panda","MenuPass","Red Apollo","POTASSIUM","Cicada"],
        "country":"China","sponsor":"MSS Tianjin Bureau","motivation":"Espionage, IP Theft",
        "active_since":"2009","risk":"HIGH","mitre_id":"G0045",
        "targets":["Managed Service Providers","Healthcare","Government","Defense","Aerospace"],
        "ttps":["T1190","T1078","T1059","T1071","T1027","T1560","T1041"],
        "tools":["RedLeaves","QuasarRAT","PlugX","UPPERCUT","Cobalt Strike"],
        "campaigns":["Operation Cloud Hopper (MSP attacks)","Operation TradeSecret","Healthcare targeting"],
        "description":"Extensive MSP (Managed Service Provider) attacks to reach hundreds of client organizations simultaneously. Caused UK, US, Australian governments to issue joint advisory.",
    },
    "Equation Group": {
        "name":"Equation Group","aliases":["EQGRP","Tilted Temple"],
        "country":"USA","sponsor":"NSA TAO","motivation":"Espionage, Intelligence Collection",
        "active_since":"2001","risk":"CRITICAL","mitre_id":"G0020",
        "targets":["Government","Military","Telecom","Financial","Nuclear","Energy"],
        "ttps":["T1190","T1195","T1059","T1014","T1027","T1078"],
        "tools":["EternalBlue","EternalRomance","DOUBLEFANTASY","GRAYFISH","FANNY","EQUATIONDRUG"],
        "campaigns":["Shadow Brokers Leak","Stuxnet (with Unit 8200)","IRATEMONK","NOPEN"],
        "description":"Considered the most technically advanced threat actor ever discovered. Tools leaked by Shadow Brokers in 2017 led to WannaCry and NotPetya epidemics.",
    },
    "Kimsuky": {
        "name":"Kimsuky","aliases":["Thallium","Black Banshee","Velvet Chollima","APT43"],
        "country":"North Korea","sponsor":"RGB","motivation":"Espionage, Intelligence",
        "active_since":"2012","risk":"HIGH","mitre_id":"G0094",
        "targets":["South Korea","US Government","Think Tanks","Nuclear Policy","Human Rights"],
        "ttps":["T1566.001","T1059","T1078","T1071","T1027","T1113","T1056"],
        "tools":["BabyShark","AppleSeed","FlowerPower","GoldDragon","CSPY Downloader"],
        "campaigns":["Korea-focused espionage","Nuclear policy targeting","COVID-19 research theft"],
        "description":"North Korean intelligence gathering focused on Korean peninsula policy, nuclear issues, and sanctions. Extensive spear-phishing campaigns.",
    },
    "REvil": {
        "name":"REvil","aliases":["Sodinokibi","Pinchy Spider","Gold Southfield"],
        "country":"Russia","sponsor":"Criminal (RaaS)","motivation":"Financial - Ransomware",
        "active_since":"2019","risk":"HIGH","mitre_id":"G0115",
        "targets":["Any - opportunistic","Healthcare","Legal","Manufacturing","Technology"],
        "ttps":["T1486","T1490","T1489","T1078","T1027","T1059"],
        "tools":["REvil/Sodinokibi","Cobalt Strike","Mimikatz"],
        "campaigns":["Kaseya VSA ($70M ransom)","JBS Foods ($11M)","Travelex ($6M)","Acer ($50M demand)"],
        "description":"Ransomware-as-a-Service group. Highest ransom demands in history. Disrupted by RU-US cooperation in 2022 with several members arrested.",
    },
    "Cl0p": {
        "name":"Cl0p","aliases":["TA505","FIN11","Lace Tempest"],
        "country":"Russia/Ukraine","sponsor":"Criminal","motivation":"Financial - Ransomware/Extortion",
        "active_since":"2019","risk":"HIGH","mitre_id":"G0092",
        "targets":["Financial","Healthcare","Manufacturing","Technology","Education"],
        "ttps":["T1190","T1486","T1041","T1078","T1059","T1027"],
        "tools":["Cl0p ransomware","SDBOT","FlawedAmmyy","Get2"],
        "campaigns":["MOVEit Transfer mass exploitation (2023)","GoAnywhere MFT (2023)","Accellion FTA","SolarWinds Orion"],
        "description":"Exploits file transfer software vulnerabilities for mass data theft. MOVEit attack affected 2,600+ organizations including US government agencies.",
    },
    "Volt Typhoon": {
        "name":"Volt Typhoon","aliases":["Bronze Silhouette","Vanguard Panda","Dev-0391"],
        "country":"China","sponsor":"PLA/MSS","motivation":"Pre-positioning for disruption",
        "active_since":"2021","risk":"CRITICAL","mitre_id":"G1017",
        "targets":["US Critical Infrastructure","Military","Utilities","Communications","Transportation"],
        "ttps":["T1078","T1190","T1133","T1059","T1071","T1036","T1014","T1560"],
        "tools":["Living off the Land","KV-Botnet","WinRAR","Impacket"],
        "campaigns":["US Critical Infrastructure Pre-positioning","Guam Military Networks","Pacific infrastructure"],
        "description":"URGENT: Pre-positioning in US critical infrastructure for potential disruption during conflict. US/UK/AUS/CA/NZ joint advisory issued. Focus on living-off-the-land techniques.",
    },
    "Salt Typhoon": {
        "name":"Salt Typhoon","aliases":["GhostEmperor","FamousSparrow","Earth Estries"],
        "country":"China","sponsor":"MSS","motivation":"Espionage - Telecom Intelligence",
        "active_since":"2019","risk":"CRITICAL","mitre_id":"G1020",
        "targets":["US Telecom Carriers","Internet Service Providers","Government Communications"],
        "ttps":["T1190","T1078","T1059","T1071","T1027","T1560","T1041"],
        "tools":["GhostSpider","Masol RAT","Demodex","SparrowDoor"],
        "campaigns":["US Telecom Breach 2024 (AT&T,Verizon,T-Mobile)","Wiretap system access","9 carriers compromised"],
        "description":"ACTIVE 2024-2025: Breached major US telecom carriers including AT&T, Verizon, T-Mobile. Accessed court-authorized wiretap systems. Described as worst telecom hack in US history.",
    },
}

# ── Load/save helpers ─────────────────────────────────────────────────────
def _load(p):
    try:
        if Path(p).exists(): return json.loads(Path(p).read_text())
    except: pass
    return {}

def _save(p, d):
    try: Path(p).write_text(json.dumps(d, indent=2, default=str))
    except: pass

def _get_db():
    db = _load(ACTOR_DB)
    if not db:
        db = BUILTIN_ACTORS.copy()
        _save(ACTOR_DB, db)
    else:
        # Merge builtins for any missing actors
        for k, v in BUILTIN_ACTORS.items():
            if k not in db:
                db[k] = v
        _save(ACTOR_DB, db)
    return db

# ── Sync with MITRE ATT&CK live ──────────────────────────────────────────
def sync_mitre_actors():
    cache = _load(MITRE_CACHE)
    if cache and time.time() - cache.get("_ts", 0) < 86400:
        return cache.get("groups", [])
    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        r = requests.get(url, headers=HDR, timeout=30)
        if r.status_code == 200:
            data = r.json()
            groups = []
            for obj in data.get("objects", []):
                if obj.get("type") == "intrusion-set" and not obj.get("revoked"):
                    aliases = obj.get("aliases", [])
                    groups.append({
                        "mitre_id": next((ref["external_id"] for ref in obj.get("external_references",[]) if ref.get("source_name")=="mitre-attack"), ""),
                        "name": obj.get("name",""),
                        "aliases": aliases,
                        "description": obj.get("description","")[:500],
                        "created": obj.get("created",""),
                        "modified": obj.get("modified",""),
                    })
            _save(MITRE_CACHE, {"groups": groups, "_ts": time.time()})
            log.info(f"MITRE sync: {len(groups)} groups")
            return groups
    except Exception as e:
        log.error(f"MITRE sync error: {e}")
    return cache.get("groups", [])

# ── Search actors ─────────────────────────────────────────────────────────
def search_actors(query="", country=None, limit=20):
    db = _get_db()
    results = []
    q = (query or "").lower().strip()
    for name, actor in db.items():
        if q:
            in_name    = q in name.lower()
            in_aliases = any(q in a.lower() for a in actor.get("aliases", []))
            in_country = q in actor.get("country", "").lower()
            in_sponsor = q in actor.get("sponsor", "").lower()
            in_targets = any(q in t.lower() for t in actor.get("targets", []))
            in_desc    = q in actor.get("description", "").lower()
            if not (in_name or in_aliases or in_country or in_sponsor or in_targets or in_desc):
                continue
        if country and country.lower() not in actor.get("country", "").lower():
            continue
        results.append(actor)
    return sorted(results, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("risk","LOW"),4))[:limit]

# ── Get actor profile ─────────────────────────────────────────────────────
def get_actor(name):
    db = _get_db()
    # Direct match
    if name in db: return db[name]
    # Case-insensitive + alias match
    nl = name.lower()
    for k, v in db.items():
        if nl == k.lower() or any(nl == a.lower() for a in v.get("aliases",[])):
            return v
    return None

# ── Attribution scoring ────────────────────────────────────────────────────
def attribute_incident(ttps=None, iocs=None, ports=None):
    db = _get_db()
    scores = []
    ttps  = [t.strip() for t in (ttps or [])]
    iocs  = iocs or []
    ports = ports or []
    for name, actor in db.items():
        score = 0
        actor_ttps = actor.get("ttps", [])
        matched = []
        for t in ttps:
            for at in actor_ttps:
                if t == at or at.startswith(t+".") or t.startswith(at+"."):
                    score += 20; matched.append(t); break
        if 4444 in ports or 1337 in ports: score += 10
        if 445 in ports and "Russia" in actor.get("country",""): score += 8
        if 3389 in ports: score += 5
        if 22 in ports: score += 3
        for ioc in iocs:
            if any(ioc.lower() in str(v).lower() for v in actor.values()): score += 15
        if score > 0:
            scores.append({"actor":name,"score":min(score,100),"risk":actor.get("risk",""),
                "country":actor.get("country",""),"motivation":actor.get("motivation",""),
                "mitre_id":actor.get("mitre_id",""),"matched_ttps":matched})
    return sorted(scores, key=lambda x: -x["score"])[:5]

# ── Stats ──────────────────────────────────────────────────────────────────
def get_actor_stats():
    db = _get_db()
    by_country = {}
    by_risk = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for actor in db.values():
        c = actor.get("country","Unknown")
        by_country[c] = by_country.get(c,0) + 1
        risk = actor.get("risk","LOW")
        by_risk[risk] = by_risk.get(risk,0) + 1
    mitre = sync_mitre_actors()
    return {
        "total_actors": len(db),
        "by_country": sorted(by_country.items(), key=lambda x:-x[1]),
        "by_risk": by_risk,
        "mitre_groups_synced": len(mitre),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "most_dangerous": [a["name"] for a in list(db.values()) if a.get("risk")=="CRITICAL"][:5],
    }

# ── OTX enrichment for actor ──────────────────────────────────────────────
def get_actor_otx(actor_name):
    key = os.environ.get("OTX_API_KEY","")
    if not key: return []
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/pulses/search?q={actor_name}&limit=5",
                         headers={**HDR, "X-OTX-API-KEY": key}, timeout=10)
        if r.status_code == 200:
            pulses = r.json().get("results", [])
            return [{"name":p.get("name",""),"created":p.get("created",""),"tags":p.get("tags",[])} for p in pulses]
    except: pass
    return []
