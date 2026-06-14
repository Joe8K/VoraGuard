"""
VoraGuard AI Risk Scoring Engine v1.0
Developed by Jithu

Scores every finding using local Ollama LLM (free, private, offline).
No API cost. Runs on your own Kali machine.

Supported models (auto-detected):
  - llama3       (best, needs ~5GB RAM)
  - mistral      (fast, needs ~4GB RAM)
  - gemma2       (good balance)
  - phi3         (small, fast, ~2GB RAM)
  - llama3.2     (latest, very good)

Install Ollama:
  curl -fsSL https://ollama.ai/install.sh | sh
  ollama pull llama3      # or mistral, gemma2, phi3

What AI scoring does for each finding:
  1. Plain-English explanation of WHY it's dangerous
  2. Business impact assessment (financial, reputational, operational)
  3. Priority ranking (fix this BEFORE that)
  4. Attacker perspective (what an attacker would do with this)
  5. Specific remediation steps tailored to the exact finding
  6. Risk score 0-100

Fallback: If Ollama not running, uses enhanced rule-based scoring.

Usage:
  from scanner.ai_scoring import score_findings, score_single
  scored = score_findings(findings_list, target="domain.com")
  result = score_single(finding_dict, target="domain.com")
"""

import os, json, re, time, logging, requests
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from datetime import datetime

log = logging.getLogger("vorag.ai_scoring")
VORAG_HOME = Path(os.environ.get("VORAG_HOME", Path.home() / "voraguard"))

# ── Ollama config ─────────────────────────────────────────────────────────────
OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_TIMEOUT = 120  # seconds — LLM can take time for complex findings

# Priority model list — tries each until one works
PREFERRED_MODELS = ["llama3", "llama3.2", "llama3:8b", "mistral", "gemma2", "phi3", "phi3:mini"]

# ── Rule-based fallback scoring ────────────────────────────────────────────────
RULE_SCORES = {
    # Finding title keywords → base score
    "actively exploit":     95, "zero-day":           95, "0-day":              95,
    "ransomware":           92, "data breach":        90, "credential leak":    90,
    "remote code":          88, "rce":                88, "sql injection":      85,
    "backdoor":             85, "webshell":           85, "command injection":  85,
    "critical":             80, "nation-state":       80, "apt":                80,
    "phishing":             75, "typosquat":          72, "fake domain":        72,
    "exposed admin":        70, "default password":   75, "no authentication":  75,
    "open redirect":        65, "xss":                65, "csrf":               60,
    "weak ssl":             60, "expired cert":       58, "http not https":     55,
    "missing header":       45, "information leak":   50, "version disclosure": 40,
    "port exposed":         55, "rdp exposed":        70, "ssh exposed":        55,
    "redis exposed":        78, "elasticsearch":      78, "mongodb exposed":    78,
    "high":                 65, "medium":             45, "low":                25,
}

RULE_REMEDIATION = {
    "phishing":         "Immediately run vorag takedown <domain>. Warn users. Report to CERT-In.",
    "credential":       "Force reset all affected passwords. Enable MFA. Check for unauthorized logins.",
    "rce":              "Patch immediately. Check for existing compromise. Review all system logs.",
    "ransomware":       "Isolate affected systems. Do NOT pay ransom. Contact incident response team.",
    "exposed":          "Restrict access via firewall rules. Apply authentication immediately.",
    "ssl":              "Renew/replace certificate. Enable HSTS. Set minimum TLS 1.2.",
    "injection":        "Sanitize all inputs. Use parameterised queries. Apply WAF rules.",
    "default":          "Review the finding details. Assess impact. Prioritize based on exposure.",
}


# ── Data classes ──────────────────────────────────────────────────────────────
@dataclass
class AIScore:
    finding_id:       str
    original_severity:str
    ai_score:         int           # 0-100
    ai_severity:      str           # CRITICAL/HIGH/MEDIUM/LOW
    plain_english:    str           # why it's dangerous, in simple terms
    business_impact:  str           # what this means for the business
    attacker_view:    str           # what an attacker would do with this
    remediation:      str           # specific steps
    priority_rank:    int           # 1 = fix first
    ai_powered:       bool          = True   # False = rule-based fallback
    model_used:       str           = ""
    scored_at:        str           = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScoredReport:
    target:          str
    total_findings:  int
    ai_powered:      bool
    model_used:      str
    executive_summary: str
    top_risk:        str            # single most dangerous thing
    priority_list:   list           # findings sorted by AI priority
    risk_score:      int            # 0-100 overall
    risk_category:   str            # CRITICAL / HIGH / MEDIUM / LOW
    ai_scores:       list           # list of AIScore objects
    scored_at:       str            = field(default_factory=lambda: datetime.now().isoformat())


# ── Ollama helpers ─────────────────────────────────────────────────────────────
def _check_ollama() -> tuple:
    """Returns (available: bool, model: str)."""
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=4)
        if r.status_code == 200:
            available_models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            log.debug(f"Ollama models available: {available_models}")
            for preferred in PREFERRED_MODELS:
                if preferred.split(":")[0] in available_models or preferred in available_models:
                    return True, preferred
            # Use whatever is available
            if available_models:
                return True, available_models[0]
    except Exception:
        pass
    return False, ""


def _ollama_generate(prompt: str, model: str, system: str = "") -> str:
    """Call Ollama generate API. Returns text or raises."""
    body = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature":    0.1,   # low temp = consistent scoring
            "num_predict":    600,   # max tokens in response
            "top_p":          0.9,
        }
    }
    if system:
        body["system"] = system
    r = requests.post(f"{OLLAMA_BASE}/api/generate", json=body, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    return r.json().get("response", "").strip()


# ── Rule-based fallback ───────────────────────────────────────────────────────
def _rule_score(finding: dict) -> AIScore:
    title   = (finding.get("title","") + " " + finding.get("description","")).lower()
    sev_map = {"CRITICAL":85,"HIGH":65,"MEDIUM":45,"LOW":25,"INFO":10}
    score   = sev_map.get(finding.get("severity","MEDIUM"), 45)
    for keyword, pts in RULE_SCORES.items():
        if keyword in title:
            score = max(score, pts)
            break
    # Clamp
    score = min(100, max(0, score))
    if score >= 80: ai_sev = "CRITICAL"
    elif score >= 60: ai_sev = "HIGH"
    elif score >= 35: ai_sev = "MEDIUM"
    else: ai_sev = "LOW"

    remed = RULE_REMEDIATION["default"]
    for key, r in RULE_REMEDIATION.items():
        if key in title:
            remed = r
            break

    return AIScore(
        finding_id        = finding.get("id","") or finding.get("title","")[:30],
        original_severity = finding.get("severity","MEDIUM"),
        ai_score          = score,
        ai_severity       = ai_sev,
        plain_english     = f"This finding ({finding.get('title','')}) has been scored {score}/100 based on security patterns. Run Ollama for detailed AI analysis.",
        business_impact   = "Unable to assess without AI. Install Ollama for detailed business impact analysis.",
        attacker_view     = "Install Ollama for attacker perspective analysis.",
        remediation       = remed,
        priority_rank     = 0,
        ai_powered        = False,
        model_used        = "rule-based",
    )


# ── Single finding scorer ─────────────────────────────────────────────────────
def score_single(finding: dict, target: str = "", model: str = "") -> AIScore:
    """Score one finding using Ollama or fallback."""
    ollama_ok, auto_model = _check_ollama()
    use_model = model or auto_model

    if not ollama_ok:
        log.debug("Ollama not running — using rule-based scoring")
        return _rule_score(finding)

    title       = finding.get("title","")
    description = finding.get("description","") or finding.get("summary","")
    severity    = finding.get("severity","MEDIUM")
    source      = finding.get("source","")
    cve         = finding.get("cve","")
    cvss        = finding.get("cvss_score","")

    system_prompt = """You are VoraGuard AI — a cybersecurity risk analyst.
You analyse security findings and produce structured risk assessments.
You are direct, accurate, and write in plain English understandable by non-technical managers.
You always respond in EXACTLY the JSON format requested. No markdown, no extra text."""

    prompt = f"""Analyse this cybersecurity finding and respond ONLY with a JSON object:

FINDING:
Title: {title}
Description: {description}
Severity: {severity}
Source: {source}
{f'CVE: {cve}' if cve else ''}
{f'CVSS Score: {cvss}' if cvss else ''}
Target system: {target or 'unknown'}

Respond ONLY with this exact JSON (no markdown, no backticks):
{{
  "risk_score": <integer 0-100>,
  "risk_severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "plain_english": "<2-3 sentence explanation of why this is dangerous, written for a business owner>",
  "business_impact": "<1-2 sentences on financial/reputational/operational impact>",
  "attacker_view": "<1 sentence: what would an attacker do with this vulnerability>",
  "remediation": "<3-4 specific actionable steps to fix this, numbered>"
}}"""

    try:
        raw = _ollama_generate(prompt, use_model, system_prompt)
        # Extract JSON from response
        raw_clean = raw.strip()
        # Remove markdown code blocks if any
        raw_clean = re.sub(r'```json\s*|\s*```', '', raw_clean)
        # Find JSON object
        m = re.search(r'\{.*\}', raw_clean, re.DOTALL)
        if m:
            data = json.loads(m.group())
            score    = int(data.get("risk_score", 50))
            ai_sev   = data.get("risk_severity","MEDIUM").upper()
            if ai_sev not in ("CRITICAL","HIGH","MEDIUM","LOW"):
                ai_sev = "MEDIUM"
            return AIScore(
                finding_id        = finding.get("id","") or title[:30],
                original_severity = severity,
                ai_score          = min(100, max(0, score)),
                ai_severity       = ai_sev,
                plain_english     = data.get("plain_english",""),
                business_impact   = data.get("business_impact",""),
                attacker_view     = data.get("attacker_view",""),
                remediation       = data.get("remediation",""),
                priority_rank     = 0,
                ai_powered        = True,
                model_used        = use_model,
            )
    except Exception as e:
        log.warning(f"Ollama scoring failed for '{title}': {e} — falling back to rules")

    return _rule_score(finding)


# ── Score all findings in a report ────────────────────────────────────────────
def score_findings(findings: list, target: str = "", model: str = "") -> ScoredReport:
    """
    Score all findings. Returns ScoredReport with AI prioritisation.
    Batches findings to avoid overwhelming the LLM.
    """
    if not findings:
        return ScoredReport(
            target="", total_findings=0, ai_powered=False, model_used="",
            executive_summary="No findings to score.", top_risk="None",
            priority_list=[], risk_score=0, risk_category="LOW", ai_scores=[],
        )

    ollama_ok, auto_model = _check_ollama()
    use_model = model or auto_model
    log.info(f"AI Scoring: {len(findings)} findings | Ollama: {ollama_ok} | Model: {use_model or 'rule-based'}")

    # Score each finding
    scores = []
    for i, finding in enumerate(findings[:50]):  # cap at 50 findings
        score = score_single(finding, target, use_model)
        scores.append(score)
        if ollama_ok:
            time.sleep(0.1)  # small delay between LLM calls

    # Assign priority ranks (sorted by score descending)
    sorted_scores = sorted(scores, key=lambda x: x.ai_score, reverse=True)
    for rank, s in enumerate(sorted_scores, 1):
        s.priority_rank = rank

    # Overall risk = max of top 3 findings weighted
    if scores:
        top3 = sorted(scores, key=lambda x: x.ai_score, reverse=True)[:3]
        overall = int(top3[0].ai_score * 0.6 + (top3[1].ai_score if len(top3)>1 else 0) * 0.3 + (top3[2].ai_score if len(top3)>2 else 0) * 0.1)
    else:
        overall = 0

    if overall >= 80:   risk_cat = "CRITICAL"
    elif overall >= 60: risk_cat = "HIGH"
    elif overall >= 35: risk_cat = "MEDIUM"
    else:               risk_cat = "LOW"

    top_risk = sorted_scores[0].plain_english if sorted_scores else "No findings"

    # Generate executive summary using Ollama
    exec_summary = ""
    if ollama_ok and scores:
        top5_summary = "\n".join(
            f"{i+1}. [{s.ai_severity}] {s.finding_id} — score {s.ai_score}/100"
            for i, s in enumerate(sorted_scores[:5])
        )
        prompt = f"""Write a 3-sentence executive summary of this security assessment for a non-technical business owner.

Target: {target}
Overall Risk Score: {overall}/100 ({risk_cat})
Top findings:
{top5_summary}

Be direct. State the most urgent risk first. End with one clear recommended action.
Write plain text only, no markdown."""
        try:
            exec_summary = _ollama_generate(prompt, use_model)
        except Exception as e:
            log.warning(f"Executive summary generation failed: {e}")

    if not exec_summary:
        crit_count = sum(1 for s in scores if s.ai_severity == "CRITICAL")
        high_count = sum(1 for s in scores if s.ai_severity == "HIGH")
        exec_summary = (
            f"Security assessment of {target} found {len(findings)} issues with an overall risk score of "
            f"{overall}/100 ({risk_cat}). {crit_count} CRITICAL and {high_count} HIGH severity findings require "
            f"immediate attention. {'Top priority: '+sorted_scores[0].finding_id+'.' if sorted_scores else ''}"
        )

    return ScoredReport(
        target           = target,
        total_findings   = len(findings),
        ai_powered       = ollama_ok,
        model_used       = use_model if ollama_ok else "rule-based",
        executive_summary= exec_summary,
        top_risk         = top_risk,
        priority_list    = [{"rank": s.priority_rank, "finding": s.finding_id,
                             "score": s.ai_score, "severity": s.ai_severity,
                             "fix": s.remediation[:100]} for s in sorted_scores],
        risk_score       = overall,
        risk_category    = risk_cat,
        ai_scores        = scores,
    )


# ── Ollama setup checker ──────────────────────────────────────────────────────
def check_ollama_status() -> dict:
    """Returns full status dict for displaying in CLI/web."""
    ok, model = _check_ollama()
    status = {
        "ollama_running":   ok,
        "recommended_model": model,
        "install_cmd":      "curl -fsSL https://ollama.ai/install.sh | sh",
        "pull_cmd":         "ollama pull llama3",
        "url":              OLLAMA_BASE,
    }
    if ok:
        try:
            r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=4)
            models = [m["name"] for m in r.json().get("models", [])]
            status["available_models"] = models
            status["message"] = f"Ollama running — {len(models)} models available"
        except Exception:
            status["available_models"] = []
    else:
        status["available_models"] = []
        status["message"] = "Ollama not running. Install with: curl -fsSL https://ollama.ai/install.sh | sh"
    return status
