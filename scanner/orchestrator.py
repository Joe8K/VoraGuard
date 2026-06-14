"""
VoraGuard Scan Orchestrator v2
Coordinates all scanners + all 12 advanced intelligence modules.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from config.settings import settings
from utils.logger import get_logger
from utils.validator import validate_domain
from scanner.core import run_nmap, run_dnstwist, run_theharvester
from scanner.intelligence import vt_check_domain, check_dns_health, check_ssl, calculate_risk_score
from scanner.advanced import (
    analyze_vulnerabilities, owasp_top10_mapping, generate_grc_report,
    detect_attack_surface_changes, map_business_impact, predict_regulatory_breach,
    map_supply_chain, honey_trap_detection, attacker_roi_score,
    threat_actor_correlation, threat_simulation,
)
from scanner.darkweb import full_darkweb_monitoring
from scanner.ip_intel import run_ip_scan, resolve_ip
from scanner.domain_deep_scan import run_domain_deep_scan
from scanner.new_modules import (
    autonomous_closed_loop_response,
    business_aligned_financial_quantification,
    ot_ics_context_analysis,
    nhi_shadow_ai_governance,
    unified_threat_fabric,
    cyber_threat_prediction,
)

log = get_logger(__name__)


@dataclass
class ScanResult:
    domain: str
    scan_id: str
    started_at: str
    completed_at: str = ""
    duration_seconds: float = 0
    nmap: dict = field(default_factory=dict)
    dnstwist: dict = field(default_factory=dict)
    harvester: dict = field(default_factory=dict)
    vt_domain: dict = field(default_factory=dict)
    dns_health: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    risk: dict = field(default_factory=dict)
    vuln_analysis: dict = field(default_factory=dict)
    owasp: dict = field(default_factory=dict)
    grc_report: dict = field(default_factory=dict)
    attack_surface_change: dict = field(default_factory=dict)
    business_impact: dict = field(default_factory=dict)
    regulatory_breach: dict = field(default_factory=dict)
    supply_chain: dict = field(default_factory=dict)
    honey_trap: dict = field(default_factory=dict)
    attacker_roi: dict = field(default_factory=dict)
    threat_actors: dict = field(default_factory=dict)
    darkweb: dict = field(default_factory=dict)
    threat_sim: dict = field(default_factory=dict)
    # New modules 13–18
    closed_loop_response: dict = field(default_factory=dict)
    financial_quantification: dict = field(default_factory=dict)
    ot_ics: dict = field(default_factory=dict)
    nhi_shadow_ai: dict = field(default_factory=dict)
    unified_fabric: dict = field(default_factory=dict)
    threat_prediction: dict = field(default_factory=dict)
    ip_scan: dict = field(default_factory=dict)   # unified IP intel (all 4 APIs)
    deep_scan: dict = field(default_factory=dict)   # 20-check deep scan
    scan_mode: str = "domain"                         # "domain" or "ip"
    output_dir: str = ""
    success: bool = True
    error: str = ""

    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2, default=str)
    def save(self):
        if self.output_dir:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            (Path(self.output_dir) / "scan-result.json").write_text(self.to_json())


def run_scan(target: str, active_scan: bool = True, scan_mode: str = "auto") -> ScanResult:
    import re as _re
    _is_ip = bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target.strip()))
    if scan_mode == "auto":
        scan_mode = "ip" if _is_ip else "domain"

    if scan_mode == "ip":
        domain = target.strip()
    else:
        try:
            domain = validate_domain(target)
        except ValueError as e:
            return ScanResult(domain=target, scan_id="invalid",
                              started_at=datetime.now().isoformat(), success=False, error=str(e))

    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = domain.replace("/","_").replace(":","_")
    # Always resolve output dir relative to voraguard root, not cwd
    _base = Path(settings.OUTPUT_BASE)
    if not _base.is_absolute():
        _base = Path(__file__).parent.parent / settings.OUTPUT_BASE
    output_dir = _base / f"{safe_name}_{scan_id}"
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    logger = get_logger("voraguard.scan", str(output_dir / "scan.log"))
    started_at = datetime.now()
    logger.info(f"VoraGuard scan started | {domain} | mode={scan_mode} | active={active_scan}")

    result = ScanResult(domain=domain, scan_id=scan_id, scan_mode=scan_mode,
                        started_at=started_at.isoformat(), output_dir=str(output_dir))

    # Phase 2: Active scan
    if active_scan:
        nmap_r = run_nmap(domain, raw_dir)
        result.nmap = nmap_r.to_dict()
        _nmap_obj = nmap_r
    else:
        _nmap_obj = None
        result.nmap = {"success": False, "open_ports": [], "reason": "Passive mode"}

    # Phase 3: OSINT
    dnstwist_r = run_dnstwist(domain, raw_dir)
    result.dnstwist = dnstwist_r.to_dict()
    harvester_r = run_theharvester(domain, raw_dir)
    result.harvester = harvester_r.to_dict()

    # Phase 4: Intelligence
    result.vt_domain = vt_check_domain(domain)
    result.dns_health = check_dns_health(domain)
    result.ssl_info = check_ssl(domain)

    # Phase 5: Risk score
    result.risk = calculate_risk_score(_nmap_obj, dnstwist_r, result.vt_domain, result.dns_health, result.ssl_info)

    # Phase 6: All 12 advanced modules
    logger.info("Running 12 advanced modules...")
    result.vuln_analysis        = analyze_vulnerabilities(result.nmap)
    result.owasp                = owasp_top10_mapping(result.nmap, result.ssl_info, result.dns_health)
    result.grc_report           = generate_grc_report(domain, result.risk, result.nmap, result.dnstwist, result.ssl_info, result.dns_health, result.vuln_analysis, result.owasp)
    result.attack_surface_change= detect_attack_surface_changes(domain, result.nmap, str(output_dir))
    result.business_impact      = map_business_impact(domain, result.nmap, result.ssl_info, result.vuln_analysis)
    result.regulatory_breach    = predict_regulatory_breach(domain, result.nmap, result.ssl_info, result.dns_health)
    result.supply_chain         = map_supply_chain(domain, result.nmap)
    result.honey_trap           = honey_trap_detection(domain, result.nmap)
    result.attacker_roi         = attacker_roi_score(domain, result.nmap, result.dnstwist, result.harvester, result.vuln_analysis)
    result.threat_actors        = threat_actor_correlation(domain, result.nmap, result.vt_domain)
    result.darkweb              = full_darkweb_monitoring(domain, result.harvester, result.nmap)
    result.threat_sim           = threat_simulation(domain, result.nmap, result.vuln_analysis)

    # New modules 13–18
    logger.info("Running 6 new advanced modules (13–18)...")
    result.closed_loop_response    = autonomous_closed_loop_response(domain, result.nmap, result.dns_health, result.ssl_info, result.vuln_analysis, result.risk)
    result.financial_quantification= business_aligned_financial_quantification(domain, result.nmap, result.vuln_analysis, result.risk)
    result.ot_ics                  = ot_ics_context_analysis(domain, result.nmap)
    result.nhi_shadow_ai           = nhi_shadow_ai_governance(domain, result.nmap, result.harvester)
    result.unified_fabric          = unified_threat_fabric(domain, result.nmap, result.vuln_analysis, result.owasp, result.supply_chain, result.threat_actors, result.darkweb, result.dns_health, result.ssl_info, result.harvester, result.nhi_shadow_ai, result.ot_ics)
    result.threat_prediction       = cyber_threat_prediction(domain, result.nmap, result.vuln_analysis, result.darkweb, result.threat_actors, result.risk)

    # Deep scan — 20 new security checks
    logger.info("Running 20-check domain deep scan...")
    result.deep_scan = run_domain_deep_scan(domain)

    # IP Intelligence scan (all 4 APIs — works for both domain and IP targets)
    logger.info("Running unified IP intelligence scan (AbuseIPDB + Shodan + IPQS + CriminalIP)...")
    result.ip_scan = run_ip_scan(domain)

    completed_at = datetime.now()
    result.completed_at = completed_at.isoformat()
    result.duration_seconds = (completed_at - started_at).total_seconds()
    logger.info(f"Complete | score={result.risk.get('score')}/100 | {result.duration_seconds:.1f}s")
    result.save()
    return result
