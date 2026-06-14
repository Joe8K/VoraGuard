"""
VoraGuard Brand Monitor — HTML Report Generator
Generates a pinpoint accurate, professional HTML report from brand scan results.
"""

import json
from pathlib import Path
from datetime import datetime


SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
    "CLEAN":    "#22c55e",
    "WARNING":  "#f59e0b",
}

SEV_BG = {
    "CRITICAL": "rgba(239,68,68,0.12)",
    "HIGH":     "rgba(249,115,22,0.12)",
    "MEDIUM":   "rgba(245,158,11,0.12)",
    "LOW":      "rgba(34,197,94,0.12)",
    "CLEAN":    "rgba(34,197,94,0.08)",
}

SOURCE_ICONS = {
    "crt_sh":       "🔏",
    "virustotal":   "🦠",
    "otx":          "👁",
    "urlhaus":      "🪝",
    "breach_intel": "💧",
    "github":       "🐙",
    "infra_intel":  "🖥",
    "dns_ssl":      "🔒",
    "fake_apps":    "📱",
    "google_safebrowsing": "🛡",
}

SOURCE_NAMES = {
    "crt_sh":       "Certificate Transparency",
    "virustotal":   "VirusTotal",
    "otx":          "AlienVault OTX",
    "urlhaus":      "URLhaus + PhishTank",
    "breach_intel": "Breach Intelligence",
    "github":       "GitHub Leak Detection",
    "infra_intel":  "Infrastructure Intel",
    "dns_ssl":      "DNS + SSL Health",
    "fake_apps":    "Fake Apps & Impersonation",
    "google_safebrowsing": "Google Safe Browsing",
}


def generate_brand_report(report: dict) -> str:
    """Generate complete HTML brand monitoring report. Returns HTML string."""

    brand    = report.get("brand", "")
    domain   = report.get("domain", "")
    score    = report.get("overall_score", 100)
    sev      = report.get("overall_severity", "CLEAN")
    findings = report.get("all_findings", [])
    sources  = report.get("sources", {})
    crit     = report.get("critical_count", 0)
    high     = report.get("high_count", 0)
    med      = report.get("medium_count", 0)
    total    = report.get("total_findings", 0)
    scan_id  = report.get("scan_id", "")
    started  = report.get("started_at", "")[:19].replace("T", " ")
    duration = report.get("duration_s", 0)
    summary  = report.get("executive_summary", "")
    sources_checked = report.get("sources_checked", 0)

    sev_col  = SEV_COLOR.get(sev, "#64748b")
    score_col = SEV_COLOR.get(sev, "#22c55e")

    # ── Score arc SVG ──────────────────────────────────────────────────────────
    radius = 54
    circumference = 2 * 3.14159 * radius
    dash = circumference * (score / 100)
    gap  = circumference - dash

    # ── Findings HTML ──────────────────────────────────────────────────────────
    def finding_card(f: dict, idx: int) -> str:
        sv   = f.get("severity", "LOW")
        col  = SEV_COLOR.get(sv, "#64748b")
        bg   = SEV_BG.get(sv, "rgba(100,116,139,0.1)")
        src  = f.get("source", "")
        act  = f.get("action", "")
        ind  = f.get("indicator", "")
        return f"""
        <div class="finding-card" style="border-left:4px solid {col};background:{bg}">
          <div class="finding-header">
            <span class="sev-badge" style="background:{col}">{sv}</span>
            <span class="finding-src">{src}</span>
            <span class="finding-num">#{idx+1}</span>
          </div>
          <div class="finding-title">{f.get('title','')}</div>
          <div class="finding-detail">{f.get('detail','')}</div>
          {f'<div class="finding-indicator">🎯 Indicator: <code>{ind}</code></div>' if ind else ''}
          {f'<div class="finding-action">⚡ Action: {act}</div>' if act else ''}
        </div>"""

    findings_html = "".join(finding_card(f, i) for i, f in enumerate(findings))
    if not findings_html:
        findings_html = '<div class="no-findings">✅ No threats detected across all intelligence sources.</div>'

    # ── Source cards ───────────────────────────────────────────────────────────
    def source_card(key: str, src: dict) -> str:
        icon  = SOURCE_ICONS.get(key, "🔍")
        name  = SOURCE_NAMES.get(key, key)
        sv    = src.get("severity", "CLEAN")
        col   = SEV_COLOR.get(sv, "#22c55e")
        n     = len(src.get("findings", []))
        avail = src.get("available", False)
        err   = src.get("error", "")
        status = "✓ Active" if avail else ("⚠ Partial" if not err else "✗ Error")
        status_col = "#22c55e" if avail else ("#f59e0b" if not err else "#ef4444")
        return f"""
        <div class="source-card">
          <div class="source-icon">{icon}</div>
          <div class="source-name">{name}</div>
          <div class="source-status" style="color:{status_col}">{status}</div>
          <div class="source-sev" style="color:{col}">{sv}</div>
          <div class="source-count">{n} finding{'s' if n!=1 else ''}</div>
          {f'<div class="source-err">{err[:60]}</div>' if err else ''}
        </div>"""

    sources_html = "".join(source_card(k, v) for k, v in sources.items())

    # ── crt.sh suspicious domains table ───────────────────────────────────────
    crt_data = sources.get("crt_sh", {})
    susp_domains = crt_data.get("suspicious_domains", [])[:15]
    crt_table = ""
    if susp_domains:
        rows = "".join(f"""<tr>
          <td><code>{d['domain']}</code></td>
          <td>{d.get('reason','')}</td>
          <td>{d.get('issued_at','')[:10]}</td>
          <td><span class="sev-badge" style="background:{SEV_COLOR.get(d.get('risk','HIGH'))}">{d.get('risk','HIGH')}</span></td>
        </tr>""" for d in susp_domains)
        crt_table = f"""
        <div class="detail-section">
          <h3>🔏 Suspicious SSL Certificates ({len(susp_domains)} shown)</h3>
          <table class="data-table"><thead><tr>
            <th>Domain</th><th>Reason</th><th>Issued</th><th>Risk</th>
          </tr></thead><tbody>{rows}</tbody></table>
        </div>"""

    # ── Breach intel detail ────────────────────────────────────────────────────
    breach_data = sources.get("breach_intel", {})
    hibp_list   = breach_data.get("hibp_breaches", [])
    breach_table = ""
    if hibp_list:
        rows = "".join(f"""<tr>
          <td><b>{b['name']}</b></td>
          <td>{b.get('breach_date','')}</td>
          <td>{b.get('pwn_count',0):,}</td>
          <td>{', '.join(b.get('data_classes',[])[:4])}</td>
        </tr>""" for b in hibp_list)
        breach_table = f"""
        <div class="detail-section">
          <h3>💧 HIBP Data Breaches ({len(hibp_list)} found)</h3>
          <table class="data-table"><thead><tr>
            <th>Breach</th><th>Date</th><th>Accounts Exposed</th><th>Data Types</th>
          </tr></thead><tbody>{rows}</tbody></table>
        </div>"""

    # ── GitHub leaks ──────────────────────────────────────────────────────────
    github_data = sources.get("github", {})
    gh_repos    = github_data.get("leaked_repos", [])[:10]
    gh_table    = ""
    if gh_repos:
        rows = "".join(f"""<tr>
          <td><a href="{r.get('repo_url','#')}" target="_blank"><code>{r.get('repo','')}</code></a></td>
          <td><code>{r.get('file','')}</code></td>
          <td>{r.get('pushed_at','')}</td>
          <td>{r.get('query_matched','')}</td>
        </tr>""" for r in gh_repos)
        gh_table = f"""
        <div class="detail-section">
          <h3>🐙 GitHub Public Leak Hits ({len(gh_repos)} shown)</h3>
          <table class="data-table"><thead><tr>
            <th>Repository</th><th>File</th><th>Last Push</th><th>Query Matched</th>
          </tr></thead><tbody>{rows}</tbody></table>
        </div>"""

    # ── Infrastructure detail ──────────────────────────────────────────────────
    infra_data  = sources.get("infra_intel", {})
    shodan_info = infra_data.get("shodan_data", {})
    abuse_info  = infra_data.get("abuseipdb_data", {})
    cves        = infra_data.get("cves", [])
    resolved_ip = (infra_data.get("resolved_ips") or ["—"])[0]

    infra_detail = f"""
    <div class="detail-section">
      <h3>🖥 Infrastructure Intelligence</h3>
      <div class="infra-grid">
        <div class="infra-item"><span>Resolved IP</span><b>{resolved_ip}</b></div>
        <div class="infra-item"><span>Org (Shodan)</span><b>{shodan_info.get('org','—')}</b></div>
        <div class="infra-item"><span>Open Ports</span><b>{', '.join(str(p) for p in shodan_info.get('ports',[])[:8]) or '—'}</b></div>
        <div class="infra-item"><span>CVEs Found</span><b style="color:{'#ef4444' if cves else '#22c55e'}">{len(cves)}</b></div>
        <div class="infra-item"><span>Abuse Confidence</span><b style="color:{'#ef4444' if abuse_info.get('confidence',0)>25 else '#22c55e'}">{abuse_info.get('confidence',0)}%</b></div>
        <div class="infra-item"><span>Abuse Reports</span><b>{abuse_info.get('reports',0)}</b></div>
      </div>
      {f'<div class="cve-list"><b>CVEs:</b> ' + ' '.join(f'<code class="cve-tag">{c}</code>' for c in cves[:10]) + '</div>' if cves else ''}
    </div>"""

    # ── DNS/SSL detail ─────────────────────────────────────────────────────────
    dns_data = sources.get("dns_ssl", {}).get("dns", {})
    ssl_data = sources.get("dns_ssl", {}).get("ssl", {})
    ssl_days = ssl_data.get("expires_in_days")
    ssl_col  = "#22c55e" if ssl_days and ssl_days > 30 else "#ef4444"

    dns_detail = f"""
    <div class="detail-section">
      <h3>🔒 DNS + SSL Health</h3>
      <div class="infra-grid">
        <div class="infra-item"><span>SPF Record</span><b style="color:{'#22c55e' if dns_data.get('spf_present') else '#ef4444'}">{'✓ Present' if dns_data.get('spf_present') else '✗ Missing'}</b></div>
        <div class="infra-item"><span>DMARC Record</span><b style="color:{'#22c55e' if dns_data.get('dmarc_present') else '#ef4444'}">{'✓ Present' if dns_data.get('dmarc_present') else '✗ Missing'}</b></div>
        <div class="infra-item"><span>SSL Valid</span><b style="color:{'#22c55e' if ssl_data.get('valid') else '#ef4444'}">{'✓ Valid' if ssl_data.get('valid') else '✗ Invalid'}</b></div>
        <div class="infra-item"><span>SSL Expires</span><b style="color:{ssl_col}">{f'{ssl_days} days' if ssl_days else '—'}</b></div>
        <div class="infra-item"><span>SSL Issuer</span><b>{ssl_data.get('issuer','—')[:30]}</b></div>
        <div class="infra-item"><span>MX Records</span><b>{len(dns_data.get('mx_records',[]))}</b></div>
      </div>
    </div>"""


    # -- Google Safe Browsing detail
    gsb_data    = sources.get("google_safebrowsing", {})
    gsb_threats = gsb_data.get("threats_found", [])
    gsb_checked = gsb_data.get("urls_checked", 0)
    gsb_err     = gsb_data.get("error", "")
    gsb_detail  = ""
    if gsb_threats:
        rows = "".join(f'''<tr>
          <td><code>{t["url"]}</code></td>
          <td><span class="sev-badge" style="background:{SEV_COLOR.get(t.get("severity","HIGH"))}">{t.get("threat_label","")}</span></td>
          <td>{t.get("platform","")}</td>
        </tr>''' for t in gsb_threats)
        gsb_detail = (
            f'<div class="detail-section"><h3>Google Safe Browsing - {len(gsb_threats)} Threat(s) ({gsb_checked} URLs checked)</h3>' +
            f'<table class="data-table"><thead><tr><th>URL</th><th>Threat</th><th>Platform</th></tr></thead><tbody>' +
            rows + '</tbody></table></div>'
        )
    elif gsb_err:
        gsb_detail = (
            f'<div class="detail-section"><h3>Google Safe Browsing</h3>' +
            f'<div style="color:#64748b;font-size:13px">Key not configured: add GOOGLE_SAFE_BROWSING_KEY to .env</div></div>'
        )
    elif gsb_data.get("available"):
        gsb_detail = (
            f'<div class="detail-section"><h3>Google Safe Browsing - {gsb_checked} URLs Checked</h3>' +
            f'<div style="color:#22c55e;font-size:14px">All {gsb_checked} URLs are CLEAN in Google Safe Browsing</div></div>'
        )


    # ── Full HTML ──────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VoraGuard Brand Monitor — {brand.upper()} — {scan_id}</title>
<style>
  :root {{
    --bg: #0a0f1e; --bg2: #0f172a; --bg3: #1e293b;
    --border: #1e293b; --text: #e2e8f0; --muted: #64748b;
    --cyan: #22d3ee; --blue: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI',system-ui,sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}
  a {{ color: var(--cyan); }}

  /* ── Header ── */
  .header {{ background: linear-gradient(135deg,#0f172a 0%,#1a1040 100%); padding: 32px 48px; border-bottom: 1px solid var(--border); }}
  .header-top {{ display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px; }}
  .brand-title {{ font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
  .brand-title span {{ color: var(--cyan); }}
  .scan-meta {{ color: var(--muted); font-size: 13px; margin-top: 6px; }}
  .scan-meta b {{ color: var(--text); }}
  .severity-pill {{
    padding: 8px 24px; border-radius: 999px; font-weight: 800;
    font-size: 16px; letter-spacing: 1px; border: 2px solid {sev_col};
    color: {sev_col}; background: {SEV_BG.get(sev,'rgba(100,116,139,0.1)')};
  }}

  /* ── Score ring ── */
  .score-section {{ display:flex; align-items:center; gap:32px; margin-top: 24px; flex-wrap:wrap; }}
  .score-ring {{ position:relative; width:140px; height:140px; flex-shrink:0; }}
  .score-ring svg {{ transform:rotate(-90deg); }}
  .score-ring .score-label {{
    position:absolute; inset:0; display:flex; flex-direction:column;
    align-items:center; justify-content:center;
  }}
  .score-num {{ font-size:36px; font-weight:800; color:{score_col}; }}
  .score-sub {{ font-size:11px; color:var(--muted); margin-top:2px; }}
  .score-stats {{ display:flex; gap:24px; flex-wrap:wrap; }}
  .stat-box {{ background:var(--bg3); border-radius:12px; padding:16px 24px; min-width:100px; }}
  .stat-num {{ font-size:32px; font-weight:800; }}
  .stat-label {{ font-size:12px; color:var(--muted); margin-top:4px; }}
  .stat-crit {{ color:#ef4444; }}
  .stat-high {{ color:#f97316; }}
  .stat-med  {{ color:#f59e0b; }}
  .stat-clean{{ color:#22c55e; }}

  /* ── Summary ── */
  .summary-box {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px 24px; margin: 24px 48px;
    font-size: 15px; line-height: 1.7; color: #94a3b8;
  }}
  .summary-box b {{ color: var(--text); }}

  /* ── Section ── */
  .section {{ margin: 0 48px 32px; }}
  .section-title {{
    font-size: 18px; font-weight: 700; color: var(--cyan);
    border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 16px;
    display: flex; align-items:center; gap: 8px;
  }}

  /* ── Sources grid ── */
  .sources-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:12px; }}
  .source-card {{
    background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px; text-align:center;
  }}
  .source-icon {{ font-size:24px; margin-bottom:6px; }}
  .source-name {{ font-size:12px; font-weight:600; color:var(--text); margin-bottom:4px; }}
  .source-status {{ font-size:11px; margin-bottom:4px; }}
  .source-sev {{ font-size:12px; font-weight:700; margin-bottom:4px; }}
  .source-count {{ font-size:11px; color:var(--muted); }}
  .source-err {{ font-size:10px; color:#ef4444; margin-top:4px; }}

  /* ── Findings ── */
  .finding-card {{
    border-radius: 10px; padding: 16px 20px; margin-bottom: 12px;
  }}
  .finding-header {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; }}
  .sev-badge {{
    font-size:11px; font-weight:700; padding:3px 10px; border-radius:999px;
    color:#fff; letter-spacing:0.5px;
  }}
  .finding-src {{ font-size:12px; color:var(--muted); }}
  .finding-num {{ margin-left:auto; font-size:11px; color:var(--muted); }}
  .finding-title {{ font-size:15px; font-weight:600; color:var(--text); margin-bottom:6px; }}
  .finding-detail {{ font-size:13px; color:#94a3b8; margin-bottom:6px; line-height:1.5; }}
  .finding-indicator {{ font-size:12px; color:var(--muted); margin-bottom:4px; }}
  .finding-indicator code {{ background:var(--bg3); padding:2px 6px; border-radius:4px; color:var(--cyan); }}
  .finding-action {{
    font-size:13px; color:#fbbf24; background:rgba(251,191,36,0.08);
    border-radius:6px; padding:6px 10px; margin-top:6px;
  }}
  .no-findings {{
    background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.3);
    border-radius:10px; padding:24px; text-align:center;
    color:#22c55e; font-size:16px; font-weight:600;
  }}

  /* ── Detail sections ── */
  .detail-section {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px 24px; margin-bottom: 16px;
  }}
  .detail-section h3 {{ font-size:15px; font-weight:700; margin-bottom:14px; color:var(--cyan); }}
  .data-table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .data-table th {{ text-align:left; color:var(--muted); font-weight:600; padding:8px 12px; border-bottom:1px solid var(--border); font-size:12px; }}
  .data-table td {{ padding:8px 12px; border-bottom:1px solid rgba(30,41,59,0.5); color:var(--text); }}
  .data-table tr:hover td {{ background:rgba(255,255,255,0.02); }}
  .data-table code {{ font-size:12px; color:var(--cyan); }}

  .infra-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:10px; margin-bottom:12px; }}
  .infra-item {{ background:var(--bg3); border-radius:8px; padding:10px 14px; }}
  .infra-item span {{ display:block; font-size:11px; color:var(--muted); margin-bottom:4px; }}
  .infra-item b {{ font-size:14px; }}
  .cve-list {{ margin-top:10px; }}
  .cve-tag {{ background:rgba(239,68,68,0.15); color:#ef4444; padding:2px 8px; border-radius:4px; font-size:12px; margin:2px; display:inline-block; }}

  /* ── Footer ── */
  .footer {{
    text-align:center; padding:24px; color:var(--muted);
    font-size:12px; border-top:1px solid var(--border); margin-top:48px;
  }}

  /* ── Filter buttons ── */
  .filter-bar {{ display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }}
  .filter-btn {{
    padding:6px 14px; border-radius:999px; border:1px solid var(--border);
    background:var(--bg2); color:var(--muted); cursor:pointer; font-size:13px;
    transition:all 0.2s;
  }}
  .filter-btn:hover,.filter-btn.active {{ border-color:var(--cyan); color:var(--cyan); background:rgba(34,211,238,0.08); }}
</style>
</head>
<body>

<!-- ── HEADER ── -->
<div class="header">
  <div class="header-top">
    <div>
      <div class="brand-title">VoraGuard <span>Brand Monitor</span></div>
      <div class="scan-meta">
        Brand: <b>{brand.upper()}</b> &nbsp;|&nbsp;
        Domain: <b>{domain}</b> &nbsp;|&nbsp;
        Scan ID: <b>{scan_id}</b> &nbsp;|&nbsp;
        {started} UTC &nbsp;|&nbsp;
        {duration}s &nbsp;|&nbsp;
        {sources_checked}/9 sources active
      </div>
    </div>
    <div class="severity-pill">{sev}</div>
  </div>

  <div class="score-section">
    <div class="score-ring">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r="{radius}" fill="none" stroke="#1e293b" stroke-width="12"/>
        <circle cx="70" cy="70" r="{radius}" fill="none" stroke="{score_col}" stroke-width="12"
          stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-linecap="round"/>
      </svg>
      <div class="score-label">
        <div class="score-num">{score}</div>
        <div class="score-sub">/ 100</div>
      </div>
    </div>
    <div class="score-stats">
      <div class="stat-box">
        <div class="stat-num stat-crit">{crit}</div>
        <div class="stat-label">CRITICAL</div>
      </div>
      <div class="stat-box">
        <div class="stat-num stat-high">{high}</div>
        <div class="stat-label">HIGH</div>
      </div>
      <div class="stat-box">
        <div class="stat-num stat-med">{med}</div>
        <div class="stat-label">MEDIUM</div>
      </div>
      <div class="stat-box">
        <div class="stat-num">{total}</div>
        <div class="stat-label">TOTAL FINDINGS</div>
      </div>
    </div>
  </div>
</div>

<!-- ── EXECUTIVE SUMMARY ── -->
<div class="summary-box">
  <b>Executive Summary:</b> {summary}
</div>

<!-- ── INTELLIGENCE SOURCES ── -->
<div class="section">
  <div class="section-title">📡 Intelligence Sources</div>
  <div class="sources-grid">{sources_html}</div>
</div>

<!-- ── ALL FINDINGS ── -->
<div class="section">
  <div class="section-title">🎯 Threat Findings ({total})</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')" style="border-color:#ef4444;color:#ef4444">Critical ({crit})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')" style="border-color:#f97316;color:#f97316">High ({high})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')" style="border-color:#f59e0b;color:#f59e0b">Medium ({med})</button>
  </div>
  <div id="findings-container">
    {findings_html}
  </div>
</div>

<!-- ── DETAIL SECTIONS ── -->
<div class="section">
  <div class="section-title">🔍 Detailed Intelligence</div>
  {crt_table}
  {breach_table}
  {gh_table}
  {infra_detail}
  {dns_detail}
  {gsb_detail}
</div>

<!-- ── FOOTER ── -->
<div class="footer">
  VoraGuard v3.0 Brand Monitoring Report &nbsp;|&nbsp;
  Generated {started} UTC &nbsp;|&nbsp;
  For authorized security use only &nbsp;|&nbsp;
  Scan ID: {scan_id}
</div>

<script>
function filterFindings(level) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    const badge = card.querySelector('.sev-badge');
    if (!badge) return;
    card.style.display = (level === 'ALL' || badge.textContent === level) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    return html


def save_brand_report(report: dict) -> str:
    """Save HTML report to output_dir. Returns file path."""
    output_dir = Path(report.get("output_dir", "."))
    output_dir.mkdir(parents=True, exist_ok=True)
    html = generate_brand_report(report)
    path = output_dir / "brand-report.html"
    path.write_text(html, encoding="utf-8")
    return str(path)
