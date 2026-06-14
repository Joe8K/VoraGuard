<div align="center">

# 🛡️ VoraGuard

### Cyber Threat Intelligence & Vulnerability Assessment Platform

[![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Modules](https://img.shields.io/badge/Modules-18-orange?style=for-the-badge)]()
[![API Routes](https://img.shields.io/badge/API_Routes-179-red?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**18 modules · 179 API routes · 6-provider AI swarm · 28,000+ lines · Multi-file architecture**

*Full-spectrum threat intelligence, vulnerability assessment, and automated response — self-hosted.*

</div>

---

## What It Does

VoraGuard is a comprehensive Cyber Threat Intelligence (CTI) and Digital Risk Protection platform combining vulnerability assessment, dark web monitoring, brand protection, network IDS/IPS, SOAR automation, and AI-powered analysis into a single self-hosted system.

---

## Architecture
voraguard/

├── voraguard.py          # Entry point + CLI

├── web/

│   ├── app.py            # Flask app — 179 API routes (~9,900 lines)

│   └── network_page.py   # Network monitoring UI

├── scanner/

│   ├── core.py           # Core scanning engine

│   ├── advanced.py       # Advanced threat detection

│   ├── intelligence.py   # Threat intelligence aggregation

│   ├── va_engine.py      # Vulnerability assessment engine

│   ├── ip_intel.py       # IP reputation & geolocation

│   ├── darkweb.py        # Dark web monitoring

│   ├── darkweb_monitor.py# Extended dark web coverage

│   ├── brand_monitor.py  # Brand & domain protection

│   ├── domain_deep_scan.py # Deep domain analysis

│   ├── network_monitor.py  # Network traffic monitoring

│   ├── network_ids_engine.py # IDS/IPS pipeline

│   ├── soar_engine.py    # SOAR automation & playbooks

│   ├── takedown.py       # Automated takedown requests

│   ├── threat_actor.py   # Threat actor profiling

│   ├── alert_manager.py  # Alert deduplication & routing

│   ├── alerting.py       # Multi-channel alerting

│   ├── ai_scoring.py     # AI-powered threat scoring

│   ├── epss_intel.py     # EPSS exploit prediction

│   ├── cyber_blog.py     # Threat intelligence feeds

│   ├── identity_manager.py # Identity & credential exposure

│   ├── new_modules.py    # Extended capability modules

│   └── orchestrator.py   # Scan orchestration engine

├── config/

│   ├── settings.py       # Central configuration

│   └── init.py

├── monitor/

│   └── monitor.py        # Background monitoring daemon

├── reports/

│   ├── html_report.py    # HTML report generation

│   └── brand_report.py   # Brand protection reports

└── utils/

├── logger.py         # Structured logging

└── validator.py      # Input validation

---

## 18 Core Modules

| Module | Capability |
|---|---|
| **VA Engine** | Threaded port scanning, version-aware CVE matching, compliance auditing, attack path analysis |
| **Network IDS/IPS** | Real-time traffic analysis, anomaly detection, automated blocking pipeline |
| **Dark Web Monitor** | Paste sites, underground forums, credential leak detection |
| **Brand Monitor** | Typosquat detection, lookalike domains, phishing page identification |
| **SOAR Engine** | Automated playbooks, incident response workflows, ticketing integration |
| **Threat Intelligence** | Multi-source IOC aggregation, feed correlation, TTP mapping |
| **IP Intelligence** | Reputation scoring, geolocation, ASN analysis, abuse history |
| **Domain Deep Scan** | WHOIS, DNS history, certificate transparency, subdomain enumeration |
| **AI Scoring** | 6-provider AI swarm for threat scoring and prioritization |
| **EPSS Intelligence** | Exploit Prediction Scoring System integration for CVE prioritization |
| **Identity Manager** | Employee credential exposure, breach database correlation |
| **Threat Actor Profiling** | Actor attribution, TTP fingerprinting, campaign tracking |
| **Alert Manager** | Deduplication, severity routing, cooldown logic |
| **Alerting** | Email, Slack, webhook multi-channel notification |
| **Takedown Engine** | Automated abuse reports, UDRP letter generation |
| **Orchestrator** | Scan workflow coordination, parallel execution |
| **Network Monitor** | Continuous network surface monitoring |
| **Cyber Blog Intel** | Threat intelligence from security blogs and advisories |

---

## AI Swarm — 6 Providers

VoraGuard uses a 6-provider AI swarm with automatic failover:

| Provider | Model | Role |
|---|---|---|
| Groq | llama-3.3-70b | Primary — threat analysis |
| Google Gemini | Flash | Fallback #1 |
| OpenAI | GPT-4o | Fallback #2 |
| Anthropic | Claude | Fallback #3 |
| Cohere | Command R+ | Fallback #4 |
| Mistral | Large | Fallback #5 |

---

## Vulnerability Assessment Engine

- Threaded port scanning across full range
- Version-aware CVE matching against NVD database
- EPSS scoring for exploit probability
- CVSS v3.1 severity classification
- Compliance auditing (CIS, NIST, ISO 27001 mapping)
- Attack path analysis and chaining
- Remediation recommendations per finding

---

## Network IDS/IPS Pipeline

- Real-time packet capture and analysis
- Anomaly detection with baseline profiling
- Signature-based detection (Snort/Suricata rule compatibility)
- Automated IP blocking on confirmed threats
- Traffic visualization dashboard
- Alert integration with SOAR engine

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Python 3.13 |
| Web Framework | Flask 3.0 + Gunicorn |
| Database | SQLite + SQLAlchemy |
| AI | 6-provider swarm (Groq, Gemini, OpenAI, Anthropic, Cohere, Mistral) |
| Frontend | Vanilla JS + dark/light theme |
| Reports | ReportLab + FPDF2 (PDF), Jinja2 (HTML) |
| Network | Scapy, dnspython, python-whois |
| Data Science | NumPy, Pandas, SciPy, scikit-learn, NetworkX |
| Visualization | Plotly |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Joe8K/VoraGuard.git
cd VoraGuard

# 2. Install
pip install -r requirements.txt

# 3. Configure
cp config/settings.py.example config/settings.py
# Edit config/settings.py with your API keys

# 4. Launch
python3 voraguard.py
# Dashboard → http://localhost:5000
```

---

## API — 179 Routes

VoraGuard exposes 179 REST API endpoints across all modules:
/api/scan/*           → Vulnerability assessment

/api/intel/*          → Threat intelligence

/api/darkweb/*        → Dark web monitoring

/api/brand/*          → Brand protection

/api/network/*        → Network monitoring & IDS

/api/soar/*           → SOAR playbooks

/api/alerts/*         → Alert management

/api/reports/*        → Report generation

/api/actors/*         → Threat actor database

/api/identity/*       → Identity & credential exposure

/api/epss/*           → EPSS exploit scoring

/api/takedown/*       → Takedown automation

---

## Key Differentiators

| Feature | VoraGuard | Commercial Tools |
|---|---|---|
| 6-provider AI swarm with failover | ✅ | ❌ |
| Version-aware CVE matching | ✅ | Partial |
| EPSS exploit prediction integration | ✅ | Rarely |
| Integrated SOAR playbooks | ✅ | Separate product |
| Network IDS/IPS + CTI in one platform | ✅ | ❌ |
| Attack path analysis | ✅ | Partial |
| Self-hosted | ✅ | ❌ |
| Cost | **Free** | $30,000–$150,000/yr |

---

## Disclaimer

VoraGuard is built for **defensive security**. Only scan systems you own or have explicit written authorization to test. The VA engine and network monitor are for authorized use only.

---

<div align="center">

**Built by [Jithu Mohan K](https://linkedin.com/in/jithumohank18)**
*Cybersecurity enthusiast · CTI Platform Developer*

[LinkedIn](https://linkedin.com/in/jithumohank18) · [GitHub](https://github.com/Joe8K)

</div>
