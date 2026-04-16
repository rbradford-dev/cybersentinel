# CyberSentinel

**Multi-Agent Cybersecurity AI System**

CyberSentinel is a production-grade, multi-agent cybersecurity intelligence platform built in Python. A Master Orchestrator (powered by Claude Opus 4.6) coordinates specialized subagents that handle vulnerability triage, threat intelligence enrichment, log anomaly detection, and automated incident reporting. The system queries real-world security feeds (NVD, CISA KEV), persists findings to SQLite, and renders rich terminal dashboards — all without LangChain, using custom orchestration on the Anthropic SDK.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLI / main.py                               │
│                  (argparse + asyncio.run entry)                       │
└──────────────────────┬───────────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Master Orchestrator                               │
│            core/orchestrator.py  (Claude Opus 4.6)                   │
│                                                                      │
│   ┌──────────┐   ┌─────────────┐   ┌──────────────┐                │
│   │  Router   │──▶│  Dispatcher  │──▶│  Synthesizer  │               │
│   │(classify) │   │(async gather)│   │  (LLM merge)  │               │
│   └──────────┘   └──────┬──────┘   └──────────────┘                │
│                          │                                           │
└──────────────────────────┼───────────────────────────────────────────┘
                           │
              ┌────────────┼────────────┬────────────┐
              ▼            ▼            ▼            ▼
    ┌─────────────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐
    │ Vulnerability│ │  Threat   │ │   Log    │ │  Report  │
    │    Agent     │ │  Intel    │ │ Analysis │ │  Agent   │
    │  (Phase 1)   │ │ (Phase 2) │ │(Phase 2) │ │(Phase 2) │
    └──────┬──────┘ └───────────┘ └──────────┘ └──────────┘
           │
     ┌─────┴──────┐
     ▼            ▼
┌─────────┐ ┌──────────┐
│   NVD   │ │ CISA KEV │     ──▶  SQLite DB  ──▶  Rich Terminal
│  API    │ │   Feed   │          (WAL mode)       Output
└─────────┘ └──────────┘
```

---

## Quick Start

```bash
# 1. Clone and enter the project
cd cybersentinel

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env to add your API keys (optional — mock mode works without them)

# 5. Run your first command (mock mode, no API keys needed)
python main.py cve CVE-2024-38094
```

---

## CLI Commands

### Natural language query
```bash
python main.py query "Check for critical vulnerabilities in Apache HTTP Server"
```

### Direct CVE lookup
```bash
python main.py cve CVE-2024-38094
```

### Scan recent critical CVEs
```bash
python main.py scan --days 7 --cvss-min 9.0
```

### Show CISA KEV additions
```bash
python main.py kev --days 30
```

### Database status
```bash
python main.py status
```

### Interactive mode (Phase 2)
```bash
python main.py interactive
```

---

## Phase Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 1** | Project skeleton, Mock LLM, Orchestrator, Vulnerability Agent, NVD + CISA KEV clients, Rich terminal, SQLite, Tests | ✅ Complete |
| **Phase 2** | Threat Intel Agent (AbuseIPDB, AlienVault, VirusTotal), Log Analysis Agent, Interactive CLI mode | 📋 Planned |
| **Phase 3** | FastAPI web dashboard, JSON/PDF export, Report Agent | 📋 Planned |
| **Phase 4** | Real Anthropic API integration, prompt optimization, token budgeting | 📋 Planned |
| **Phase 5** | Shodan integration, MITRE ATT&CK navigator, alerting webhooks | 📋 Planned |

---

## Data Sources

| Source | Provides | Rate Limit | Auth Required |
|--------|----------|------------|---------------|
| **NVD API v2.0** | CVE details, CVSS scores, configurations | 50 req/30s (with key), 5 without | Optional API key |
| **CISA KEV** | Known exploited vulnerabilities, due dates, ransomware flags | No limit (JSON feed) | None |
| **AbuseIPDB** | IP abuse reports, confidence scores | 1,000/day (free) | API key (Phase 2) |
| **AlienVault OTX** | IOC enrichment, pulses, threat context | 10,000/hour | API key (Phase 2) |
| **VirusTotal** | Multi-engine scan results for files, URLs, IPs | 4/min (free) | API key (Phase 2) |
| **Shodan** | Internet-facing asset discovery, banners, open ports | Varies by plan | API key (Phase 2) |

---

## Agents

| Agent | Responsibility | Model | Status |
|-------|---------------|-------|--------|
| **Vulnerability Agent** | CVE lookup, CVSS triage, KEV cross-reference, priority assignment | Claude Sonnet 4.6 | ✅ Phase 1 |
| **Threat Intel Agent** | IOC enrichment across multiple feeds, confidence scoring | Claude Sonnet 4.6 | 📋 Phase 2 |
| **Log Analysis Agent** | SIEM log anomaly detection, MITRE ATT&CK mapping | Claude Sonnet 4.6 | 📋 Phase 2 |
| **Report Agent** | Executive and technical report generation | Claude Sonnet 4.6 | 📋 Phase 2 |

---

## Tech Stack

- **Language:** Python 3.11+
- **LLM:** Anthropic Claude (Opus 4.6 orchestrator, Sonnet 4.6 subagents)
- **HTTP:** httpx (async)
- **Database:** SQLite with WAL mode
- **Terminal UI:** Rich
- **Web (Phase 3):** FastAPI + Jinja2
- **Testing:** pytest + pytest-asyncio + pytest-httpx
- **Orchestration:** Custom — no LangChain / LangGraph

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Security Note

API keys are never committed to git. Store all secrets in a `.env` file (added to `.gitignore`). Use `.env.example` as a reference for required variables.
