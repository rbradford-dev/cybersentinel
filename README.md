# CyberSentinel

**Multi-Agent Cybersecurity AI System**

CyberSentinel is a production-grade, multi-agent cybersecurity intelligence platform built in Python. A Master Orchestrator (powered by Claude Opus 4.6) coordinates specialized subagents that handle vulnerability triage, threat intelligence enrichment, log anomaly detection, and automated incident reporting. The system queries real-world security feeds (NVD, CISA KEV, Exa, AlienVault OTX, AbuseIPDB), persists findings to SQLite, renders rich terminal dashboards, and serves a real-time web UI — all without LangChain, using custom orchestration on the Anthropic SDK.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CLI / main.py  +  Web Dashboard                    │
│             (argparse + asyncio.run  |  FastAPI + HTMX)               │
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
    └──────┬──────┘ └─────┬─────┘ └──────────┘ └─────┬────┘
           │              │                           │
     ┌─────┴──────┐  ┌────┴─────┐              ┌─────┴──────┐
     ▼            ▼  ▼          ▼              ▼            ▼
┌─────────┐ ┌────────┐ ┌──────────┐      ┌─────────┐ ┌──────────┐
│   NVD   │ │  CISA  │ │ AbuseIPDB│      │  SQLite  │ │   JSON   │
│  API    │ │  KEV   │ │   + OTX  │      │    DB    │ │  Export  │
└─────────┘ └────────┘ └──────────┘      └─────────┘ └──────────┘
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

# 6. Start the web dashboard
python main.py serve
# Then open http://localhost:8000 in your browser
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

### Enrich an IP address
```bash
python main.py enrich-ip 198.51.100.23
```

### Analyze a log file
```bash
python main.py analyze-log /var/log/auth.log
cat syslog.txt | python main.py analyze-log --stdin
```

### Generate a security report
```bash
python main.py report --type executive
python main.py report --type technical --export
```

### Full multi-agent assessment
```bash
python main.py assess --ip 198.51.100.23 --cve CVE-2024-38094
```

### Start the web dashboard
```bash
python main.py serve                    # http://localhost:8000
python main.py serve --port 8080        # custom port
python main.py serve --reload           # dev mode with auto-reload
```

### Database status
```bash
python main.py status
```

### Test Exa API connectivity
```bash
python main.py test-exa
```

---

## Web Dashboard

The Phase 3 web dashboard provides a real-time SOC-style interface:

- **Dashboard** — Overview with stat cards, severity distribution chart, recent findings
- **Findings** — Full findings table with severity filters
- **IOCs** — Indicators of Compromise with type filters and abuse scores
- **CVEs** — CVE findings with CVSS scores, KEV badges, priority columns
- **Run Query** — Submit queries with live SSE-streamed agent output
- **Agents** — Agent health, session history, integration status

**Stack:** FastAPI, Jinja2, HTMX, Tailwind CSS, Chart.js, Server-Sent Events

![Dashboard](docs/dashboard.png)

---

## Phase Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 1** | Project skeleton, Mock LLM, Orchestrator, Vulnerability Agent, NVD + CISA KEV + Exa clients, Rich terminal, SQLite, Tests | ✅ Complete |
| **Phase 2** | Threat Intel Agent (AbuseIPDB, AlienVault OTX), Log Analysis Agent, Report Agent, JSON export, new CLI commands | ✅ Complete |
| **Phase 3** | FastAPI web dashboard, HTMX + Tailwind UI, SSE real-time streaming, Chart.js visualizations | ✅ Complete |
| **Phase 4** | Real Anthropic API integration, prompt optimization, token budgeting, live SSE orchestrator wiring | 📋 Planned |
| **Phase 5** | Shodan integration, MITRE ATT&CK navigator, alerting webhooks, VirusTotal | 📋 Planned |

---

## Data Sources

| Source | Provides | Rate Limit | Auth Required |
|--------|----------|------------|---------------|
| **NVD API v2.0** | CVE details, CVSS scores, configurations | 50 req/30s (with key), 5 without | Optional API key |
| **CISA KEV** | Known exploited vulnerabilities, due dates, ransomware flags | No limit (JSON feed) | None |
| **Exa** | Web search intelligence, advisories, PoC write-ups | Varies by plan | API key |
| **AbuseIPDB** | IP abuse reports, confidence scores, category mappings | 1,000/day (free) | API key |
| **AlienVault OTX** | IOC enrichment, threat pulses, IP/domain reputation | 10,000/hour | API key |
| **VirusTotal** | Multi-engine scan results for files, URLs, IPs | 4/min (free) | API key (Phase 5) |
| **Shodan** | Internet-facing asset discovery, banners, open ports | Varies by plan | API key (Phase 5) |

---

## Agents

| Agent | Responsibility | Model | Status |
|-------|---------------|-------|--------|
| **Vulnerability Agent** | CVE lookup, CVSS triage, KEV cross-reference, Exa web enrichment, priority assignment | Claude Sonnet 4.6 | ✅ Active |
| **Threat Intel Agent** | IP/domain IOC enrichment via AbuseIPDB + AlienVault OTX, confidence scoring | Claude Sonnet 4.6 | ✅ Active |
| **Log Analysis Agent** | Log parsing, brute-force/exfiltration/off-hours anomaly detection, MITRE ATT&CK mapping | Claude Sonnet 4.6 | ✅ Active |
| **Report Agent** | Executive, technical, and compliance report generation from stored findings | Claude Sonnet 4.6 | ✅ Active |

---

## Tech Stack

- **Language:** Python 3.11+
- **LLM:** Anthropic Claude (Opus 4.6 orchestrator, Sonnet 4.6 subagents)
- **HTTP:** httpx (async)
- **Database:** SQLite with WAL mode
- **Terminal UI:** Rich
- **Web Dashboard:** FastAPI + Jinja2 + HTMX + Tailwind CSS + Chart.js
- **Real-time:** Server-Sent Events (SSE) via sse-starlette
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
