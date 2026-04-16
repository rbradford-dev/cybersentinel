"""CyberSentinel configuration — all settings, API keys, and model config."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
load_dotenv(Path(__file__).parent / ".env")

# ---------------------------------------------------------------------------
# LLM Configuration
# ---------------------------------------------------------------------------
USE_MOCK_LLM: bool = os.getenv("USE_MOCK_LLM", "true").lower() == "true"
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
ORCHESTRATOR_MODEL: str = os.getenv("ORCHESTRATOR_MODEL", "claude-opus-4-6")
SUBAGENT_MODEL: str = os.getenv("SUBAGENT_MODEL", "claude-sonnet-4-6")

# Mock LLM simulated latency (milliseconds)
MOCK_DELAY_MS: int = int(os.getenv("MOCK_DELAY_MS", "200"))

# ---------------------------------------------------------------------------
# NVD (National Vulnerability Database)
# ---------------------------------------------------------------------------
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT: int = 50  # requests per 30 seconds with API key (5 without)

# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------
CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CACHE_TTL: int = 14400  # 4 hours in seconds

# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_RATE_LIMIT: int = 1000  # per day, free tier
ABUSEIPDB_CACHE_TTL: int = 3600  # 1 hour
ABUSEIPDB_CONFIDENCE_THRESHOLD: int = 50  # abuse confidence score threshold

# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------
OTX_API_KEY: str = os.getenv("OTX_API_KEY", "")
OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1"
OTX_RATE_LIMIT: int = 10000  # per hour
OTX_CACHE_TTL: int = 1800  # 30 minutes

# ---------------------------------------------------------------------------
# VirusTotal (Phase 2)
# ---------------------------------------------------------------------------
VT_API_KEY: str = os.getenv("VT_API_KEY", "")
VT_RATE_LIMIT: int = 4  # per minute, free tier

# ---------------------------------------------------------------------------
# Shodan (Phase 2)
# ---------------------------------------------------------------------------
SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")

# ---------------------------------------------------------------------------
# Exa (Web Search Intelligence)
# ---------------------------------------------------------------------------
EXA_API_KEY: str = os.getenv("EXA_API_KEY", "")
EXA_BASE_URL: str = "https://api.exa.ai"
EXA_SEARCH_TYPE: str = os.getenv("EXA_SEARCH_TYPE", "auto")  # auto|fast|deep
EXA_NUM_RESULTS: int = int(os.getenv("EXA_NUM_RESULTS", "5"))
EXA_HIGHLIGHTS_MAX_CHARS: int = 4000
EXA_CACHE_TTL: int = 3600  # 1 hour

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH: str = os.getenv("DB_PATH", str(Path(__file__).parent / "cybersentinel.db"))

# ---------------------------------------------------------------------------
# Severity Thresholds
# ---------------------------------------------------------------------------
CVSS_CRITICAL_THRESHOLD: float = 9.0
CVSS_HIGH_THRESHOLD: float = 7.0
CVSS_MEDIUM_THRESHOLD: float = 4.0

# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------
REPORT_OUTPUT_DIR: str = os.getenv(
    "REPORT_OUTPUT_DIR", str(Path(__file__).parent / "reports")
)
REPORT_MAX_FINDINGS: int = int(os.getenv("REPORT_MAX_FINDINGS", "100"))

# ---------------------------------------------------------------------------
# Log Analysis
# ---------------------------------------------------------------------------
LOG_MAX_LINES: int = int(os.getenv("LOG_MAX_LINES", "50000"))
LOG_ANOMALY_THRESHOLD: float = float(os.getenv("LOG_ANOMALY_THRESHOLD", "2.0"))

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
VERSION: str = "0.2.0"
APP_NAME: str = "CyberSentinel"
LOG_FILE: str = os.getenv("LOG_FILE", str(Path(__file__).parent / "cybersentinel.log"))
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "DEBUG")
CACHE_DIR: str = str(Path(__file__).parent / ".cache")
