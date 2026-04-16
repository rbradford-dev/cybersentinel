"""Unit tests for the Log Analysis Agent."""

import pytest

import config
from agents.log_analysis_agent import LogAnalysisAgent
from core.agent_result import AgentResult

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

# The structured regex (_STRUCTURED_RE) expects:
#   TIMESTAMP [SRC_IP -> DST_IP] ACTION [user=USER] MESSAGE
# where the IP->IP part is optional.  "DENY" / "authentication failure" /
# "Failed password" trigger _FAILED_AUTH_PATTERNS for brute-force detection.

_BRUTE_FORCE_LINES = [
    f"2024-10-28T02:15:{i:02d}Z 203.0.113.45 -> 10.0.0.1 DENY user={'admin' if i % 2 == 0 else 'root'} authentication failure"
    for i in range(15)
]

# A large data-transfer line.  The transfer detector needs a keyword from
# _TRANSFER_PATTERNS (e.g. "transfer") AND a byte count via _BYTES_RE which
# matches "bytes" followed by [_=: ]* then digits  (e.g. "bytes=2147483648").
TRANSFER_LINE = (
    "2024-10-28T03:15:00Z 10.0.1.50 -> 198.51.100.23 transfer user=svc_backup bytes=2147483648"
)

# Off-hours login (03:00 falls in the 22:00-06:00 window).
OFF_HOURS_LINE = (
    "2024-10-28T03:00:00Z 10.0.1.100 -> 10.0.0.2 ACCEPT user=dr.smith login success to ehr-system"
)

# Combined sample set used by full-agent tests.
SAMPLE_LOG_LINES = _BRUTE_FORCE_LINES + [TRANSFER_LINE, OFF_HOURS_LINE]

# Syslog-format lines.  The syslog regex extracts the user via
# re.search(r'(?:for|user[= ])(\S+)', message).  "user=admin" matches;
# the bare "for admin" form does NOT because the alternation requires
# 'for' to be immediately followed by \S+.
SAMPLE_SYSLOG_LINES = [
    "Oct 28 02:13:45 server01 sshd[12345]: Failed password user=admin from 203.0.113.45 port 22",
    "Oct 28 02:13:46 server01 sshd[12346]: Failed password user=root from 203.0.113.45 port 22",
    "Oct 28 02:13:47 server01 sshd[12347]: Accepted publickey user=deploy from 10.0.0.5 port 22",
    "Oct 28 14:00:00 mailgw postfix[9001]: connect from unknown[192.168.1.200]",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_llm_mode():
    """Ensure all tests run with mock LLM."""
    original = config.USE_MOCK_LLM
    config.USE_MOCK_LLM = True
    yield
    config.USE_MOCK_LLM = original


@pytest.fixture
def agent() -> LogAnalysisAgent:
    return LogAnalysisAgent()


@pytest.fixture
def parser():
    return LogAnalysisAgent.LogParser


# ---------------------------------------------------------------------------
# LogParser.parse_lines tests
# ---------------------------------------------------------------------------


class TestParseLines:
    def test_parse_lines_structured(self, parser):
        """Parse structured 'IP -> IP ACTION' log lines and verify field extraction."""
        events = parser.parse_lines(SAMPLE_LOG_LINES)

        assert len(events) == len(SAMPLE_LOG_LINES)

        # Check the first event (a DENY / auth-failure line)
        first = events[0]
        assert first["timestamp"] == "2024-10-28T02:15:00Z"
        assert first["source_ip"] == "203.0.113.45"
        assert first["destination_ip"] == "10.0.0.1"
        assert first["action"] == "DENY"
        assert first["user"] == "admin"
        assert first["raw"] == SAMPLE_LOG_LINES[0]

        # All events must carry the required keys
        required_keys = {"timestamp", "source_ip", "destination_ip", "action", "user", "message", "raw"}
        for evt in events:
            assert required_keys.issubset(evt.keys()), f"Missing keys in {evt}"

    def test_parse_lines_syslog(self, parser):
        """Parse syslog-format lines and verify extracted fields."""
        events = parser.parse_lines(SAMPLE_SYSLOG_LINES)

        assert len(events) == len(SAMPLE_SYSLOG_LINES)

        # First syslog line: "Failed password user=admin from 203.0.113.45"
        first = events[0]
        assert first["timestamp"] is not None
        assert "Oct" in first["timestamp"]
        assert first["source_ip"] == "203.0.113.45"
        assert first["user"] == "admin"
        assert "Failed password" in first["message"]
        assert first["raw"] == SAMPLE_SYSLOG_LINES[0]

        # Third syslog line: "Accepted publickey user=deploy from 10.0.0.5"
        third = events[2]
        assert third["user"] == "deploy"
        assert third["source_ip"] == "10.0.0.5"

    def test_parse_lines_empty_and_blank(self, parser):
        """Blank lines and whitespace-only lines are skipped."""
        lines = ["", "   ", SAMPLE_LOG_LINES[0], "  "]
        events = parser.parse_lines(lines)
        assert len(events) == 1


# ---------------------------------------------------------------------------
# Brute-force detection tests
# ---------------------------------------------------------------------------


class TestDetectBruteForce:
    def test_detect_brute_force(self, parser):
        """15 failed auth events from one IP exceeds the default threshold of 10."""
        events = parser.parse_lines(_BRUTE_FORCE_LINES)
        hits = parser.detect_brute_force(events)

        assert len(hits) == 1
        bf = hits[0]
        assert bf["anomaly_type"] == "brute_force"
        assert bf["source_ip"] == "203.0.113.45"
        assert bf["attempt_count"] == 15
        assert "admin" in bf["target_users"]
        assert "root" in bf["target_users"]
        assert bf["first_seen"] is not None
        assert bf["last_seen"] is not None

    def test_detect_brute_force_below_threshold(self, parser):
        """5 failed auth events should NOT trigger detection at default threshold=10."""
        events = parser.parse_lines(_BRUTE_FORCE_LINES[:5])
        hits = parser.detect_brute_force(events)

        assert len(hits) == 0

    def test_detect_brute_force_custom_threshold(self, parser):
        """Custom threshold=3 detects even a small burst of failures."""
        events = parser.parse_lines(_BRUTE_FORCE_LINES[:5])
        hits = parser.detect_brute_force(events, threshold=3)

        assert len(hits) == 1
        assert hits[0]["attempt_count"] == 5


# ---------------------------------------------------------------------------
# Large transfer detection tests
# ---------------------------------------------------------------------------


class TestDetectLargeTransfers:
    def test_detect_large_transfers(self, parser):
        """A 2 GB transfer line should be flagged as data exfiltration."""
        events = parser.parse_lines([TRANSFER_LINE])
        hits = parser.detect_large_transfers(events)

        assert len(hits) == 1
        tx = hits[0]
        assert tx["anomaly_type"] == "data_exfiltration"
        assert tx["bytes_transferred"] == 2_147_483_648
        assert tx["source_ip"] == "10.0.1.50"
        assert tx["destination_ip"] == "198.51.100.23"

    def test_detect_large_transfers_below_threshold(self, parser):
        """A transfer below the default 100 MB threshold should not be flagged."""
        small_line = "2024-10-28T12:00:00Z 10.0.0.5 -> 10.0.0.6 transfer user=jdoe bytes=50000"
        events = parser.parse_lines([small_line])
        hits = parser.detect_large_transfers(events)

        assert len(hits) == 0


# ---------------------------------------------------------------------------
# Off-hours access detection tests
# ---------------------------------------------------------------------------


class TestDetectOffHours:
    def test_detect_off_hours(self, parser):
        """Events at 02:xx and 03:xx should be flagged as off-hours (22:00-06:00)."""
        events = parser.parse_lines(SAMPLE_LOG_LINES)
        hits = parser.detect_off_hours_access(events)

        # All lines in our sample have timestamps at 02:xx or 03:xx -- all off-hours
        assert len(hits) > 0
        for h in hits:
            assert h["anomaly_type"] == "off_hours_access"
            assert 0 <= h["hour"] < 6 or h["hour"] >= 22

    def test_no_off_hours_during_business(self, parser):
        """A 14:00 event is NOT off-hours."""
        business_line = (
            "2024-10-28T14:00:00Z 10.0.0.5 -> 10.0.0.6 ACCEPT user=jdoe login success"
        )
        events = parser.parse_lines([business_line])
        hits = parser.detect_off_hours_access(events)

        assert len(hits) == 0


# ---------------------------------------------------------------------------
# extract_stats tests
# ---------------------------------------------------------------------------


class TestExtractStats:
    def test_extract_stats(self, parser):
        """Stats dict must contain the expected summary keys."""
        events = parser.parse_lines(SAMPLE_LOG_LINES)
        stats = parser.extract_stats(events)

        assert "total_events" in stats
        assert "unique_ips" in stats
        assert "time_range" in stats
        assert "event_types" in stats

        assert stats["total_events"] == len(SAMPLE_LOG_LINES)
        assert stats["unique_ips"] >= 1
        assert stats["time_range"] is not None
        assert stats["time_range"]["earliest"] is not None
        assert stats["time_range"]["latest"] is not None
        assert isinstance(stats["event_types"], dict)
        assert "DENY" in stats["event_types"]

    def test_extract_stats_empty(self, parser):
        """Stats for an empty event list should have zero counts."""
        stats = parser.extract_stats([])
        assert stats["total_events"] == 0
        assert stats["unique_ips"] == 0
        assert stats["time_range"] is None
        assert stats["event_types"] == {}


# ---------------------------------------------------------------------------
# Full agent execution tests
# ---------------------------------------------------------------------------


class TestAgentExecution:
    @pytest.mark.asyncio
    async def test_agent_with_log_lines(self, agent):
        """Full agent run with sample log lines returns a valid AgentResult."""
        result = await agent.execute({"log_lines": SAMPLE_LOG_LINES})

        assert isinstance(result, AgentResult)
        assert result.agent_name == "log_analysis_agent"
        assert result.status == "success"
        assert result.finding_count() >= 1
        assert result.execution_time_ms >= 0
        assert "log_analysis" in result.data_sources
        assert result.summary  # non-empty summary string

        # raw_data should contain detection counts
        assert result.raw_data is not None
        assert "total_lines" in result.raw_data
        assert result.raw_data["total_lines"] == len(SAMPLE_LOG_LINES)
        assert "parsed_events" in result.raw_data
        assert "brute_force_detections" in result.raw_data

        # Check that findings conform to the standard finding schema
        for f in result.findings:
            assert "finding_id" in f
            assert "finding_type" in f
            assert "title" in f
            assert "severity" in f
            assert "confidence" in f
            assert "evidence" in f
            assert isinstance(f["evidence"], list)
            assert "mitre_techniques" in f
            assert isinstance(f["mitre_techniques"], list)

    @pytest.mark.asyncio
    async def test_agent_no_data(self, agent):
        """An empty task with no log data returns status='no_data'."""
        result = await agent.execute({})

        assert isinstance(result, AgentResult)
        assert result.status == "no_data"
        assert result.finding_count() == 0
        assert result.agent_name == "log_analysis_agent"

    @pytest.mark.asyncio
    async def test_agent_with_log_text(self, agent):
        """Pass log data as a single 'log_text' string instead of a list."""
        log_text = "\n".join(SAMPLE_LOG_LINES)
        result = await agent.execute({"log_text": log_text})

        assert isinstance(result, AgentResult)
        assert result.status == "success"
        assert result.finding_count() >= 1
        assert result.raw_data is not None
        assert result.raw_data["total_lines"] == len(SAMPLE_LOG_LINES)
