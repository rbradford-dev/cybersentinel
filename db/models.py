"""Table schemas expressed as dataclasses for documentation and type safety."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IOCRecord:
    """An Indicator of Compromise stored in the iocs table."""

    ioc_type: str
    value: str
    source: str
    confidence: float = 0.5
    severity: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: Optional[str] = None  # JSON array as TEXT
    mitre_techniques: Optional[str] = None  # JSON array as TEXT
    is_active: bool = True
    notes: Optional[str] = None
    id: Optional[int] = None


@dataclass
class CVEFinding:
    """A CVE finding stored in the cve_findings table."""

    cve_id: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    risk_score: Optional[float] = None
    is_kev: bool = False
    kev_due_date: Optional[str] = None
    recommended_action: Optional[str] = None
    deadline: Optional[str] = None
    affected_assets: Optional[str] = None  # JSON array as TEXT
    remediation: Optional[str] = None
    status: str = "open"
    first_detected: Optional[str] = None
    last_updated: Optional[str] = None
    raw_nvd_data: Optional[str] = None  # JSON blob
    notes: Optional[str] = None
    id: Optional[int] = None


@dataclass
class FindingRecord:
    """A generic agent finding stored in the findings table."""

    finding_id: str
    finding_type: str
    agent_name: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None  # JSON array as TEXT
    mitre_techniques: Optional[str] = None  # JSON array as TEXT
    status: str = "open"
    created_at: Optional[str] = None
    dedup_hash: Optional[str] = None
    raw_data: Optional[str] = None  # JSON blob
    id: Optional[int] = None


@dataclass
class AgentSession:
    """An agent execution session stored in the agent_sessions table."""

    session_id: str
    agent_name: str
    input_summary: Optional[str] = None
    status: Optional[str] = None
    findings_count: int = 0
    tokens_used: int = 0
    execution_time_ms: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    id: Optional[int] = None


@dataclass
class ConversationMessage:
    """A conversation turn stored in the conversation_history table."""

    session_id: str
    role: str
    content: str
    agent_name: Optional[str] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None
