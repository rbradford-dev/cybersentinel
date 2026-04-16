"""AgentResult — the strict contract between every agent and the orchestrator."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentResult:
    """Structured result returned by every agent to the orchestrator."""

    agent_name: str
    status: str  # "success" | "partial" | "error" | "no_data"
    findings: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    tokens_used: int = 0
    execution_time_ms: int = 0
    data_sources: list[str] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None
    raw_data: Optional[dict] = None

    def finding_count(self) -> int:
        """Return the number of findings."""
        return len(self.findings)

    def critical_count(self) -> int:
        """Return number of critical-severity findings."""
        return sum(1 for f in self.findings if f.get("severity") == "critical")

    def high_count(self) -> int:
        """Return number of high-severity findings."""
        return sum(1 for f in self.findings if f.get("severity") == "high")

    def has_kev_findings(self) -> bool:
        """Return True if any finding is in the CISA KEV catalog."""
        return any(f.get("is_kev") for f in self.findings)

    def merge(self, other: "AgentResult") -> "AgentResult":
        """Merge another AgentResult into this one."""
        return AgentResult(
            agent_name="orchestrator",
            status=self._merge_status(self.status, other.status),
            findings=self.findings + other.findings,
            confidence=min(self.confidence, other.confidence),
            tokens_used=self.tokens_used + other.tokens_used,
            execution_time_ms=max(self.execution_time_ms, other.execution_time_ms),
            data_sources=list(set(self.data_sources + other.data_sources)),
            summary=f"{self.summary} | {other.summary}",
            error=self.error or other.error,
            raw_data=None,
        )

    @staticmethod
    def _merge_status(a: str, b: str) -> str:
        """Return the worst status between two results."""
        priority = {"error": 0, "partial": 1, "no_data": 2, "success": 3}
        if priority.get(a, 3) <= priority.get(b, 3):
            return a
        return b

    @staticmethod
    def make_finding(
        finding_id: str,
        finding_type: str,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        cvss_score: Optional[float] = None,
        cve_id: Optional[str] = None,
        affected_asset: Optional[str] = None,
        evidence: Optional[list[str]] = None,
        mitre_techniques: Optional[list[str]] = None,
        remediation: Optional[str] = None,
        is_kev: bool = False,
        kev_due_date: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> dict:
        """Create a finding dict conforming to the standard schema."""
        from datetime import datetime, timezone

        return {
            "finding_id": finding_id,
            "finding_type": finding_type,
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cve_id": cve_id,
            "affected_asset": affected_asset,
            "evidence": evidence or [],
            "mitre_techniques": mitre_techniques or [],
            "remediation": remediation,
            "is_kev": is_kev,
            "kev_due_date": kev_due_date,
            "confidence": confidence,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        }
