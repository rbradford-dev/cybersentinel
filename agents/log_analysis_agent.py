"""Log analysis agent -- detects anomalies in security logs and maps findings to MITRE ATT&CK.

Ingests SIEM log exports, raw syslog, or structured log data. Runs statistical
anomaly detection (brute-force, data exfiltration, off-hours access) and then
enriches results via the LLM for MITRE ATT&CK technique mapping and
healthcare-contextualized alerting.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import config
from core.agent_result import AgentResult
from core.base_agent import BaseAgent

logger = logging.getLogger("cybersentinel.agents.log_analysis")

LOG_ANALYSIS_SYSTEM_PROMPT = """\
You are a security log analyst for a major healthcare system. Analyze the \
provided log data and identify anomalies, threats, and suspicious patterns.

For each finding, provide:
- Anomaly type: brute_force | data_exfiltration | privilege_escalation | \
lateral_movement | c2_communication | malware_execution | policy_violation | \
suspicious_access
- Severity: critical | high | medium | low
- MITRE ATT&CK technique IDs
- Recommended actions

Healthcare context: Unusual access to medical records systems, DICOM/HL7 \
traffic anomalies, and after-hours access to clinical systems should receive \
elevated priority.

Output: Valid JSON array of finding objects. No markdown. No preamble.\
"""

# Common syslog / security-log regex.  Handles lines like:
#   2024-10-28T02:13:45Z 10.0.0.5 -> 198.51.100.23 DENY user=jsmith ...
#   Oct 28 02:13:45 server01 sshd[12345]: Failed password for admin from 203.0.113.45
_STRUCTURED_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+"
    r"(?:(?P<source_ip>(?:\d{1,3}\.){3}\d{1,3})\s*->\s*"
    r"(?P<destination_ip>(?:\d{1,3}\.){3}\d{1,3})\s+)?"
    r"(?P<action>\S+)\s*"
    r"(?:user=(?P<user>\S+)\s*)?"
    r"(?P<message>.*)"
)

_SYSLOG_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)"
)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_BYTES_RE = re.compile(r"(?:bytes[_=: ]*)(\d+)", re.IGNORECASE)

_FAILED_AUTH_PATTERNS = re.compile(
    r"(?:failed\s+(?:password|login|auth)|authentication\s+fail|"
    r"invalid\s+(?:user|credentials)|login\s+failed|access\s+denied|DENY)",
    re.IGNORECASE,
)

_TRANSFER_PATTERNS = re.compile(
    r"(?:bytes_sent|bytes_transferred|upload|transfer|sent\s+\d+\s+bytes)",
    re.IGNORECASE,
)

_PRIV_ESC_PATTERNS = re.compile(
    r"(?:added\s+to\s+.*admin|privilege|sudo|runas|"
    r"domain\s+admin|group\s+change|net\s+group|"
    r"elevated|escalat|impersonat)",
    re.IGNORECASE,
)


class LogAnalysisAgent(BaseAgent):
    """Analyzes security logs for anomalies and maps findings to MITRE ATT&CK techniques."""

    name = "log_analysis_agent"
    description = "Log anomaly detection with MITRE ATT&CK mapping"
    capabilities = ["log_analysis", "anomaly_detection", "mitre_mapping"]
    model = config.SUBAGENT_MODEL

    # ------------------------------------------------------------------
    # Nested LogParser utility
    # ------------------------------------------------------------------

    class LogParser:
        """Static helper methods for parsing and analyzing raw log lines."""

        @staticmethod
        def parse_lines(lines: list[str]) -> list[dict]:
            """Parse raw log lines into structured dicts.

            Each dict has keys: timestamp, source_ip, destination_ip, action,
            user, message, raw.
            """
            events: list[dict] = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                event: dict = {
                    "timestamp": None,
                    "source_ip": None,
                    "destination_ip": None,
                    "action": None,
                    "user": None,
                    "message": "",
                    "raw": line,
                }

                # Attempt structured format first
                m = _STRUCTURED_RE.match(line)
                if m:
                    event["timestamp"] = m.group("timestamp")
                    event["source_ip"] = m.group("source_ip")
                    event["destination_ip"] = m.group("destination_ip")
                    event["action"] = m.group("action")
                    event["user"] = m.group("user")
                    event["message"] = (m.group("message") or "").strip()
                    events.append(event)
                    continue

                # Try syslog format
                m = _SYSLOG_RE.match(line)
                if m:
                    event["timestamp"] = m.group("timestamp")
                    event["message"] = (m.group("message") or "").strip()
                    # Extract IPs from the message body
                    ips = _IP_RE.findall(line)
                    if ips:
                        event["source_ip"] = ips[-1]  # "from <ip>" typically last
                    if len(ips) >= 2:
                        event["source_ip"] = ips[0]
                        event["destination_ip"] = ips[1]
                    # Guess user from common patterns
                    user_m = re.search(r"(?:for|user[= ])(\S+)", event["message"])
                    if user_m:
                        event["user"] = user_m.group(1)
                    events.append(event)
                    continue

                # Fallback -- store the raw line with whatever IPs we can find
                ips = _IP_RE.findall(line)
                if ips:
                    event["source_ip"] = ips[0]
                if len(ips) >= 2:
                    event["destination_ip"] = ips[1]
                event["message"] = line
                events.append(event)

            return events

        @staticmethod
        def detect_brute_force(
            events: list[dict], threshold: int = 10
        ) -> list[dict]:
            """Find source IPs with more than *threshold* failed authentication attempts."""
            failed_by_ip: dict[str, list[dict]] = {}
            for evt in events:
                msg = evt.get("message", "") + " " + (evt.get("action") or "")
                if _FAILED_AUTH_PATTERNS.search(msg):
                    ip = evt.get("source_ip") or "unknown"
                    failed_by_ip.setdefault(ip, []).append(evt)

            results: list[dict] = []
            for ip, evts in failed_by_ip.items():
                if len(evts) > threshold:
                    timestamps = [e.get("timestamp") for e in evts if e.get("timestamp")]
                    target_users = list(
                        {e.get("user") for e in evts if e.get("user")}
                    )
                    results.append(
                        {
                            "anomaly_type": "brute_force",
                            "source_ip": ip,
                            "attempt_count": len(evts),
                            "target_users": target_users,
                            "first_seen": min(timestamps) if timestamps else None,
                            "last_seen": max(timestamps) if timestamps else None,
                            "sample_events": evts[:5],
                        }
                    )
            return results

        @staticmethod
        def detect_large_transfers(
            events: list[dict], threshold_bytes: int = 100_000_000
        ) -> list[dict]:
            """Find events indicating data transfers exceeding *threshold_bytes*."""
            results: list[dict] = []
            for evt in events:
                msg = evt.get("message", "") + " " + (evt.get("raw") or "")
                if not _TRANSFER_PATTERNS.search(msg):
                    continue
                bytes_m = _BYTES_RE.search(msg)
                if not bytes_m:
                    continue
                byte_count = int(bytes_m.group(1))
                if byte_count >= threshold_bytes:
                    results.append(
                        {
                            "anomaly_type": "data_exfiltration",
                            "source_ip": evt.get("source_ip"),
                            "destination_ip": evt.get("destination_ip"),
                            "bytes_transferred": byte_count,
                            "user": evt.get("user"),
                            "timestamp": evt.get("timestamp"),
                            "raw": evt.get("raw"),
                        }
                    )
            return results

        @staticmethod
        def detect_off_hours_access(events: list[dict]) -> list[dict]:
            """Find access events occurring between 22:00 and 06:00."""
            results: list[dict] = []
            for evt in events:
                ts = evt.get("timestamp")
                if not ts:
                    continue
                # Try to extract hour from various timestamp formats
                hour = None
                # ISO format: 2024-10-28T02:13:45Z
                hm = re.search(r"[T ](\d{2}):\d{2}:\d{2}", ts)
                if hm:
                    hour = int(hm.group(1))
                if hour is None:
                    continue
                if hour >= 22 or hour < 6:
                    results.append(
                        {
                            "anomaly_type": "off_hours_access",
                            "timestamp": ts,
                            "hour": hour,
                            "source_ip": evt.get("source_ip"),
                            "destination_ip": evt.get("destination_ip"),
                            "user": evt.get("user"),
                            "action": evt.get("action"),
                            "message": evt.get("message"),
                        }
                    )
            return results

        @staticmethod
        def extract_stats(events: list[dict]) -> dict:
            """Return summary statistics for a list of parsed events."""
            all_ips: set[str] = set()
            timestamps: list[str] = []
            event_types: dict[str, int] = {}

            for evt in events:
                for key in ("source_ip", "destination_ip"):
                    ip = evt.get(key)
                    if ip:
                        all_ips.add(ip)
                ts = evt.get("timestamp")
                if ts:
                    timestamps.append(ts)
                action = evt.get("action") or "unknown"
                event_types[action] = event_types.get(action, 0) + 1

            time_range = None
            if timestamps:
                time_range = {"earliest": min(timestamps), "latest": max(timestamps)}

            return {
                "total_events": len(events),
                "unique_ips": len(all_ips),
                "time_range": time_range,
                "event_types": event_types,
            }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self, task: dict) -> AgentResult:
        """Execute log analysis based on the task parameters.

        Accepted task keys:
          - log_lines : list[str] -- raw log strings
          - log_source : str      -- path to a log file on disk
          - log_text   : str      -- raw text blob (will be split on newlines)
        """
        lines = self._gather_lines(task)

        if not lines:
            logger.info("No log data provided in task.")
            return AgentResult(
                agent_name=self.name,
                status="no_data",
                summary="No log data available for analysis.",
            )

        # Enforce line cap
        max_lines = config.LOG_MAX_LINES
        if len(lines) > max_lines:
            logger.warning(
                "Log input has %d lines; capping at %d.", len(lines), max_lines
            )
            lines = lines[:max_lines]

        # ---- Parse ----
        events = self.LogParser.parse_lines(lines)
        if not events:
            return AgentResult(
                agent_name=self.name,
                status="no_data",
                summary="Log data could not be parsed into events.",
            )

        stats = self.LogParser.extract_stats(events)
        logger.info(
            "Parsed %d events (%d unique IPs).",
            stats["total_events"],
            stats["unique_ips"],
        )

        # ---- Run rule-based detectors ----
        brute_force_hits = self.LogParser.detect_brute_force(events)
        transfer_hits = self.LogParser.detect_large_transfers(events)
        off_hours_hits = self.LogParser.detect_off_hours_access(events)

        # ---- Build findings from detector results ----
        findings: list[dict] = []

        for bf in brute_force_hits:
            findings.append(
                self._build_anomaly_finding(
                    anomaly_type="brute_force",
                    events=[bf],
                    description=(
                        f"Brute-force / credential-stuffing detected from "
                        f"{bf['source_ip']}: {bf['attempt_count']} failed "
                        f"authentication attempts."
                    ),
                )
            )

        for tx in transfer_hits:
            mb = tx["bytes_transferred"] / (1024 * 1024)
            findings.append(
                self._build_anomaly_finding(
                    anomaly_type="data_exfiltration",
                    events=[tx],
                    description=(
                        f"Unusual data transfer of {mb:,.1f} MB from "
                        f"{tx.get('source_ip', 'unknown')} to "
                        f"{tx.get('destination_ip', 'unknown')}."
                    ),
                )
            )

        # Group off-hours events by user for a cleaner finding
        off_hours_by_user: dict[str, list[dict]] = {}
        for oh in off_hours_hits:
            key = oh.get("user") or oh.get("source_ip") or "unknown"
            off_hours_by_user.setdefault(key, []).append(oh)

        for identity, oh_events in off_hours_by_user.items():
            findings.append(
                self._build_anomaly_finding(
                    anomaly_type="suspicious_access",
                    events=oh_events,
                    description=(
                        f"Off-hours access detected for {identity}: "
                        f"{len(oh_events)} event(s) between 22:00-06:00."
                    ),
                )
            )

        # ---- LLM enrichment ----
        llm_prompt = self._build_llm_prompt(findings, stats, events)
        llm_response = await self._call_llm(
            llm_prompt,
            system_prompt=LOG_ANALYSIS_SYSTEM_PROMPT,
            max_tokens=config.LOG_AGENT_MAX_TOKENS,
            temperature=0.1,
        )
        enriched = self._enrich_with_llm(findings, llm_response)

        summary = self._generate_summary(enriched, stats)

        return AgentResult(
            agent_name=self.name,
            status="success",
            findings=enriched,
            confidence=0.80,
            data_sources=["log_analysis"],
            summary=summary,
            raw_data={
                "total_lines": len(lines),
                "parsed_events": stats["total_events"],
                "brute_force_detections": len(brute_force_hits),
                "large_transfer_detections": len(transfer_hits),
                "off_hours_detections": len(off_hours_hits),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _gather_lines(task: dict) -> list[str]:
        """Extract log lines from whichever task key is populated."""
        # 1. Direct list
        lines: Optional[list[str]] = task.get("log_lines")
        if lines:
            return lines

        # 2. File path
        log_source: Optional[str] = task.get("log_source")
        if log_source:
            path = Path(log_source)
            if path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    return text.splitlines()
                except OSError as exc:
                    logger.error("Failed to read log source %s: %s", log_source, exc)

        # 3. Raw text blob
        log_text: Optional[str] = task.get("log_text")
        if log_text:
            return log_text.splitlines()

        return []

    def _build_anomaly_finding(
        self,
        anomaly_type: str,
        events: list[dict],
        description: str,
    ) -> dict:
        """Create a standardized finding dict from an anomaly detection result."""
        severity = self._anomaly_severity(anomaly_type, events)
        mitre = self._anomaly_mitre(anomaly_type)

        # Collect evidence strings
        evidence: list[str] = []
        for evt in events:
            if isinstance(evt, dict):
                # Add key stats as evidence
                if evt.get("attempt_count"):
                    evidence.append(
                        f"{evt['attempt_count']} failed auth attempts from "
                        f"{evt.get('source_ip', 'unknown')}"
                    )
                if evt.get("bytes_transferred"):
                    mb = evt["bytes_transferred"] / (1024 * 1024)
                    evidence.append(f"{mb:,.1f} MB transferred")
                if evt.get("raw"):
                    evidence.append(f"Sample log: {str(evt['raw'])[:200]}")
                if evt.get("timestamp"):
                    evidence.append(f"Timestamp: {evt['timestamp']}")

        # Determine affected asset from events
        affected_asset = None
        for evt in events:
            if isinstance(evt, dict):
                affected_asset = (
                    evt.get("destination_ip")
                    or evt.get("source_ip")
                    or evt.get("user")
                )
                if affected_asset:
                    break

        return AgentResult.make_finding(
            finding_id=str(uuid.uuid4()),
            finding_type="log_anomaly",
            title=f"[{anomaly_type.upper()}] {description[:100]}",
            description=description,
            severity=severity,
            confidence=0.75,
            affected_asset=affected_asset,
            evidence=evidence,
            mitre_techniques=mitre,
            remediation=self._default_remediation(anomaly_type),
        )

    @staticmethod
    def _anomaly_severity(anomaly_type: str, events: list[dict]) -> str:
        """Map an anomaly type to a severity level, factoring in scale."""
        base_severity: dict[str, str] = {
            "brute_force": "high",
            "data_exfiltration": "critical",
            "privilege_escalation": "critical",
            "lateral_movement": "high",
            "c2_communication": "critical",
            "malware_execution": "critical",
            "policy_violation": "medium",
            "suspicious_access": "medium",
        }
        severity = base_severity.get(anomaly_type, "medium")

        # Escalate brute-force to critical if the attempt count is very high
        if anomaly_type == "brute_force":
            for evt in events:
                if isinstance(evt, dict) and (evt.get("attempt_count", 0) > 100):
                    severity = "critical"
                    break

        # Escalate off-hours/suspicious access if many events are flagged
        if anomaly_type == "suspicious_access" and len(events) > 20:
            severity = "high"

        return severity

    @staticmethod
    def _anomaly_mitre(anomaly_type: str) -> list[str]:
        """Return default MITRE ATT&CK technique IDs for a given anomaly type."""
        mapping: dict[str, list[str]] = {
            "brute_force": ["T1110"],
            "data_exfiltration": ["T1041", "T1567"],
            "privilege_escalation": ["T1078", "T1098"],
            "lateral_movement": ["T1021", "T1076"],
            "c2_communication": ["T1071", "T1105"],
            "malware_execution": ["T1059", "T1204"],
            "policy_violation": ["T1078"],
            "suspicious_access": ["T1078"],
        }
        return mapping.get(anomaly_type, [])

    @staticmethod
    def _default_remediation(anomaly_type: str) -> str:
        """Provide a default remediation recommendation for an anomaly type."""
        remediation_map: dict[str, str] = {
            "brute_force": (
                "Block offending source IP at the perimeter firewall. "
                "Enable account lockout policies. Review targeted accounts "
                "for successful logins."
            ),
            "data_exfiltration": (
                "Isolate the source host immediately. Block the destination "
                "IP. Initiate forensic imaging of the affected system. "
                "Assess potential PHI exposure under HIPAA."
            ),
            "privilege_escalation": (
                "Remove unauthorized privileges immediately. Reset affected "
                "credentials. Audit all recent activity by the compromised account."
            ),
            "lateral_movement": (
                "Isolate affected hosts. Review authentication logs for "
                "compromised credentials. Segment the network to limit spread."
            ),
            "c2_communication": (
                "Block the C2 IP/domain at all egress points. Isolate the "
                "communicating host. Search for additional beaconing activity."
            ),
            "malware_execution": (
                "Isolate the host. Run a full AV/EDR scan. Collect forensic "
                "artifacts. Identify the malware family and check for persistence."
            ),
            "policy_violation": (
                "Review the violation with the responsible user/team. "
                "Update access controls as needed. Document the incident."
            ),
            "suspicious_access": (
                "Verify the access with the account owner. If unauthorized, "
                "reset credentials and review session activity. Restrict "
                "after-hours access for sensitive systems."
            ),
        }
        return remediation_map.get(anomaly_type, "Investigate and respond per incident playbook.")

    @staticmethod
    def _build_llm_prompt(
        findings: list[dict],
        stats: dict,
        events: "list[dict] | None" = None,
    ) -> str:
        """Build a structured production prompt for LLM-based log analysis."""
        log_type = "security_log"
        total_events = stats.get("total_events", 0)
        unique_ips = stats.get("unique_ips", 0)
        time_range_dict = stats.get("time_range") or {}
        time_range = (
            f"{time_range_dict.get('earliest', 'unknown')} — {time_range_dict.get('latest', 'unknown')}"
            if time_range_dict else "unknown"
        )

        # Detected patterns summary from findings
        detected_patterns: list[dict] = []
        brute_force_events: list[dict] = []
        priv_esc_events: list[dict] = []

        for f in findings:
            title = f.get("title", "")
            anomaly_type = title.split("]")[0].strip("[") if "]" in title else "unknown"
            pattern = {
                "anomaly_type": anomaly_type,
                "severity": f.get("severity"),
                "description": f.get("description", "")[:200],
                "mitre_techniques": f.get("mitre_techniques", []),
                "evidence_count": len(f.get("evidence", [])),
            }
            detected_patterns.append(pattern)
            if "BRUTE_FORCE" in title.upper():
                brute_force_events.append(pattern)
            elif "PRIVILEGE" in title.upper() or "PRIV_ESC" in title.upper():
                priv_esc_events.append(pattern)

        # Sample events (first 20) — strip overly large fields
        sample_events: list[dict] = []
        if events:
            for evt in events[:20]:
                sample_events.append(
                    {
                        "timestamp": evt.get("timestamp"),
                        "source_ip": evt.get("source_ip"),
                        "destination_ip": evt.get("destination_ip"),
                        "action": evt.get("action"),
                        "user": evt.get("user"),
                        "message": (evt.get("message") or "")[:150],
                    }
                )

        finding_summaries: list[dict] = [
            {
                "finding_type": f.get("finding_type"),
                "title": f.get("title", "")[:120],
                "severity": f.get("severity"),
                "description": f.get("description", "")[:300],
                "mitre_techniques": f.get("mitre_techniques", []),
            }
            for f in findings
        ]

        return (
            f"Analyze the following parsed security log events and identify anomalies.\n\n"
            f"Log Type: {log_type}\n"
            f"Total Events: {total_events}\n"
            f"Time Range: {time_range}\n"
            f"Unique Source IPs: {unique_ips}\n\n"
            f"Detected Patterns:\n{json.dumps(detected_patterns, indent=2)}\n\n"
            f"Sample Events (first 20):\n{json.dumps(sample_events, indent=2)}\n\n"
            f"Brute Force Candidates: {json.dumps(brute_force_events, indent=2)}\n"
            f"Privilege Escalation Candidates: {json.dumps(priv_esc_events, indent=2)}\n\n"
            f"Rule-based findings ({len(findings)} total):\n"
            f"{json.dumps(finding_summaries, indent=2)}\n\n"
            f"Apply MITRE ATT&CK mapping and severity assessment from your system prompt.\n"
            f"Return ONLY a valid JSON array of anomaly finding objects. No markdown."
        )

    @classmethod
    def _enrich_with_llm(cls, findings: list[dict], llm_response: str) -> list[dict]:
        """Merge LLM analysis back into the rule-based findings."""
        try:
            analyses = cls._parse_llm_json(llm_response)
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.warning("LLM response was not valid JSON; skipping enrichment.")
            return findings

        if not isinstance(analyses, list):
            return findings

        # Match LLM enrichments to findings by index or by type
        for idx, analysis in enumerate(analyses):
            if idx >= len(findings):
                break
            finding = findings[idx]

            # Merge deeper analysis text
            if "analysis" in analysis:
                finding["description"] = analysis["analysis"]

            # Merge MITRE techniques (union of rule-based + LLM)
            if "mitre_techniques" in analysis:
                existing = set(finding.get("mitre_techniques", []))
                existing.update(analysis["mitre_techniques"])
                finding["mitre_techniques"] = sorted(existing)

            # Merge recommended actions into remediation
            if "recommended_actions" in analysis:
                finding["remediation"] = "; ".join(analysis["recommended_actions"])

            # Accept LLM severity upgrade (never downgrade)
            if "severity" in analysis:
                llm_sev = analysis["severity"]
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                current = sev_order.get(finding.get("severity", "low"), 3)
                proposed = sev_order.get(llm_sev, 3)
                if proposed < current:
                    finding["severity"] = llm_sev

        return findings

    @staticmethod
    def _generate_summary(findings: list[dict], stats: dict) -> str:
        """Generate a plain-English summary of the log analysis results."""
        total = len(findings)
        if total == 0:
            return (
                f"Analyzed {stats.get('total_events', 0)} log events. "
                "No anomalies detected."
            )

        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        # Collect distinct anomaly types
        anomaly_types = list(
            {f.get("title", "").split("]")[0].strip("[") for f in findings if f.get("title")}
        )

        parts = [
            f"Analyzed {stats.get('total_events', 0)} log events "
            f"({stats.get('unique_ips', 0)} unique IPs).",
            f"Detected {total} anomal{'y' if total == 1 else 'ies'}.",
        ]
        if critical:
            parts.append(f"{critical} critical.")
        if high:
            parts.append(f"{high} high.")
        if medium:
            parts.append(f"{medium} medium.")
        if anomaly_types:
            parts.append(f"Types: {', '.join(sorted(anomaly_types))}.")

        return " ".join(parts)
