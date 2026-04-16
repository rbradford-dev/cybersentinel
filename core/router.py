"""Intent classifier — routes user input to the correct agent(s)."""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("cybersentinel.router")

# Regex patterns for entity extraction
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Keyword sets for intent classification
VULN_KEYWORDS = {
    "vulnerability", "vulnerabilities", "cve", "patch", "patching", "cvss",
    "exploit", "exploited", "unpatched", "scan", "remediate", "remediation",
}
THREAT_KEYWORDS = {
    "threat", "ioc", "indicator", "malware", "phishing", "ransomware",
    "apt", "campaign", "c2", "command and control", "ttps",
}
LOG_KEYWORDS = {
    "log", "logs", "alert", "alerts", "anomaly", "anomalies", "siem",
    "event", "events", "detection", "baseline", "correlation",
}
REPORT_KEYWORDS = {
    "report", "summary", "executive", "briefing", "assessment",
    "compliance", "audit", "generate", "export",
}
ASSESS_KEYWORDS = {
    "full", "comprehensive", "complete", "overall", "assess",
    "investigate", "deep", "thorough",
}

# Agent registry — maps intent to agent names
INTENT_AGENT_MAP: dict[str, list[str]] = {
    "cve_lookup": ["vulnerability_agent"],
    "vulnerability_scan": ["vulnerability_agent"],
    "ip_check": ["threat_intel_agent"],
    "ip_enrichment": ["threat_intel_agent"],
    "threat_intel": ["threat_intel_agent"],
    "log_analysis": ["log_analysis_agent"],
    "generate_report": ["report_agent"],
    "full_assessment": ["vulnerability_agent", "threat_intel_agent", "log_analysis_agent"],
    "general": ["vulnerability_agent"],
}


@dataclass
class RoutingDecision:
    """The output of the router — tells the orchestrator where to dispatch."""

    intent: str
    target_agents: list[str] = field(default_factory=list)
    extracted_entities: dict = field(default_factory=dict)
    confidence: float = 0.0
    reasoning: str = ""


def classify(user_input: str) -> RoutingDecision:
    """Classify user input and return a routing decision."""
    text = user_input.lower().strip()
    entities: dict = {}

    # ------------------------------------------------------------------
    # Entity extraction
    # ------------------------------------------------------------------
    cve_ids = CVE_PATTERN.findall(user_input)
    if cve_ids:
        entities["cve_ids"] = [c.upper() for c in cve_ids]

    ipv4s = IPV4_PATTERN.findall(user_input)
    if ipv4s:
        entities["ipv4_addresses"] = ipv4s

    domains = DOMAIN_PATTERN.findall(user_input)
    # Filter out common false positives
    domains = [d for d in domains if not d.endswith((".py", ".js", ".json", ".txt"))]
    if domains:
        entities["domains"] = domains

    # ------------------------------------------------------------------
    # Intent classification (rule-based, highest-confidence-first)
    # ------------------------------------------------------------------
    if cve_ids:
        decision = RoutingDecision(
            intent="cve_lookup",
            target_agents=["vulnerability_agent"],
            extracted_entities=entities,
            confidence=0.97,
            reasoning=f"Detected CVE identifier(s): {', '.join(cve_ids)}",
        )
        logger.info("Routed to cve_lookup (CVE pattern match): %s", cve_ids)
        return decision

    if ipv4s:
        decision = RoutingDecision(
            intent="ip_check",
            target_agents=["threat_intel_agent"],
            extracted_entities=entities,
            confidence=0.95,
            reasoning=f"Detected IP address(es): {', '.join(ipv4s)}",
        )
        logger.info("Routed to ip_check (IPv4 pattern match): %s", ipv4s)
        return decision

    words = set(re.findall(r"[a-z]+", text))

    vuln_overlap = words & VULN_KEYWORDS
    threat_overlap = words & THREAT_KEYWORDS
    log_overlap = words & LOG_KEYWORDS
    report_overlap = words & REPORT_KEYWORDS
    assess_overlap = words & ASSESS_KEYWORDS

    # Check for file path pattern (e.g., /var/log/auth.log, C:\logs\security.evtx)
    has_log_path = bool(re.search(r"(?:/[\w./]+\.(?:log|evtx|csv)|\b\w:\\[\w\\]+\.(?:log|evtx|csv))", user_input))
    log_path_boost = 0.3 if has_log_path else 0.0

    # Score each category
    scores: dict[str, float] = {
        "vulnerability_scan": len(vuln_overlap) / max(len(VULN_KEYWORDS), 1),
        "threat_intel": len(threat_overlap) / max(len(THREAT_KEYWORDS), 1),
        "log_analysis": (len(log_overlap) / max(len(LOG_KEYWORDS), 1)) + log_path_boost,
        "generate_report": len(report_overlap) / max(len(REPORT_KEYWORDS), 1),
        "full_assessment": len(assess_overlap) / max(len(ASSESS_KEYWORDS), 1),
    }

    best_intent = max(scores, key=lambda k: scores[k])
    best_score = scores[best_intent]

    if best_score > 0:
        decision = RoutingDecision(
            intent=best_intent,
            target_agents=INTENT_AGENT_MAP.get(best_intent, ["vulnerability_agent"]),
            extracted_entities=entities,
            confidence=min(0.6 + best_score, 0.95),
            reasoning=f"Keyword match for '{best_intent}' (score {best_score:.2f})",
        )
        logger.info("Routed to %s (keyword match, score=%.2f)", best_intent, best_score)
        return decision

    # Fallback
    decision = RoutingDecision(
        intent="general",
        target_agents=["vulnerability_agent"],
        extracted_entities=entities,
        confidence=0.3,
        reasoning="No strong intent signal — defaulting to general/vulnerability agent",
    )
    logger.info("Routed to general (fallback)")
    return decision


def classify_structured(task: dict) -> RoutingDecision:
    """Classify a structured task dict and return a routing decision."""
    task_type = task.get("type", "")
    entities: dict = {}

    if task.get("cve_id"):
        entities["cve_ids"] = [task["cve_id"]]
    if task.get("keyword"):
        entities["keyword"] = task["keyword"]
    if task.get("ip"):
        entities["ipv4_addresses"] = [task["ip"]]
    if task.get("log_source"):
        entities["log_source"] = task["log_source"]
    if task.get("report_type"):
        entities["report_type"] = task["report_type"]

    intent_map: dict[str, str] = {
        "cve_lookup": "cve_lookup",
        "vulnerability_scan": "vulnerability_scan",
        "ip_check": "ip_check",
        "ip_enrichment": "ip_enrichment",
        "threat_intel": "threat_intel",
        "log_analysis": "log_analysis",
        "generate_report": "generate_report",
        "full_assessment": "full_assessment",
    }

    intent = intent_map.get(task_type, "general")
    agents = INTENT_AGENT_MAP.get(intent, ["vulnerability_agent"])

    return RoutingDecision(
        intent=intent,
        target_agents=agents,
        extracted_entities=entities,
        confidence=0.99,
        reasoning=f"Structured input with explicit type='{task_type}'",
    )
