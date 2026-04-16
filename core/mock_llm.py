"""Mock LLM layer — returns realistic fake responses for every agent type."""

import asyncio
import json
import re

import config


class MockLLM:
    """Simulates LLM responses with realistic security-analyst output."""

    @staticmethod
    async def generate(agent_name: str, prompt: str) -> str:
        """Return a realistic mock response based on agent type and prompt content."""
        delay_s = config.MOCK_DELAY_MS / 1000.0
        await asyncio.sleep(delay_s)

        dispatch = {
            "orchestrator": MockLLM._orchestrator_response,
            "orchestrator_parallel": MockLLM._orchestrator_parallel_response,
            "vulnerability_agent": MockLLM._vulnerability_response,
            "threat_intel_agent": MockLLM._threat_intel_response,
            "log_analysis_agent": MockLLM._log_analysis_response,
            "report_agent": MockLLM._report_response,
            "router": MockLLM._router_response,
        }
        handler = dispatch.get(agent_name, MockLLM._default_response)
        return handler(prompt)

    # ------------------------------------------------------------------
    # Per-agent mock handlers
    # ------------------------------------------------------------------

    @staticmethod
    def _orchestrator_response(prompt: str) -> str:
        return json.dumps(
            {
                "synthesis": (
                    "Based on the collected agent findings, the primary risk is a critical "
                    "remote code execution vulnerability actively exploited in the wild. "
                    "Immediate patching is required for all internet-facing assets. "
                    "The vulnerability is listed in the CISA KEV catalog, which mandates "
                    "remediation within the federal deadline."
                ),
                "risk_level": "critical",
                "recommended_actions": [
                    "Patch all affected systems within 24 hours",
                    "Enable WAF rules to block known exploit patterns",
                    "Monitor IDS/IPS for exploitation attempts",
                    "Notify asset owners and schedule emergency change window",
                ],
                "confidence": 0.92,
            },
            indent=2,
        )

    @staticmethod
    def _vulnerability_response(prompt: str) -> str:
        # Try to extract a CVE ID from the prompt for realistic output
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", prompt)
        cve_id = cve_match.group(0) if cve_match else "CVE-2024-38094"

        return json.dumps(
            [
                {
                    "cve_id": cve_id,
                    "priority": "P1",
                    "risk_score": 95,
                    "recommended_action": "patch_immediately",
                    "deadline": "24h",
                    "analysis": (
                        f"{cve_id} is a critical remote code execution vulnerability in "
                        "Microsoft SharePoint Server. The vulnerability allows an authenticated "
                        "attacker with Site Owner permissions to inject and execute arbitrary code "
                        "on the SharePoint Server. This vulnerability is actively exploited in the "
                        "wild and is listed in the CISA Known Exploited Vulnerabilities catalog. "
                        "Healthcare organizations running SharePoint for clinical document management "
                        "are at elevated risk due to the sensitivity of stored PHI data."
                    ),
                    "cvss_breakdown": {
                        "base_score": 9.8,
                        "attack_vector": "NETWORK",
                        "attack_complexity": "LOW",
                        "privileges_required": "NONE",
                        "user_interaction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentiality_impact": "HIGH",
                        "integrity_impact": "HIGH",
                        "availability_impact": "HIGH",
                    },
                    "affected_systems": [
                        "Microsoft SharePoint Server 2016",
                        "Microsoft SharePoint Server 2019",
                        "Microsoft SharePoint Server Subscription Edition",
                    ],
                    "remediation_steps": [
                        "Apply Microsoft security update KB5002606 immediately",
                        "If patching is delayed, restrict Site Owner permissions",
                        "Enable advanced audit logging for SharePoint",
                        "Monitor for suspicious .aspx file uploads",
                    ],
                    "mitre_techniques": ["T1190", "T1059.001"],
                }
            ],
            indent=2,
        )

    @staticmethod
    def _orchestrator_parallel_response(prompt: str) -> str:
        return json.dumps(
            {
                "synthesis": (
                    "Multi-agent assessment complete. Vulnerability analysis identified "
                    "critical CVEs requiring immediate attention, threat intelligence "
                    "confirmed active exploitation by known threat actors, and log analysis "
                    "detected anomalous patterns consistent with lateral movement. "
                    "Recommend activating incident response protocols."
                ),
                "risk_level": "critical",
                "recommended_actions": [
                    "Activate incident response team immediately",
                    "Block identified C2 IP addresses at perimeter firewall",
                    "Patch all critical vulnerabilities within 24 hours",
                    "Isolate affected workstations pending forensic analysis",
                    "Enable enhanced monitoring on all network segments",
                ],
                "confidence": 0.90,
                "agents_consulted": ["vulnerability_agent", "threat_intel_agent", "log_analysis_agent"],
            },
            indent=2,
        )

    @staticmethod
    def _threat_intel_response(prompt: str) -> str:
        # Extract IP from prompt if present
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", prompt)
        ip_addr = ip_match.group(0) if ip_match else "198.51.100.23"

        return json.dumps(
            [
                {
                    "ioc_type": "ip",
                    "value": ip_addr,
                    "verdict": "malicious",
                    "confidence": 0.87,
                    "threat_type": "command_and_control",
                    "associated_malware": ["Cobalt Strike", "SystemBC"],
                    "threat_actor": "Unknown — possibly FIN7 affiliate",
                    "first_seen": "2024-09-15T00:00:00Z",
                    "last_seen": "2024-11-01T12:30:00Z",
                    "sources": ["AlienVault OTX", "AbuseIPDB"],
                    "geo": {"country": "RU", "asn": "AS12345", "org": "Suspicious Hosting LLC"},
                    "abuse_score": 95,
                    "total_reports": 247,
                    "otx_pulse_count": 12,
                    "mitre_techniques": ["T1071.001", "T1105", "T1573.002"],
                    "recommended_actions": [
                        "Block IP at perimeter firewall immediately",
                        "Search SIEM for historical connections to this IP",
                        "Check for lateral movement from any host that contacted this IP",
                    ],
                    "healthcare_context": (
                        "This C2 server has been linked to ransomware campaigns targeting "
                        "healthcare organizations. Immediate containment is critical to "
                        "protect PHI and maintain clinical operations."
                    ),
                }
            ],
            indent=2,
        )

    @staticmethod
    def _log_analysis_response(prompt: str) -> str:
        return json.dumps(
            [
                {
                    "type": "brute_force_attempt",
                    "severity": "high",
                    "source_ip": "203.0.113.45",
                    "target": "vpn-gateway-01",
                    "event_count": 847,
                    "time_window": "2024-10-28T02:00:00Z to 2024-10-28T02:45:00Z",
                    "analysis": (
                        "847 failed authentication attempts from single IP against VPN "
                        "gateway in 45-minute window. Pattern consistent with credential "
                        "stuffing using breached credential lists."
                    ),
                    "mitre_techniques": ["T1110.004"],
                    "recommended_actions": [
                        "Block source IP 203.0.113.45 at perimeter firewall",
                        "Enable account lockout policy on VPN gateway",
                        "Review affected accounts for successful logins",
                    ],
                },
                {
                    "type": "data_exfiltration_indicator",
                    "severity": "critical",
                    "source_host": "ws-radiology-12",
                    "destination": "198.51.100.23",
                    "bytes_transferred": 2_147_483_648,
                    "time_window": "2024-10-28T03:15:00Z to 2024-10-28T04:00:00Z",
                    "analysis": (
                        "2.1 GB transferred to external IP from radiology workstation "
                        "outside business hours. Destination IP has known C2 associations. "
                        "High risk of PHI exfiltration from medical imaging systems."
                    ),
                    "mitre_techniques": ["T1041", "T1567"],
                    "recommended_actions": [
                        "Isolate ws-radiology-12 immediately",
                        "Block outbound traffic to 198.51.100.23",
                        "Begin forensic imaging of affected workstation",
                    ],
                },
                {
                    "type": "privilege_escalation",
                    "severity": "high",
                    "source_host": "dc-01.internal.clinic",
                    "account": "svc_backup",
                    "analysis": (
                        "Service account svc_backup added to Domain Admins group via "
                        "net group command. This account should not have DA privileges. "
                        "Possible credential compromise or insider threat."
                    ),
                    "mitre_techniques": ["T1078.002", "T1098"],
                    "recommended_actions": [
                        "Remove svc_backup from Domain Admins immediately",
                        "Reset svc_backup credentials",
                        "Audit all recent changes by svc_backup account",
                    ],
                },
            ],
            indent=2,
        )

    @staticmethod
    def _report_response(prompt: str) -> str:
        return json.dumps(
            {
                "report_title": "CyberSentinel Threat Assessment — 2024-10-28",
                "report_type": "executive",
                "executive_summary": (
                    "Three critical findings require immediate attention. "
                    "A remote code execution vulnerability (CVE-2024-38094) is actively "
                    "exploited and affects our SharePoint infrastructure. Additionally, "
                    "log analysis detected potential data exfiltration from a radiology "
                    "workstation. Recommend immediate incident response activation."
                ),
                "risk_rating": "CRITICAL",
                "key_findings": [
                    "CVE-2024-38094 — Critical RCE in SharePoint, actively exploited",
                    "C2 communication detected from radiology workstation",
                    "Credential stuffing attack against VPN gateway",
                ],
                "recommendations": [
                    "Activate incident response team immediately",
                    "Patch SharePoint servers within 24 hours",
                    "Isolate ws-radiology-12 for forensic analysis",
                    "Implement MFA on VPN gateway",
                ],
                "sections": [
                    "Critical Vulnerabilities",
                    "Threat Intelligence",
                    "Log Analysis Anomalies",
                    "Remediation Timeline",
                    "Compliance Impact (HIPAA)",
                ],
                "compliance_notes": (
                    "Potential HIPAA breach notification required if PHI exfiltration "
                    "from radiology workstation is confirmed. 60-day notification "
                    "deadline applies per 45 CFR 164.408."
                ),
            },
            indent=2,
        )

    @staticmethod
    def _router_response(prompt: str) -> str:
        return json.dumps(
            {
                "intent": "cve_lookup",
                "target_agents": ["vulnerability_agent"],
                "confidence": 0.95,
                "reasoning": "Input contains a CVE identifier pattern — routing to vulnerability agent.",
            },
            indent=2,
        )

    @staticmethod
    def _default_response(prompt: str) -> str:
        return json.dumps(
            {
                "response": "Acknowledged. Processed input with mock LLM.",
                "agent": "unknown",
                "confidence": 0.5,
            },
            indent=2,
        )
