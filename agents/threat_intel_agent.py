"""Threat intelligence agent — enriches IOCs via AlienVault OTX and AbuseIPDB.

Queries AlienVault OTX and AbuseIPDB to enrich indicators of compromise
(IPs, domains) and produces confidence-scored threat assessments with
MITRE ATT&CK mapping and healthcare-context prioritization.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import config
from core.agent_result import AgentResult
from core.base_agent import BaseAgent

logger = logging.getLogger("cybersentinel.agents.threat_intel")

THREAT_INTEL_SYSTEM_PROMPT = """\
You are a threat intelligence analyst for a major healthcare system. \
Analyze the provided IOC enrichment data and produce a structured threat assessment.

For each IOC, assess:
- Verdict: malicious | suspicious | benign
- Confidence: 0.0-1.0
- Threat type: command_and_control | scanner | bruteforce | malware_distribution | phishing | spam | benign
- Associated MITRE ATT&CK techniques
- Recommended actions for healthcare SOC

Healthcare context: IOCs associated with ransomware, data exfiltration, or \
medical device targeting should receive elevated priority. Patient data \
protection and clinical system availability are paramount.

Output: Valid JSON array of IOC assessment objects. No markdown. No preamble.\
"""


class ThreatIntelAgent(BaseAgent):
    """Enriches IOCs using AlienVault OTX and AbuseIPDB threat intelligence feeds."""

    name = "threat_intel_agent"
    description = "IOC enrichment via AlienVault OTX, AbuseIPDB"
    capabilities = ["ip_check", "domain_check", "ioc_enrichment", "ip_enrichment"]
    model = config.SUBAGENT_MODEL

    async def run(self, task: dict) -> AgentResult:
        """Execute IOC enrichment based on the task parameters."""
        from integrations.alienvault_client import AlienVaultClient
        from integrations.abuseipdb_client import AbuseIPDBClient

        otx = AlienVaultClient()
        abuseipdb = AbuseIPDBClient()
        data_sources: list[str] = []
        findings: list[dict] = []

        # ---- Extract IOCs from the task ----
        ips: list[str] = []
        domains: list[str] = []

        single_ip: Optional[str] = task.get("ip")
        ip_list: list[str] = task.get("ipv4_addresses", [])
        single_domain: Optional[str] = task.get("domain")
        domain_list: list[str] = task.get("domains", [])

        if single_ip:
            ips.append(single_ip)
        ips.extend(ip_list)

        if single_domain:
            domains.append(single_domain)
        domains.extend(domain_list)

        # Deduplicate while preserving order
        ips = list(dict.fromkeys(ips))
        domains = list(dict.fromkeys(domains))

        if not ips and not domains:
            return AgentResult(
                agent_name=self.name,
                status="no_data",
                data_sources=data_sources,
                summary="No IOCs (IPs or domains) found in the task.",
            )

        # ---- Enrich IP addresses ----
        for ip in ips:
            try:
                abuse_data = await abuseipdb.check_ip(ip)
                if abuse_data:
                    if "AbuseIPDB" not in data_sources:
                        data_sources.append("AbuseIPDB")

                otx_data = await otx.get_ip_reputation(ip)
                if otx_data:
                    if "AlienVault_OTX" not in data_sources:
                        data_sources.append("AlienVault_OTX")

                # Fetch associated malware samples if OTX returned data
                malware_data: list[dict] = []
                if otx_data:
                    malware_data = await otx.get_ip_malware(ip)

                finding = self._build_ip_finding(ip, abuse_data, otx_data, malware_data)
                findings.append(finding)

            except Exception as exc:
                logger.warning("IP enrichment failed for %s: %s", ip, exc)
                # Create a minimal finding so the IP is still tracked
                findings.append(
                    AgentResult.make_finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type="threat_intel",
                        title=f"IOC Enrichment (partial): {ip}",
                        description=f"Enrichment partially failed for {ip}: {exc}",
                        severity="low",
                        confidence=0.3,
                        affected_asset=ip,
                        evidence=[f"Enrichment error: {exc}"],
                    )
                )

        # ---- Enrich domains ----
        for domain in domains:
            try:
                otx_data = await otx.get_domain_reputation(domain)
                if otx_data:
                    if "AlienVault_OTX" not in data_sources:
                        data_sources.append("AlienVault_OTX")

                finding = self._build_domain_finding(domain, otx_data)
                findings.append(finding)

            except Exception as exc:
                logger.warning("Domain enrichment failed for %s: %s", domain, exc)
                findings.append(
                    AgentResult.make_finding(
                        finding_id=str(uuid.uuid4()),
                        finding_type="threat_intel",
                        title=f"IOC Enrichment (partial): {domain}",
                        description=f"Enrichment partially failed for {domain}: {exc}",
                        severity="low",
                        confidence=0.3,
                        affected_asset=domain,
                        evidence=[f"Enrichment error: {exc}"],
                    )
                )

        # ---- Call LLM for enriched analysis ----
        llm_prompt = self._build_llm_prompt(findings)
        llm_response = await self._call_llm(llm_prompt, THREAT_INTEL_SYSTEM_PROMPT)
        enriched = self._enrich_with_llm(findings, llm_response)

        summary = self._generate_summary(enriched)

        return AgentResult(
            agent_name=self.name,
            status="success",
            findings=enriched,
            confidence=0.85,
            data_sources=list(set(data_sources)),
            summary=summary,
            raw_data={"ip_count": len(ips), "domain_count": len(domains)},
        )

    # ------------------------------------------------------------------
    # Building findings from raw enrichment data
    # ------------------------------------------------------------------

    def _build_ip_finding(
        self,
        ip: str,
        abuse_data: dict,
        otx_data: dict,
        malware_data: list[dict],
    ) -> dict:
        """Convert raw AbuseIPDB + OTX data into a standard finding dict."""
        evidence: list[str] = []

        # ---- AbuseIPDB evidence ----
        abuse_score: int = abuse_data.get("abuseConfidenceScore", 0)
        total_reports: int = abuse_data.get("totalReports", 0)
        country: str = abuse_data.get("countryCode", "Unknown")
        isp: str = abuse_data.get("isp", "Unknown")
        usage_type: str = abuse_data.get("usageType", "Unknown")
        domain_name: str = abuse_data.get("domain", "")

        if abuse_data:
            evidence.append(f"AbuseIPDB confidence score: {abuse_score}%")
            evidence.append(f"AbuseIPDB total reports: {total_reports}")
            evidence.append(f"Country: {country} | ISP: {isp}")
            if usage_type:
                evidence.append(f"Usage type: {usage_type}")
            if domain_name:
                evidence.append(f"Associated domain: {domain_name}")

            # Include abuse category breakdown if present
            categories = abuse_data.get("reports", [])
            category_ids: set[int] = set()
            for report in categories[:50]:  # Cap iteration
                for cat_id in report.get("categories", []):
                    category_ids.add(cat_id)
            if category_ids:
                from integrations.abuseipdb_client import AbuseIPDBClient
                cat_names = [
                    AbuseIPDBClient.get_abuse_category_name(cid)
                    for cid in sorted(category_ids)
                ]
                evidence.append(f"Abuse categories: {', '.join(cat_names)}")

        # ---- OTX evidence ----
        pulse_info = otx_data.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)
        reputation: int = otx_data.get("reputation", 0)

        if otx_data:
            evidence.append(f"OTX pulse count: {pulse_count}")
            if reputation:
                evidence.append(f"OTX reputation score: {reputation}")

            # Extract pulse names for context
            pulses = pulse_info.get("pulses", [])
            for pulse in pulses[:5]:
                pulse_name = pulse.get("name", "")
                if pulse_name:
                    evidence.append(f"OTX pulse: {pulse_name[:120]}")

        # ---- Malware evidence ----
        if malware_data:
            evidence.append(f"OTX associated malware samples: {len(malware_data)}")
            for sample in malware_data[:3]:
                hash_val = sample.get("hash", "unknown")
                evidence.append(f"Malware hash: {hash_val}")

        # ---- Determine severity ----
        severity = self._determine_severity(abuse_score, pulse_count)

        # ---- Confidence ----
        confidence = 0.5
        if abuse_data and otx_data:
            confidence = 0.9
        elif abuse_data or otx_data:
            confidence = 0.7

        # ---- MITRE techniques ----
        mitre_techniques: list[str] = []
        if abuse_score >= 50 or pulse_count >= 5:
            mitre_techniques.append("T1071")  # Application Layer Protocol
        if malware_data:
            mitre_techniques.append("T1587.001")  # Develop Capabilities: Malware

        # ---- Build title ----
        verdict = "Malicious" if abuse_score >= 80 else (
            "Suspicious" if abuse_score >= 25 or pulse_count >= 3 else "Low Risk"
        )
        title = f"Threat Intel — {ip}: {verdict} (abuse={abuse_score}%, pulses={pulse_count})"

        # ---- Description ----
        description = (
            f"IP {ip} was enriched via AbuseIPDB and AlienVault OTX. "
            f"Abuse confidence score: {abuse_score}%, total reports: {total_reports}, "
            f"OTX pulse count: {pulse_count}. "
            f"Country: {country}, ISP: {isp}."
        )
        if malware_data:
            description += f" {len(malware_data)} associated malware sample(s) found."

        return AgentResult.make_finding(
            finding_id=str(uuid.uuid4()),
            finding_type="threat_intel",
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            affected_asset=ip,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            remediation=self._ip_remediation(severity, abuse_score),
        )

    def _build_domain_finding(self, domain: str, otx_data: dict) -> dict:
        """Convert raw OTX domain data into a standard finding dict."""
        evidence: list[str] = []

        pulse_info = otx_data.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)
        whois = otx_data.get("whois", "")

        if otx_data:
            evidence.append(f"OTX pulse count: {pulse_count}")
            if whois:
                evidence.append("WHOIS data available")

            # Extract pulse names
            pulses = pulse_info.get("pulses", [])
            for pulse in pulses[:5]:
                pulse_name = pulse.get("name", "")
                if pulse_name:
                    evidence.append(f"OTX pulse: {pulse_name[:120]}")

            # Alexa ranking (if present)
            alexa = otx_data.get("alexa")
            if alexa:
                evidence.append(f"Alexa ranking: {alexa}")

        # Severity based on pulse count alone (no abuse score for domains)
        if pulse_count >= 10:
            severity = "critical"
        elif pulse_count >= 5:
            severity = "high"
        elif pulse_count >= 2:
            severity = "medium"
        else:
            severity = "low"

        confidence = 0.7 if otx_data else 0.4

        mitre_techniques: list[str] = []
        if pulse_count >= 3:
            mitre_techniques.append("T1071")  # Application Layer Protocol
            mitre_techniques.append("T1583.001")  # Acquire Infrastructure: Domains

        verdict = "Malicious" if pulse_count >= 10 else (
            "Suspicious" if pulse_count >= 2 else "Low Risk"
        )
        title = f"Threat Intel — {domain}: {verdict} (pulses={pulse_count})"

        description = (
            f"Domain {domain} was enriched via AlienVault OTX. "
            f"OTX pulse count: {pulse_count}."
        )
        if whois:
            description += " WHOIS data present."

        remediation = None
        if pulse_count >= 5:
            remediation = (
                f"Block domain {domain} at DNS/proxy level. "
                "Investigate any internal hosts that resolved or connected to this domain. "
                "Check for data exfiltration or C2 activity."
            )
        elif pulse_count >= 2:
            remediation = (
                f"Monitor traffic to {domain}. "
                "Add to watchlist and investigate connections from clinical systems."
            )

        return AgentResult.make_finding(
            finding_id=str(uuid.uuid4()),
            finding_type="threat_intel",
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            affected_asset=domain,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            remediation=remediation,
        )

    # ------------------------------------------------------------------
    # Severity and remediation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_severity(abuse_score: int, otx_pulse_count: int) -> str:
        """Determine finding severity from abuse score and OTX pulse count.

        Rules (evaluated in order):
        - abuse_score >= 80 OR pulse_count >= 10 -> critical
        - abuse_score >= 50 OR pulse_count >= 5  -> high
        - abuse_score >= 25 OR pulse_count >= 2  -> medium
        - otherwise                               -> low
        """
        if abuse_score >= 80 or otx_pulse_count >= 10:
            return "critical"
        if abuse_score >= 50 or otx_pulse_count >= 5:
            return "high"
        if abuse_score >= 25 or otx_pulse_count >= 2:
            return "medium"
        return "low"

    @staticmethod
    def _ip_remediation(severity: str, abuse_score: int) -> Optional[str]:
        """Generate remediation guidance for an IP finding."""
        if severity == "critical":
            return (
                "Immediately block this IP at the perimeter firewall. "
                "Search SIEM for all connections to/from this IP in the last 30 days. "
                "Isolate any internal hosts that communicated with it. "
                "Escalate to incident response if clinical systems are affected."
            )
        if severity == "high":
            return (
                "Block this IP at the perimeter firewall. "
                "Review recent connections in SIEM and investigate any internal contacts. "
                "Add to threat intelligence blocklist."
            )
        if severity == "medium":
            return (
                "Add this IP to the monitoring watchlist. "
                "Investigate if any clinical or HIPAA-regulated systems have connected to it. "
                "Consider blocking if associated with healthcare-targeting campaigns."
            )
        return None

    # ------------------------------------------------------------------
    # LLM integration
    # ------------------------------------------------------------------

    @staticmethod
    def _build_llm_prompt(findings: list[dict]) -> str:
        """Build the prompt for LLM-based threat assessment."""
        summary_data = []
        for f in findings:
            summary_data.append(
                {
                    "ioc": f.get("affected_asset"),
                    "finding_type": f.get("finding_type"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence"),
                    "title": f.get("title", "")[:120],
                    "evidence": f.get("evidence", [])[:6],
                }
            )
        return (
            "Analyze these IOC enrichment results and provide a structured "
            "threat assessment for each indicator:\n\n"
            + json.dumps(summary_data, indent=2)
        )

    @staticmethod
    def _enrich_with_llm(findings: list[dict], llm_response: str) -> list[dict]:
        """Merge LLM analysis back into findings where possible."""
        try:
            analyses = json.loads(llm_response)
        except (json.JSONDecodeError, TypeError):
            return findings

        if isinstance(analyses, list):
            # Build a lookup by IOC value (IP or domain)
            analysis_map: dict[str, dict] = {}
            for a in analyses:
                ioc = a.get("ioc") or a.get("ip") or a.get("domain") or a.get("indicator")
                if ioc:
                    analysis_map[ioc] = a

            for f in findings:
                asset = f.get("affected_asset", "")
                a = analysis_map.get(asset)
                if a:
                    # Enrich description with LLM analysis
                    if "analysis" in a:
                        f["description"] = a["analysis"]
                    # Enrich verdict into the title if provided
                    if "verdict" in a:
                        f["evidence"].append(f"LLM verdict: {a['verdict']}")
                    if "threat_type" in a:
                        f["evidence"].append(f"LLM threat type: {a['threat_type']}")
                    if "recommended_actions" in a:
                        actions = a["recommended_actions"]
                        if isinstance(actions, list):
                            f["remediation"] = "; ".join(actions)
                        elif isinstance(actions, str):
                            f["remediation"] = actions
                    if "mitre_techniques" in a:
                        f["mitre_techniques"] = a["mitre_techniques"]
                    # Update confidence from LLM if provided
                    if "confidence" in a and isinstance(a["confidence"], (int, float)):
                        # Average the existing confidence with LLM confidence
                        existing = f.get("confidence", 0.5)
                        f["confidence"] = round((existing + a["confidence"]) / 2, 2)

        return findings

    @staticmethod
    def _generate_summary(findings: list[dict]) -> str:
        """Generate a plain English summary of threat intelligence findings."""
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        ips = sum(
            1 for f in findings
            if f.get("affected_asset") and "." in f.get("affected_asset", "")
            and f.get("affected_asset", "").replace(".", "").isdigit()
        )
        domains = total - ips

        parts = [f"Enriched {total} IOC{'s' if total != 1 else ''}."]
        if ips:
            parts.append(f"{ips} IP{'s' if ips != 1 else ''}.")
        if domains:
            parts.append(f"{domains} domain{'s' if domains != 1 else ''}.")
        if critical:
            parts.append(f"{critical} critical.")
        if high:
            parts.append(f"{high} high.")
        if medium:
            parts.append(f"{medium} medium.")
        if critical or high:
            parts.append("Immediate review recommended for healthcare SOC.")
        return " ".join(parts)
