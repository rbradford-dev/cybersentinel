"""Report generation agent — produces executive, technical, and compliance reports."""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import config
from core.agent_result import AgentResult
from core.base_agent import BaseAgent

logger = logging.getLogger("cybersentinel.agents.report")

REPORT_SYSTEM_PROMPT = """\
You are a security report writer for a major healthcare system. Generate clear, \
actionable reports from security findings data.

Report types:
- executive: High-level summary for CISO/leadership. Focus on business impact, \
risk ratings, and top recommendations. Keep technical jargon minimal.
- technical: Detailed technical report for SOC analysts. Include all CVE details, \
IOCs, MITRE ATT&CK mappings, and step-by-step remediation.
- compliance: HIPAA-focused compliance report. Highlight findings that affect PHI, \
suggest controls, and note regulatory deadlines.

Structure the report with clear sections. Output valid JSON with keys: \
report_title, report_type, executive_summary, risk_rating, key_findings, \
recommendations, sections, compliance_notes (if applicable).\
"""


class ReportAgent(BaseAgent):
    """Generates executive, technical, and compliance security reports from findings."""

    name = "report_agent"
    description = "Automated security report generation"
    capabilities = ["executive_report", "technical_report", "compliance_report"]
    model = config.SUBAGENT_MODEL

    async def run(self, task: dict) -> AgentResult:
        """Generate a security report from stored findings.

        Task keys:
            report_type: "executive" | "technical" | "compliance" (default "executive")
        """
        from db.repository import Repository

        repo = Repository()

        # 1. Determine report type
        report_type = task.get("report_type", "executive")
        if report_type not in ("executive", "technical", "compliance"):
            report_type = "executive"

        # 2. Fetch recent findings from the database
        findings = await repo.get_findings(limit=config.REPORT_MAX_FINDINGS)

        # 3. Fetch CVE-specific findings
        cve_findings = await repo.get_cve_findings()

        # 4. If nothing to report, return early
        if not findings and not cve_findings:
            return AgentResult(
                agent_name=self.name,
                status="no_data",
                data_sources=["sqlite"],
                summary="No findings to report.",
            )

        # 5. Build the prompt with findings data
        prompt = self._build_report_prompt(report_type, findings, cve_findings)

        # 6. Call the LLM
        llm_response = await self._call_llm(prompt, REPORT_SYSTEM_PROMPT)

        # 7. Parse the LLM response into a structured report
        report_data = self._parse_report(llm_response)
        report_data["report_type"] = report_type
        report_data["generated_at"] = datetime.now(timezone.utc).isoformat()
        report_data["findings_analyzed"] = len(findings)
        report_data["cve_findings_analyzed"] = len(cve_findings)

        # 8. Create a single "report" finding
        report_title = report_data.get("report_title", f"{report_type.title()} Security Report")
        executive_summary = report_data.get(
            "executive_summary",
            self._generate_summary(report_data),
        )

        finding = AgentResult.make_finding(
            finding_id=str(uuid.uuid4()),
            finding_type="report",
            title=report_title,
            description=executive_summary,
            severity="info",
            confidence=0.9,
        )

        summary = self._generate_summary(report_data)

        return AgentResult(
            agent_name=self.name,
            status="success",
            findings=[finding],
            confidence=0.9,
            data_sources=["sqlite"],
            summary=summary,
            raw_data=report_data,
        )

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_report_prompt(
        report_type: str,
        findings: list[dict],
        cve_findings: list[dict],
    ) -> str:
        """Build the LLM prompt containing findings data for report generation."""
        # Summarize general findings
        findings_summary: list[dict] = []
        for f in findings:
            findings_summary.append(
                {
                    "finding_type": f.get("finding_type", ""),
                    "title": f.get("title", "")[:150],
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence"),
                    "status": f.get("status", ""),
                    "agent_name": f.get("agent_name", ""),
                }
            )

        # Summarize CVE findings
        cve_summary: list[dict] = []
        for c in cve_findings:
            cve_summary.append(
                {
                    "cve_id": c.get("cve_id", ""),
                    "cvss_score": c.get("cvss_score"),
                    "severity": c.get("severity", ""),
                    "is_kev": bool(c.get("is_kev")),
                    "kev_due_date": c.get("kev_due_date"),
                    "remediation": c.get("remediation", ""),
                    "status": c.get("status", ""),
                }
            )

        # Severity breakdown
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        kev_count = sum(1 for c in cve_findings if c.get("is_kev"))

        prompt_parts = [
            f"Generate a {report_type} security report from the following findings data.",
            "",
            f"Total findings: {len(findings)}",
            f"CVE findings: {len(cve_findings)}",
            f"Actively exploited (CISA KEV): {kev_count}",
            f"Severity breakdown: {json.dumps(severity_counts)}",
            "",
            "=== FINDINGS ===",
            json.dumps(findings_summary, indent=2),
            "",
            "=== CVE FINDINGS ===",
            json.dumps(cve_summary, indent=2),
        ]

        if report_type == "compliance":
            prompt_parts.extend(
                [
                    "",
                    "=== COMPLIANCE CONTEXT ===",
                    "This is a HIPAA-regulated healthcare environment.",
                    "Highlight any findings that may affect Protected Health Information (PHI).",
                    "Note relevant HIPAA Security Rule safeguards (Administrative, Physical, Technical).",
                    "Include regulatory deadlines and required remediation timelines.",
                ]
            )
        elif report_type == "executive":
            prompt_parts.extend(
                [
                    "",
                    "=== EXECUTIVE CONTEXT ===",
                    "Target audience: CISO and senior leadership.",
                    "Focus on business risk, potential financial impact, and strategic recommendations.",
                    "Minimize technical jargon. Use risk ratings (Critical/High/Medium/Low).",
                ]
            )
        elif report_type == "technical":
            prompt_parts.extend(
                [
                    "",
                    "=== TECHNICAL CONTEXT ===",
                    "Target audience: SOC analysts and security engineers.",
                    "Include full CVE details, CVSS vectors, IOC data, and MITRE ATT&CK technique IDs.",
                    "Provide step-by-step remediation procedures.",
                ]
            )

        return "\n".join(prompt_parts)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_report(llm_response: str) -> dict:
        """Parse the LLM response into a structured report dict.

        Attempts to extract JSON from the response. Falls back to a minimal
        structure wrapping the raw text if parsing fails.
        """
        # Try direct JSON parse first
        try:
            report = json.loads(llm_response)
            if isinstance(report, dict):
                return report
        except (json.JSONDecodeError, TypeError):
            pass

        # Try to find JSON embedded in the response (e.g., wrapped in markdown fences)
        text = llm_response.strip()
        json_start = text.find("{")
        json_end = text.rfind("}")
        if json_start != -1 and json_end != -1 and json_end > json_start:
            try:
                report = json.loads(text[json_start : json_end + 1])
                if isinstance(report, dict):
                    return report
            except (json.JSONDecodeError, TypeError):
                pass

        # Fallback: wrap the raw text in a minimal report structure
        logger.warning("Could not parse LLM response as JSON; using raw text fallback.")
        return {
            "report_title": "Security Report",
            "report_type": "executive",
            "executive_summary": text[:500] if text else "Report generation produced no content.",
            "risk_rating": "unknown",
            "key_findings": [],
            "recommendations": [],
            "sections": [],
            "raw_llm_output": text,
        }

    # ------------------------------------------------------------------
    # Summary generation
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_summary(report_data: dict) -> str:
        """Generate a concise plain-text summary from the report data."""
        parts: list[str] = []

        report_type = report_data.get("report_type", "executive")
        parts.append(f"{report_type.title()} report generated.")

        findings_count = report_data.get("findings_analyzed", 0)
        cve_count = report_data.get("cve_findings_analyzed", 0)
        if findings_count or cve_count:
            parts.append(f"Analyzed {findings_count} findings and {cve_count} CVEs.")

        risk_rating = report_data.get("risk_rating")
        if risk_rating and risk_rating != "unknown":
            parts.append(f"Overall risk: {risk_rating}.")

        key_findings = report_data.get("key_findings", [])
        if key_findings:
            parts.append(f"{len(key_findings)} key findings highlighted.")

        recommendations = report_data.get("recommendations", [])
        if recommendations:
            parts.append(f"{len(recommendations)} recommendations provided.")

        return " ".join(parts)
