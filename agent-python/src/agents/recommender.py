from typing import Any, Dict, List, Optional


class RecommenderAgent:
    def suggest(
        self,
        analysis_result: Dict[str, Any],
        source: Optional[str] = None,
        original_doc: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        level = analysis_result.get("risk_level", "LOW")
        evidence = analysis_result.get("evidence", {})
        recommendations: List[str] = []

        if level == "CRITICAL":
            recommendations.extend(
                [
                    "Isolate affected systems or services immediately if exposure is confirmed.",
                    "Apply vendor patch or mitigation with emergency priority.",
                    "Review access, authentication and application logs for the last 24-72 hours.",
                ]
            )
        elif level == "HIGH":
            recommendations.extend(
                [
                    "Accelerate patching/mitigation in the next maintenance window.",
                    "Restrict exposed services, ports or vulnerable endpoints where possible.",
                    "Increase monitoring for exploitation attempts and suspicious outbound traffic.",
                ]
            )
        elif level == "MEDIUM":
            recommendations.extend(
                [
                    "Add the issue to the priority watch list.",
                    "Validate hardening controls and compensating mitigations.",
                    "Track vendor advisories and exposure status.",
                ]
            )
        else:
            recommendations.extend(
                [
                    "Keep the indicator or issue under routine monitoring.",
                    "Record the finding for threat intelligence reference.",
                ]
            )

        related_urlhaus_count = evidence.get("related_urlhaus_count", 0)
        related_dread_count = evidence.get("related_dread_count", 0)
        dread_categories = evidence.get("dread_categories", []) or evidence.get("categories", [])
        tags = evidence.get("tags", [])

        if related_urlhaus_count > 0:
            recommendations.append(
                "Add related IOC values to firewall, DNS, proxy or EDR block/watch lists after validation."
            )

        if related_dread_count > 0:
            recommendations.append(
                "Perform analyst review because cross-source discussion suggests elevated attacker interest."
            )

        if "exploit_sale" in dread_categories or "access_sale" in dread_categories:
            recommendations.append(
                "Treat matching assets as potentially targeted and validate external exposure immediately."
            )

        if source == "urlhaus":
            recommendations.append(
                "Search historical network logs and DNS/proxy telemetry for this IOC."
            )

        if source == "cve":
            recommendations.append(
                "Confirm whether vulnerable product/version is present in the environment."
            )

        if "cobaltstrike" in tags or "botnet" in tags:
            recommendations.append(
                "Prioritize endpoint telemetry review for beaconing, staging or command-and-control patterns."
            )

        return self._deduplicate(recommendations)

    def _deduplicate(self, items: List[str]) -> List[str]:
        seen = set()
        result = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result