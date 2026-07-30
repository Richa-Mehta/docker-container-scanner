"""
recommendation_engine.py

SentinelScan Recommendation Engine

Responsible for:
- Prioritizing findings
- Generating actionable recommendations
- Returning frontend/API compatible recommendations

Compatible with:
- Dockerfile Analyzer
- Secret Scanner
- Vulnerability Scanner
- Risk Engine
- Scanner
- CLI
- Flask API
- Lovable Frontend
"""

from typing import Dict, List


class RecommendationEngine:
    """
    Generates prioritized security recommendations
    from scanner findings.
    """

    def __init__(self):

        self.priority_order = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5,
        }

    # -----------------------------------------------------
    # Internal Helper
    # -----------------------------------------------------

    def _build_recommendation(
        self,
        finding: Dict,
    ) -> Dict:

        severity = (
            finding.get("severity", "low")
            .lower()
            .strip()
        )

        title = finding.get(
            "title",
            "Security Finding",
        )

        recommendation = finding.get(
            "recommendation",
            "Review this finding."
        )

        return {
            "id": finding.get(
                "ruleId",
                finding.get("id", "UNKNOWN"),
            ),
            "priority": severity,
            "title": title,
            "detail": recommendation,
        }

    # -----------------------------------------------------
    # Sort Findings
    # -----------------------------------------------------

    def sort_findings(
        self,
        findings: List[Dict],
    ) -> List[Dict]:

        return sorted(
            findings,
            key=lambda finding: (
                self.priority_order.get(
                    finding.get(
                        "severity",
                        "info"
                    ).lower(),
                    99,
                )
            ),
        )

    # -----------------------------------------------------
    # Remove Duplicate Recommendations
    # -----------------------------------------------------

    def remove_duplicates(
        self,
        recommendations: List[Dict],
    ) -> List[Dict]:

        unique = []
        seen = set()

        for recommendation in recommendations:

            key = (
                recommendation["title"],
                recommendation["priority"],
            )

            if key not in seen:

                seen.add(key)
                unique.append(recommendation)

        return unique

    # -----------------------------------------------------
    # Generate Recommendations
    # -----------------------------------------------------

    def generate(
        self,
        findings: List[Dict],
    ) -> List[Dict]:

        if not findings:
            return []

        findings = self.sort_findings(findings)

        recommendations = []

        for finding in findings:

            recommendations.append(
                self._build_recommendation(
                    finding
                )
            )

            recommendations = self.remove_duplicates(
            recommendations
        )

        return recommendations

    # -----------------------------------------------------
    # Public API
    # -----------------------------------------------------

    def build(
        self,
        findings: List[Dict],
        risk_summary: Dict = None,
    ) -> List[Dict]:
        """
        Builds the final recommendation list.

        Compatible with:
            - Risk Engine
            - Scanner
            - Flask API
            - Lovable Frontend
        """

        recommendations = self.generate(findings)

        # Future enhancement:
        # risk_summary can later be used to inject
        # overall recommendations based on score.

        return recommendations

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    def summary(
        self,
        findings: List[Dict],
        risk_summary: Dict = None,
    ) -> Dict:

        recommendations = self.build(
            findings,
            risk_summary,
        )

        return {
            "totalRecommendations": len(recommendations),
            "recommendations": recommendations,
        }


# ==========================================================
# Testing
# ==========================================================

if __name__ == "__main__":

    sample_findings = [

        {
            "ruleId": "DKR001",
            "severity": "critical",
            "title": "Hardcoded AWS Secret",
            "recommendation": (
                "Remove the secret and inject it "
                "using a secret manager."
            ),
        },

        {
            "ruleId": "DKR005",
            "severity": "high",
            "title": "Container runs as root",
            "recommendation": (
                "Create a non-root user and "
                "switch using USER."
            ),
        },

        {
            "ruleId": "DKR010",
            "severity": "medium",
            "title": "SSH Port Exposed",
            "recommendation": (
                "Avoid exposing SSH inside containers."
            ),
        },

        {
            "ruleId": "DKR020",
            "severity": "low",
            "title": "Using latest image tag",
            "recommendation": (
                "Pin a specific image version."
            ),
        },

    ]

    engine = RecommendationEngine()

    result = engine.summary(sample_findings)

    print("\n========== Recommendation Engine ==========\n")

    print(
        f"Recommendations Generated : "
        f"{result['totalRecommendations']}\n"
    )

    for recommendation in result["recommendations"]:

        print(
            f"[{recommendation['priority'].upper()}] "
            f"{recommendation['title']}"
        )

        print(
            f"Recommendation : "
            f"{recommendation['detail']}"
        )

        print("-" * 55)


# ==========================================================
# Module Exports
# ==========================================================

__all__ = [
    "RecommendationEngine",
]