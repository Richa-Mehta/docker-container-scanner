"""
risk_engine.py

SentinelScan Risk Scoring Engine

Responsible for:
- Counting findings
- Calculating Security Score
- Determining Overall Risk Level

Compatible with:
- CLI
- Scanner
- Dockerfile Analyzer
- Secret Scanner
- Vulnerability Scanner
- Recommendation Engine
- Flask API
- Lovable Frontend
"""

from typing import Dict, List


class RiskEngine:
    """
    Calculates overall security score
    from analyzer findings.
    """

    def __init__(self):

        self.weights = {
            "critical": 25,
            "high": 12,
            "medium": 5,
            "low": 2,
            "info": 0.5,
        }

        self.maximum_score = 100

    # -----------------------------------------------------
    # Severity Counting
    # -----------------------------------------------------

    def count_severity(
        self,
        findings: List[Dict],
    ) -> Dict[str, int]:

        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:

            severity = (
                finding.get("severity", "")
                .lower()
                .strip()
            )

            if severity in counts:
                counts[severity] += 1

        return counts

    # -----------------------------------------------------
    # Score Calculation
    # -----------------------------------------------------

    def calculate_score(
        self,
        counts: Dict[str, int],
    ) -> int:
        """
        Returns score between 0 and 100.
        """

        score = self.maximum_score

        score -= counts["critical"] * self.weights["critical"]
        score -= counts["high"] * self.weights["high"]
        score -= counts["medium"] * self.weights["medium"]
        score -= counts["low"] * self.weights["low"]
        score -= counts["info"] * self.weights["info"]

        if score < 0:
            score = 0

        return round(score)

    # -----------------------------------------------------
    # Risk Level
    # -----------------------------------------------------

    def calculate_risk_level(
        self,
        score: int,
    ) -> str:

        if score >= 90:
            return "safe"

        elif score >= 75:
            return "low"

        elif score >= 50:
            return "medium"

        elif score >= 25:
            return "high"

        return "critical"

    # -----------------------------------------------------
    # Public API
    # -----------------------------------------------------

    def calculate(
        self,
        findings: List[Dict],
    ) -> Dict:

        counts = self.count_severity(findings)

        score = self.calculate_score(counts)

        risk_level = self.calculate_risk_level(score)

        return {
            "score": score,
            "riskLevel": risk_level,
            "counts": counts,
        }
    
        # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    def summary(
        self,
        findings: List[Dict],
    ) -> Dict:
        """
        Returns a complete risk summary.
        """

        result = self.calculate(findings)

        return {
            "score": result["score"],
            "riskLevel": result["riskLevel"],
            "counts": result["counts"],
            "totalFindings": len(findings),
        }

    # -----------------------------------------------------
    # Future Compatibility
    # -----------------------------------------------------

    def merge(
        self,
        *finding_lists: List[Dict],
    ) -> List[Dict]:
        """
        Merge findings from multiple scanners.

        Compatible with:
            - Dockerfile Analyzer
            - Secret Scanner
            - Vulnerability Scanner
            - Image Scanner
        """

        merged = []

        for finding_list in finding_lists:

            if finding_list:

                merged.extend(finding_list)

        return merged


# ==========================================================
# Testing
# ==========================================================

if __name__ == "__main__":

    sample_findings = [

        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "info"},
    ]

    engine = RiskEngine()

    result = engine.summary(sample_findings)

    print("\n========== Risk Engine ==========\n")

    print(f"Security Score : {result['score']}/100")
    print(f"Risk Level     : {result['riskLevel'].upper()}")

    print("\nSeverity Counts")

    for severity, count in result["counts"].items():

        print(f"{severity.capitalize():10}: {count}")

    print(f"\nTotal Findings : {result['totalFindings']}")


# ==========================================================
# Module Exports
# ==========================================================

__all__ = [
    "RiskEngine",
]