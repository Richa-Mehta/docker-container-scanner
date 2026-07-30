"""
dockerfile_analyzer.py

Core Dockerfile Analyzer for SentinelScan.

Responsibilities
----------------
• Read a Dockerfile
• Validate input
• Execute all Dockerfile security rules
• Generate standardized findings
• Count severities
• Return analyzer output compatible with:

    - CLI
    - REST API
    - Lovable Frontend
    - Risk Engine
    - Recommendation Engine
"""

from pathlib import Path
from typing import Dict, List

from src.rules.dockerfile_rules import run_all_rules


class DockerfileAnalyzer:
    """
    Main Dockerfile analyzer.
    """

    def __init__(self):
        pass

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    def validate(self, dockerfile_path: str) -> None:
        """
        Validates Dockerfile path.
        """

        path = Path(dockerfile_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Dockerfile not found: {dockerfile_path}"
            )

        if not path.is_file():
            raise ValueError(
                "Provided path is not a file."
            )

    # ---------------------------------------------------------
    # Reading
    # ---------------------------------------------------------

    def read(self, dockerfile_path: str) -> List[str]:
        """
        Reads Dockerfile.
        """

        self.validate(dockerfile_path)

        with open(
            dockerfile_path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            return file.readlines()

    # ---------------------------------------------------------
    # Severity Counts
    # ---------------------------------------------------------

    def severity_counts(
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

            severity = finding["severity"]

            if severity in counts:
                counts[severity] += 1

        return counts

    # ---------------------------------------------------------
    # Analyze
    # ---------------------------------------------------------

    def analyze(
        self,
        dockerfile_path: str,
    ) -> Dict:

        lines = self.read(dockerfile_path)

        findings = run_all_rules(lines)

        counts = self.severity_counts(findings)

        return {
            "target": Path(dockerfile_path).name,
            "findings": findings,
            "counts": counts,
            "total_findings": len(findings),
        }


if __name__ == "__main__":

    analyzer = DockerfileAnalyzer()

    result = analyzer.analyze("sample.Dockerfile")

    print("\n========== Dockerfile Analysis ==========\n")

    print(f"Target : {result['target']}")
    print(f"Total Findings : {result['total_findings']}\n")

    print(result["counts"])

    print("\nFindings:\n")

    for finding in result["findings"]:

        print(
            f"[{finding['severity'].upper()}] "
            f"{finding['title']}"
        )

        print(f"Line : {finding['line']}")
        print(f"Rule : {finding['ruleId']}")
        print()