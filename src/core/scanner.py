"""
scanner.py
Master orchestrator for SentinelScan.

Responsibilities
Scan Docker Images
Analyze Dockerfiles
Calculate Risk
Generate Recommendations
This class combines all backend modules into one interface.
"""
from datetime import datetime
from typing import Dict
from src.core.docker_handler import DockerHandler
from src.core.dockerfile_analyzer import DockerfileAnalyzer
from src.core.secret_scanner import SecretScanner
from src.core.vulnerability_scanner import VulnerabilityScanner
from src.core.risk_engine import RiskEngine
from src.core.recommendation_engine import RecommendationEngine


class Scanner:
    """
    Main SentinelScan backend orchestrator.
    """

    def __init__(self):
        self.docker = DockerHandler()
        self.dockerfile = DockerfileAnalyzer()
        self.secret = SecretScanner()
        self.vulnerability = VulnerabilityScanner()
        self.risk = RiskEngine()
        self.recommendation = RecommendationEngine()

    # -----------------------------------------------------
    # Scan Docker Image
    # -----------------------------------------------------
    def scan_image(
        self,
        image_reference: str,
    ) -> Dict:
        result = {
            "success": False,
            "metadata": {},
            "vulnerabilities": [],
            "risk": {},
            "recommendations": [],
            "errors": [],
        }
        # ---------------------------------------------
        # Metadata
        # ---------------------------------------------
        try:
            result["metadata"] = (
                self.docker.get_metadata(
                    image_reference
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Metadata: {error}"
            )
        # ---------------------------------------------
        # Vulnerability Scan
        # ---------------------------------------------
        try:
            result["vulnerabilities"] = (
                self.vulnerability.scan(
                    image_reference
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Vulnerability Scanner: {error}"
            )
        # ---------------------------------------------
        # Risk Engine
        # ---------------------------------------------
        try:
            findings = []
            findings.extend(
                result["vulnerabilities"]
            )
            result["risk"] = (
                self.risk.calculate(
                    findings
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Risk Engine: {error}"
            )
        # ---------------------------------------------
        # Recommendation Engine
        # ---------------------------------------------
        try:
            result["recommendations"] = (
                self.recommendation.generate(
                    result["vulnerabilities"]
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Recommendation Engine: {error}"
            )
        result["success"] = (
            len(result["errors"]) == 0
        )
        return result

    # -----------------------------------------------------
    # Analyze Dockerfile
    # -----------------------------------------------------
    def analyze_dockerfile(
        self,
        dockerfile_path: str,
    ) -> Dict:
        result = {
            "success": False,
            "dockerfileFindings": [],
            "secrets": [],
            "risk": {},
            "recommendations": [],
            "errors": [],
        }
        # ---------------------------------------------
        # Dockerfile Analysis
        # ---------------------------------------------
        try:
            analysis = self.dockerfile.analyze(
                dockerfile_path
            )
            result["dockerfileFindings"] = (
                analysis["findings"]
            )
        except Exception as error:
            result["errors"].append(
                f"Dockerfile Analyzer: {error}"
            )
        # ---------------------------------------------
        # Secret Scan
        # ---------------------------------------------
        try:
            with open(
                dockerfile_path,
                "r",
                encoding="utf-8",
            ) as file:
                dockerfile_text = file.read()
            result["secrets"] = (
                self.secret.scan(
                    dockerfile_text
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Secret Scanner: {error}"
            )
        # ---------------------------------------------
        # Risk Engine
        # ---------------------------------------------
        try:
            findings = []
            findings.extend(
                result["dockerfileFindings"]
            )
            findings.extend(
                result["secrets"]
            )
            result["risk"] = (
                self.risk.calculate(
                    findings
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Risk Engine: {error}"
            )
        # ---------------------------------------------
        # Recommendation Engine
        # ---------------------------------------------
        try:
            findings = []
            findings.extend(
                result["dockerfileFindings"]
            )
            findings.extend(
                result["secrets"]
            )
            result["recommendations"] = (
                self.recommendation.generate(
                    findings
                )
            )
        except Exception as error:
            result["errors"].append(
                f"Recommendation Engine: {error}"
            )
        result["success"] = (
            len(result["errors"]) == 0
        )
        return result

    # -----------------------------------------------------
    # Complete Scan
    # -----------------------------------------------------
    def scan_complete(
        self,
        image_reference: str,
        dockerfile_path: str | None = None,
    ) -> Dict:
        result = {
            "success": False,
            "id": image_reference.replace(":", "-"),
            "kind": (
                "dockerfile"
                if dockerfile_path
                else "image"
            ),
            "target": (
                dockerfile_path
                if dockerfile_path
                else image_reference
            ),
            "createdAt": datetime.utcnow().isoformat(),
            "metadata": None,
            "findings": [],
            "vulnerabilities": [],
            "secrets": [],
            "recommendations": [],
            "score": 100,
            "riskLevel": "safe",
            "counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            # Keep these for internal compatibility
            "risk": {},
            "summary": {},
            "errors": [],
        }
        # ---------------------------------------------
        # Image Scan
        # ---------------------------------------------
        image_result = self.scan_image(
            image_reference
        )
        result["metadata"] = image_result["metadata"]
        result["vulnerabilities"] = (
            image_result["vulnerabilities"]
        )
        result["errors"].extend(
            image_result["errors"]
        )
        # ---------------------------------------------
        # Dockerfile Analysis
        # ---------------------------------------------
        if dockerfile_path:
            dockerfile_result = (
                self.analyze_dockerfile(
                    dockerfile_path
                )
            )
            result["findings"] = (
                dockerfile_result[
                    "dockerfileFindings"
                ]
            )
            result["secrets"] = (
                dockerfile_result[
                    "secrets"
                ]
            )
            result["errors"].extend(
                dockerfile_result["errors"]
            )
        # ---------------------------------------------
        # Risk
        # ---------------------------------------------
        try:
            all_findings = []
            all_findings.extend(
                result["findings"]
            )
            all_findings.extend(
                result["vulnerabilities"]
            )
            all_findings.extend(
                result["secrets"]
            )
            risk = self.risk.calculate(
                all_findings
            )
            result["risk"] = risk
            result["score"] = risk["score"]
            result["riskLevel"] = (
                risk["riskLevel"]
            )
            result["counts"] = (
                risk["counts"]
            )
        except Exception as error:
            result["errors"].append(
                f"Risk Engine: {error}"
            )
        # ---------------------------------------------
        # Recommendations
        # ---------------------------------------------
        try:
            recommendations = (
                self.recommendation.generate(
                    all_findings
                )
            )
            mapped = []
            for recommendation in recommendations:
                mapped.append(
                    {
                        "id": recommendation.get(
                            "id",
                            "",
                        ),
                        "priority": recommendation.get(
                            "severity",
                            recommendation.get(
                                "priority",
                                "info",
                            ),
                        ),
                        "title": recommendation.get(
                            "title",
                            "",
                        ),
                        "detail": recommendation.get(
                            "recommendation",
                            recommendation.get(
                                "detail",
                                "",
                            ),
                        ),
                    }
                )
            result["recommendations"] = mapped
        except Exception as error:
            result["errors"].append(
                f"Recommendation Engine: {error}"
            )
        # ---------------------------------------------
        # Summary
        # ---------------------------------------------
        result["summary"] = {
            "dockerfileIssues": len(
                result["findings"]
            ),
            "vulnerabilities": len(
                result["vulnerabilities"]
            ),
            "secrets": len(
                result["secrets"]
            ),
            "recommendations": len(
                result["recommendations"]
            ),
            "totalIssues": (
                len(result["findings"])
                + len(result["vulnerabilities"])
                + len(result["secrets"])
            ),
        }
        result["success"] = (
            len(result["errors"]) == 0
        )
        return result

    # -----------------------------------------------------
    # Backward Compatibility
    # -----------------------------------------------------
    def scan(
        self,
        image_reference: str,
        dockerfile_path: str | None = None,
    ) -> Dict:
        return self.scan_complete(
            image_reference,
            dockerfile_path,
        )


# =========================================================
# Testing
# =========================================================
if __name__ == "__main__":
    scanner = Scanner()
    report = scanner.scan_complete(
        image_reference="nginx:latest",
        dockerfile_path="sample_data/Dockerfile",
    )
    print()
    print("============== SentinelScan ==============")
    print()
    print(
        f"Success : {report['success']}"
    )
    print()
    print("========== Summary ==========")
    print(
        f"Metadata                : {'Yes' if report['metadata'] else 'No'}"
    )
    print(
        f"Dockerfile Findings     : {len(report['findings'])}"
    )
    print(
        f"Vulnerabilities         : {len(report['vulnerabilities'])}"
    )
    print(
        f"Secrets                 : {len(report['secrets'])}"
    )
    print(
        f"Recommendations         : {len(report['recommendations'])}"
    )
    if report["risk"]:
        print()
        print(
            f"Security Score          : {report['risk']['score']}"
        )
        print(
            f"Risk Level              : {report['risk']['riskLevel']}"
        )
    if report["errors"]:
        print()
        print("Errors")
        for error in report["errors"]:
            print(f"- {error}")