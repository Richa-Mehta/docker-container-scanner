"""
secret_scanner.py

SentinelScan Secret Scanner

Detects:
- AWS Access Keys
- AWS Secret Keys
- GitHub Personal Access Tokens
- GitLab Tokens
- Google API Keys
- Slack Tokens
- Stripe Keys
- JWT Tokens
- Bearer Tokens
- Generic Passwords
- API Keys
- Private Keys
- SSH Keys

Compatible with:
- Dockerfile Analyzer
- Scanner
- Risk Engine
- Recommendation Engine
- CLI
- Flask API
- Lovable Frontend
"""

import re
from typing import Dict, List


class SecretScanner:

    def __init__(self):

        self.rules = [

            {
                "name": "AWS Access Key",
                "severity": "critical",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "recommendation":
                    "Remove the AWS Access Key and rotate it immediately."
            },

            {
                "name": "AWS Secret Key",
                "severity": "critical",
                "pattern":
                    r"(?i)aws(.{0,20})?(secret|access)?.{0,3}[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
                "recommendation":
                    "Remove the AWS Secret Key and rotate credentials."
            },

            {
                "name": "GitHub Token",
                "severity": "critical",
                "pattern":
                    r"gh[pousr]_[A-Za-z0-9]{36,255}",
                "recommendation":
                    "Remove GitHub Personal Access Tokens."
            },

            {
                "name": "GitLab Token",
                "severity": "critical",
                "pattern":
                    r"glpat-[A-Za-z0-9_-]{20,}",
                "recommendation":
                    "Remove GitLab Personal Access Tokens."
            },

            {
                "name": "Google API Key",
                "severity": "critical",
                "pattern":
                    r"AIza[0-9A-Za-z\\-_]{35}",
                "recommendation":
                    "Store API Keys inside a Secret Manager."
            },

            {
                "name": "Slack Token",
                "severity": "critical",
                "pattern":
                    r"xox[baprs]-[A-Za-z0-9-]{10,}",
                "recommendation":
                    "Rotate Slack tokens immediately."
            },

            {
                "name": "Stripe Secret",
                "severity": "critical",
                "pattern":
                    r"sk_live_[A-Za-z0-9]{20,}",
                "recommendation":
                    "Never commit Stripe live secrets."
            },

            {
                "name": "JWT Token",
                "severity": "high",
                "pattern":
                    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                "recommendation":
                    "Do not hardcode JWT tokens."
            },

            {
                "name": "Bearer Token",
                "severity": "high",
                "pattern":
                    r"Bearer\s+[A-Za-z0-9._\-]+",
                "recommendation":
                    "Use runtime authentication instead."
            },

            {
                "name": "Generic Password",
                "severity": "high",
                "pattern":
                    r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})",
                "recommendation":
                    "Move passwords into environment variables."
            },

            {
                "name": "API Key",
                "severity": "high",
                "pattern":
                    r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})",
                "recommendation":
                    "Store API keys in a secret manager."
            },

            {
                "name": "Private Key",
                "severity": "critical",
                "pattern":
                    r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----",
                "recommendation":
                    "Never commit private keys."
            },

            {
                "name": "SSH Private Key",
                "severity": "critical",
                "pattern":
                    r"-----BEGIN OPENSSH PRIVATE KEY-----",
                "recommendation":
                    "Remove SSH private keys immediately."
            }

        ]

    # -----------------------------------------------------
    # Mask Secret
    # -----------------------------------------------------

    def mask(self, secret: str) -> str:

        if len(secret) <= 8:
            return "*" * len(secret)

        return (
            secret[:3]
            + "*" * (len(secret) - 6)
            + secret[-3:]
        )

    # -----------------------------------------------------
    # Placeholder Detection
    # -----------------------------------------------------

    def is_placeholder(
        self,
        value: str,
    ) -> bool:

        placeholders = [

            "example",
            "changeme",
            "password",
            "your_password",
            "dummy",
            "test",
            "sample",
            "secret",
            "apikey",
            "api_key",
            "token"

        ]

        value = value.lower()

        return any(
            word in value
            for word in placeholders
        )

    # -----------------------------------------------------
    # Scan
    # -----------------------------------------------------

    def scan(
        self,
        text: str,
    ) -> List[Dict]:

        findings = []

        for line_number, line in enumerate(text.splitlines(), start=1):

            for rule in self.rules:

                matches = re.finditer(
                    rule["pattern"],
                    line,
                )

                for match in matches:

                    value = match.group(0)

                    if self.is_placeholder(value):
                        continue

                    findings.append(
                        {
                            "id": f"secret-{len(findings)+1}",
                            "type": rule["name"],
                            "severity": rule["severity"],
                            "line": line_number,
                            "masked": self.mask(value),
                            "recommendation": rule["recommendation"],
                        }
                    )

        return self.remove_duplicates(findings)

    # -----------------------------------------------------
    # Remove Duplicate Findings
    # -----------------------------------------------------

    def remove_duplicates(
        self,
        findings: List[Dict],
    ) -> List[Dict]:

        unique = []
        seen = set()

        for finding in findings:

            key = (
                finding["type"],
                finding["line"],
                finding["masked"],
            )

            if key not in seen:

                seen.add(key)
                unique.append(finding)

        return unique

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    def summary(
        self,
        text: str,
    ) -> Dict:

        findings = self.scan(text)

        return {

            "totalSecrets": len(findings),

            "secrets": findings

        }


# ==========================================================
# Testing
# ==========================================================

if __name__ == "__main__":

    sample = """
FROM ubuntu:latest

ENV AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF

ENV PASSWORD=SuperSecret123

ENV API_KEY=abcdefghijklmnopqrstuvwxyz

ENV TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.xyz

-----BEGIN OPENSSH PRIVATE KEY-----

"""

    scanner = SecretScanner()

    result = scanner.summary(sample)

    print("\n========== Secret Scanner ==========\n")

    print(
        f"Secrets Found : "
        f"{result['totalSecrets']}\n"
    )

    for secret in result["secrets"]:

        print(
            f"[{secret['severity'].upper()}] "
            f"{secret['type']}"
        )

        print(
            f"Line           : "
            f"{secret['line']}"
        )

        print(
            f"Masked Secret  : "
            f"{secret['masked']}"
        )

        print(
            f"Recommendation : "
            f"{secret['recommendation']}"
        )

        print("-" * 60)


# ==========================================================
# Module Exports
# ==========================================================

__all__ = [
    "SecretScanner",
]