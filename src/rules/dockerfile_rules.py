"""
SentinelScan
Docker Container Security Scanner

dockerfile_rules.py

Central rule engine for Dockerfile security analysis.

This module defines:
    • Rule metadata
    • Security finding schema
    • Detection rule registration
    • Shared helper utilities
    • Regex patterns
    • Severity ordering

Every rule returns standardized findings compatible with:

    • CLI
    • Scanner Engine
    • Risk Engine
    • Recommendation Engine
    • JSON API
    • Lovable Frontend

Author:
    Richa Mehta

Project:
    SentinelScan
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from typing import List
from typing import Dict
from typing import Optional


# ============================================================
# Severity Order
# ============================================================

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


# ============================================================
# Categories
# ============================================================

CATEGORY_CONFIGURATION = "configuration"
CATEGORY_PRIVILEGE = "privilege"
CATEGORY_NETWORK = "network"
CATEGORY_SECRET = "secret"
CATEGORY_SUPPLY_CHAIN = "supply-chain"
CATEGORY_BEST_PRACTICE = "best-practice"


# ============================================================
# Rule Definition
# ============================================================

@dataclass(slots=True)
class Rule:
    """
    Represents a single Dockerfile security rule.
    """

    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    recommendation: str
    detector: Callable


# ============================================================
# Finding Factory
# ============================================================

_finding_counter = 0


def create_finding(
    *,
    rule: Rule,
    line: int,
    evidence: str,
) -> Dict:
    """
    Creates a standardized finding.

    Compatible with:

    - CLI
    - Risk Engine
    - Recommendation Engine
    - Web API
    """

    global _finding_counter

    _finding_counter += 1

    return {
        "id": f"finding-{_finding_counter}",
        "ruleId": rule.rule_id,
        "title": rule.title,
        "description": rule.description,
        "severity": rule.severity,
        "category": rule.category,
        "line": line,
        "evidence": evidence.strip(),
        "recommendation": rule.recommendation,
    }


# ============================================================
# Shared Helpers
# ============================================================

def normalize(line: str) -> str:
    """
    Lowercase + strip helper.
    """

    return line.strip().lower()


def starts_with(line: str, keyword: str) -> bool:
    """
    Case-insensitive instruction check.
    """

    return normalize(line).startswith(keyword.lower())


def contains(line: str, value: str) -> bool:
    """
    Case-insensitive substring check.
    """

    return value.lower() in normalize(line)


# ============================================================
# Regular Expressions
# ============================================================

AWS_ACCESS_KEY_REGEX = re.compile(
    r"AKIA[0-9A-Z]{16}"
)

AWS_SECRET_REGEX = re.compile(
    r"(?i)aws(.{0,20})?(secret|key)"
)

PASSWORD_REGEX = re.compile(
    r"(?i)(password|passwd|pwd)\s*=\s*.+"
)

SECRET_REGEX = re.compile(
    r"(?i)(secret)\s*=\s*.+"
)

TOKEN_REGEX = re.compile(
    r"(?i)(token)\s*=\s*.+"
)

API_KEY_REGEX = re.compile(
    r"(?i)(api[_-]?key)\s*=\s*.+"
)

PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN(.*?)PRIVATE KEY-----"
)

JWT_REGEX = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

SSH_PORT_REGEX = re.compile(
    r"EXPOSE\s+22\b",
    re.IGNORECASE,
)

CHMOD_777_REGEX = re.compile(
    r"chmod\s+777",
    re.IGNORECASE,
)

CURL_PIPE_REGEX = re.compile(
    r"curl.+\|\s*(sh|bash)",
    re.IGNORECASE,
)

WGET_PIPE_REGEX = re.compile(
    r"wget.+\|\s*(sh|bash)",
    re.IGNORECASE,
)

SUDO_REGEX = re.compile(
    r"\bsudo\b",
    re.IGNORECASE,
)


# ============================================================
# Rule Registry
# ============================================================

RULES: List[Rule] = []

# ============================================================
# Detection Rules
# ============================================================


def rule_latest_tag(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR001",
        title="Using latest image tag",
        description="Mutable tags reduce reproducibility and may introduce unexpected changes.",
        severity="medium",
        category=CATEGORY_CONFIGURATION,
        recommendation="Pin the base image to a specific version or digest.",
        detector=rule_latest_tag,
    )

    for line_no, line in enumerate(lines, start=1):
        if starts_with(line, "FROM") and ":latest" in line:
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_root_user(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR002",
        title="Container runs as root",
        description="Running containers as root increases attack surface.",
        severity="high",
        category=CATEGORY_PRIVILEGE,
        recommendation="Create and switch to a dedicated non-root user.",
        detector=rule_root_user,
    )

    for line_no, line in enumerate(lines, start=1):
        if starts_with(line, "USER") and normalize(line) == "user root":
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_missing_user(lines: List[str]) -> List[Dict]:
    findings = []

    has_user = any(starts_with(line, "USER") for line in lines)

    if not has_user:

        rule = Rule(
            rule_id="DKR003",
            title="No USER instruction",
            description="Containers should explicitly define a non-root runtime user.",
            severity="medium",
            category=CATEGORY_PRIVILEGE,
            recommendation="Add a USER instruction near the end of the Dockerfile.",
            detector=rule_missing_user,
        )

        findings.append(create_finding(
            rule=rule,
            line=0,
            evidence="Dockerfile"
        ))

    return findings


def rule_add_instruction(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR004",
        title="ADD instruction used",
        description="COPY is generally safer and more predictable than ADD.",
        severity="low",
        category=CATEGORY_BEST_PRACTICE,
        recommendation="Replace ADD with COPY unless archive extraction is required.",
        detector=rule_add_instruction,
    )

    for line_no, line in enumerate(lines, start=1):
        if starts_with(line, "ADD"):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_missing_healthcheck(lines: List[str]) -> List[Dict]:
    findings = []

    has_healthcheck = any(
        starts_with(line, "HEALTHCHECK")
        for line in lines
    )

    if not has_healthcheck:

        rule = Rule(
            rule_id="DKR005",
            title="Missing HEALTHCHECK",
            description="Containers should expose a health check for orchestration platforms.",
            severity="low",
            category=CATEGORY_BEST_PRACTICE,
            recommendation="Add a HEALTHCHECK instruction.",
            detector=rule_missing_healthcheck,
        )

        findings.append(create_finding(
            rule=rule,
            line=0,
            evidence="Dockerfile"
        ))

    return findings


def rule_expose_ssh(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR006",
        title="SSH Port Exposed",
        description="Running SSH inside containers is generally discouraged.",
        severity="medium",
        category=CATEGORY_NETWORK,
        recommendation="Avoid exposing port 22 unless absolutely required.",
        detector=rule_expose_ssh,
    )

    for line_no, line in enumerate(lines, start=1):
        if SSH_PORT_REGEX.search(line):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_chmod_777(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR007",
        title="chmod 777 detected",
        description="World-writable permissions can introduce privilege escalation risks.",
        severity="high",
        category=CATEGORY_CONFIGURATION,
        recommendation="Grant only the minimum required permissions.",
        detector=rule_chmod_777,
    )

    for line_no, line in enumerate(lines, start=1):
        if CHMOD_777_REGEX.search(line):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_curl_pipe(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR008",
        title="curl | sh detected",
        description="Executing remote scripts directly is dangerous.",
        severity="high",
        category=CATEGORY_SUPPLY_CHAIN,
        recommendation="Download, verify integrity, then execute.",
        detector=rule_curl_pipe,
    )

    for line_no, line in enumerate(lines, start=1):
        if CURL_PIPE_REGEX.search(line):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_wget_pipe(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR009",
        title="wget | bash detected",
        description="Executing downloaded scripts directly is unsafe.",
        severity="high",
        category=CATEGORY_SUPPLY_CHAIN,
        recommendation="Verify downloaded content before execution.",
        detector=rule_wget_pipe,
    )

    for line_no, line in enumerate(lines, start=1):
        if WGET_PIPE_REGEX.search(line):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings


def rule_sudo_usage(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR010",
        title="sudo command used",
        description="sudo is unnecessary inside containers.",
        severity="low",
        category=CATEGORY_PRIVILEGE,
        recommendation="Run commands directly or use USER appropriately.",
        detector=rule_sudo_usage,
    )

    for line_no, line in enumerate(lines, start=1):
        if SUDO_REGEX.search(line):
            findings.append(create_finding(rule=rule, line=line_no, evidence=line))

    return findings

# ============================================================
# Secret Detection Rules
# ============================================================

def rule_password_secret(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR011",
        title="Possible hardcoded password",
        description="Hardcoded passwords inside Dockerfiles can expose sensitive credentials.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Use Docker Secrets, Kubernetes Secrets or environment variables.",
        detector=rule_password_secret,
    )

    for line_no, line in enumerate(lines, start=1):
        if PASSWORD_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_generic_secret(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR012",
        title="Possible hardcoded secret",
        description="Potential secret detected inside Dockerfile.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Never commit secrets into Dockerfiles.",
        detector=rule_generic_secret,
    )

    for line_no, line in enumerate(lines, start=1):
        if SECRET_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_api_key(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR013",
        title="API Key detected",
        description="API keys should never be stored inside Dockerfiles.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Move API keys to a secure secret manager.",
        detector=rule_api_key,
    )

    for line_no, line in enumerate(lines, start=1):
        if API_KEY_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_token(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR014",
        title="Authentication Token detected",
        description="Authentication tokens should never be baked into container images.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Inject tokens securely during runtime.",
        detector=rule_token,
    )

    for line_no, line in enumerate(lines, start=1):
        if TOKEN_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_aws_access_key(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR015",
        title="AWS Access Key detected",
        description="AWS credentials detected inside Dockerfile.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Rotate the key immediately and use IAM roles or Secrets Manager.",
        detector=rule_aws_access_key,
    )

    for line_no, line in enumerate(lines, start=1):
        if AWS_ACCESS_KEY_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_aws_secret(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR016",
        title="AWS Secret detected",
        description="Potential AWS secret found.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Store AWS credentials securely outside the image.",
        detector=rule_aws_secret,
    )

    for line_no, line in enumerate(lines, start=1):
        if AWS_SECRET_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_private_key(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR017",
        title="Private Key detected",
        description="Private cryptographic key detected inside Dockerfile.",
        severity="critical",
        category=CATEGORY_SECRET,
        recommendation="Never store private keys inside source code or images.",
        detector=rule_private_key,
    )

    for line_no, line in enumerate(lines, start=1):
        if PRIVATE_KEY_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_jwt(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR018",
        title="JWT Token detected",
        description="A JWT token appears to be embedded inside the Dockerfile.",
        severity="high",
        category=CATEGORY_SECRET,
        recommendation="Generate JWTs dynamically instead of storing them.",
        detector=rule_jwt,
    )

    for line_no, line in enumerate(lines, start=1):
        if JWT_REGEX.search(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


# ============================================================
# Package Management Rules
# ============================================================

def rule_apt_upgrade(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR019",
        title="apt-get upgrade detected",
        description="Running apt-get upgrade inside Dockerfiles reduces reproducibility.",
        severity="medium",
        category=CATEGORY_BEST_PRACTICE,
        recommendation="Install only required packages with pinned versions.",
        detector=rule_apt_upgrade,
    )

    for line_no, line in enumerate(lines, start=1):
        lower = normalize(line)

        if "apt-get upgrade" in lower or "apt upgrade" in lower:
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings


def rule_apk_upgrade(lines: List[str]) -> List[Dict]:
    findings = []

    rule = Rule(
        rule_id="DKR020",
        title="apk upgrade detected",
        description="apk upgrade may reduce build reproducibility.",
        severity="medium",
        category=CATEGORY_BEST_PRACTICE,
        recommendation="Install only required Alpine packages.",
        detector=rule_apk_upgrade,
    )

    for line_no, line in enumerate(lines, start=1):
        if "apk upgrade" in normalize(line):
            findings.append(
                create_finding(
                    rule=rule,
                    line=line_no,
                    evidence=line,
                )
            )

    return findings

# ============================================================
# Rule Registration
# ============================================================

RULES.extend([
    rule_latest_tag,
    rule_root_user,
    rule_missing_user,
    rule_add_instruction,
    rule_missing_healthcheck,
    rule_expose_ssh,
    rule_chmod_777,
    rule_curl_pipe,
    rule_wget_pipe,
    rule_sudo_usage,
    rule_password_secret,
    rule_generic_secret,
    rule_api_key,
    rule_token,
    rule_aws_access_key,
    rule_aws_secret,
    rule_private_key,
    rule_jwt,
    rule_apt_upgrade,
    rule_apk_upgrade,
])


# ============================================================
# Internal Helpers
# ============================================================

def _sort_findings(findings: List[Dict]) -> List[Dict]:
    """
    Sort findings from highest severity to lowest.
    """

    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding["severity"], 0),
            -finding.get("line", 0)
        ),
        reverse=True,
    )


def _remove_duplicates(findings: List[Dict]) -> List[Dict]:
    """
    Remove duplicate findings.

    Duplicate =
        ruleId
        +
        line
        +
        evidence
    """

    unique = {}
    cleaned = []

    for finding in findings:

        key = (
            finding["ruleId"],
            finding["line"],
            finding["evidence"],
        )

        if key not in unique:
            unique[key] = True
            cleaned.append(finding)

    return cleaned


# ============================================================
# Main Rule Engine
# ============================================================

def run_all_rules(lines: List[str]) -> List[Dict]:
    """
    Executes every Dockerfile rule.

    Parameters
    ----------
    lines:
        Dockerfile split into lines.

    Returns
    -------
    List[Dict]

    Standardized finding objects compatible with

    • CLI

    • Dockerfile Analyzer

    • Risk Engine

    • Recommendation Engine

    • REST API

    • Lovable Frontend
    """

    findings = []

    for detector in RULES:

        try:

            detector_findings = detector(lines)

            if detector_findings:

                findings.extend(detector_findings)

        except Exception as exc:

            print(
                f"[WARNING] Rule "
                f"{detector.__name__} "
                f"failed: {exc}"
            )

    findings = _remove_duplicates(findings)

    findings = _sort_findings(findings)

    return findings


# ============================================================
# Module Exports
# ============================================================

__all__ = [
    "Rule",
    "RULES",
    "run_all_rules",
    "create_finding",
]