# Docker Container Security Scanner

## Manual Testing Log

---

## Test Case 001

**Module**
Docker Handler

**Objective**
Verify connection with Docker Engine.

**Command**

```bash
python -m src.cli.main scan --image nginx:latest
```

**Expected Result**

- Docker Engine connects successfully.
- Image metadata is displayed.

**Actual Result**

✅ Passed

**Date**

09 July 2026

---

## Test Case 002

**Module**
Dockerfile Analyzer

**Objective**
Detect common Dockerfile security issues.

**Input**

sample.Dockerfile

**Expected Findings**

- Latest tag
- Hardcoded secret
- ADD instruction
- SSH exposed
- USER root
- Missing HEALTHCHECK

**Actual Result**

✅ Passed

**Notes**

Duplicate secret detection observed.
To be fixed in Version 0.1.1.