```markdown
# Architecture & Design

## System Architecture

Docker Image/Registry ↓ ┌─────────────────────────────────┐ │ Image Analysis Module │ ├─────────────────────────────────┤ │ - Layer Extraction │ │ - Dockerfile Parsing │ │ - Dependency Detection │ ├─────────────────────────────────┤ │ Scanning Engine │ ├─────────────────────────────────┤ │ - Vulnerability Scanner │ │ - Secrets Detector │ │ - Configuration Analyzer │ ├─────────────────────────────────┤ │ Database Integration │ ├─────────────────────────────────┤ │ - CVE Database (NVD) │ │ - Secret Patterns │ │ - Config Rules │ ├─────────────────────────────────┤ │ Report Generation │ ├─────────────────────────────────┤ │ - JSON Output │ │ - HTML Reports │ │ - SBOM (CycloneDX) │ └─────────────────────────────────┘

Copy
## Core Modules

### scanner_core.py
Main orchestrator that coordinates all scanning modules.

### vulnerability_analyzer.py
Detects known CVEs using NVD database integration.

### dockerfile_analyzer.py
Checks Dockerfile against security best practices.

### secrets_detector.py
Uses regex and entropy analysis to find hardcoded secrets.

### report_generator.py
Generates reports in multiple formats (JSON, HTML, SBOM).

## Data Flow

1. **Input**: Docker image URI or Dockerfile path
2. **Extraction**: Extract layers, configurations, dependencies
3. **Analysis**: Run all scanning modules in parallel
4. **Enrichment**: Cross-reference with CVE databases
5. **Scoring**: Calculate risk scores and severity
6. **Output**: Generate formatted reports
