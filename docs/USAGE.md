Name: `docs/USAGE.md`

```markdown
# Usage Guide

## Basic Scanning

### Scan a Local Docker Image
```bash
python -m src.main scan --image nginx:latest
Scan with Custom Options
Copypython -m src.main scan \
  --image myapp:1.0 \
  --format json \
  --output myapp-report.json \
  --min-severity HIGH
Dockerfile Analysis
Analyze Security Best Practices
Copypython -m src.main analyze-dockerfile --file ./Dockerfile
SBOM Generation
Generate Software Bill of Materials
Copypython -m src.main generate-sbom --image myapp:1.0 --format cyclonedx
CI/CD Integration
GitHub Actions Example
See .github/workflows/scan.yml for automated scanning on push.

Command Options
scan
--image (required): Docker image to scan
--format: Output format (json, html, xml)
--output: Save report to file
--min-severity: Filter vulnerabilities (CRITICAL, HIGH, MEDIUM, LOW)
--fail-on: Exit with error code if severity found
analyze-dockerfile
--file (required): Path to Dockerfile
--format: Output format
generate-sbom
--image (required): Docker image
--format: cyclonedx or spdx
Copy
