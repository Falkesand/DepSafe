# NuGet Health Analyzer

Health scoring for NuGet dependencies - predicts maintenance risk and package abandonment. Includes EU Cyber Resilience Act (CRA) compliance tooling with SBOM and VEX generation.

## Installation

```bash
dotnet tool install -g NuGetHealthAnalyzer
```

## Features

- **Health Scoring**: 0-100 score based on freshness, release cadence, download trends, repository activity, and vulnerabilities
- **Abandonment Prediction**: Identifies packages at risk of being abandoned
- **SBOM Generation**: SPDX 3.0 and CycloneDX formats
- **VEX Generation**: OpenVEX vulnerability status documents
- **CRA Compliance Reports**: Comprehensive reports for EU Cyber Resilience Act compliance

## Usage

### Analyze Project Health

```bash
# Analyze current directory
nuget-health analyze

# Analyze specific project or solution
nuget-health analyze ./src/MyProject.csproj
nuget-health analyze ./MyApp.sln

# Output formats
nuget-health analyze --format table    # Default, rich console output
nuget-health analyze --format json     # Machine-readable JSON
nuget-health analyze --format markdown # Markdown for documentation

# CI/CD integration - fail if score below threshold
nuget-health analyze --fail-below 60
```

### Check Single Package

```bash
nuget-health check Newtonsoft.Json
nuget-health check Serilog --version 3.1.1
nuget-health check AutoMapper --format json
```

### Generate SBOM

```bash
# SPDX 3.0 format (default)
nuget-health sbom

# CycloneDX format
nuget-health sbom --format cyclonedx

# Save to file
nuget-health sbom --output sbom.json
```

### Generate VEX Document

```bash
nuget-health vex
nuget-health vex --output vulnerabilities.vex.json
```

### Generate CRA Compliance Report

```bash
# HTML report (default)
nuget-health cra-report

# JSON report
nuget-health cra-report --format json

# Custom output path
nuget-health cra-report --output compliance-report.html
```

## Health Score Calculation

Each package receives a health score (0-100) based on weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Freshness | 25% | Days since last release |
| Release Cadence | 15% | Average releases per year |
| Download Trend | 20% | Growing/stable/declining downloads |
| Repository Activity | 25% | Commits, issues, stars |
| Vulnerabilities | 15% | Known security issues |

### Score Interpretation

- **80-100 (Healthy)**: Actively maintained, low risk
- **60-79 (Watch)**: Some concerns, monitor closely
- **40-59 (Warning)**: Consider alternatives
- **0-39 (Critical)**: High abandonment risk, action needed

## Sample Output

```
Package Health Report
==========================================

Package                    Version    Score   Status
─────────────────────────────────────────────────────
Newtonsoft.Json            13.0.3      92     ✓ Healthy
Serilog                    3.1.1       88     ✓ Healthy
AutoMapper                 12.0.1      85     ✓ Healthy
OldLibrary.Utils           2.1.0       34     ✗ Critical
SomePackage                1.0.0       52     ⚠ Warning

Project Score: 72/100 (Watch)
─────────────────────────────────────────────────────
Recommendations:
• OldLibrary.Utils: No releases in 3 years, declining downloads
```

## CRA Compliance

The EU Cyber Resilience Act (effective December 2027) requires:
- Software Bill of Materials (SBOM)
- Vulnerability documentation (VEX)
- Security update mechanisms

This tool helps meet these requirements by generating:
- SPDX 3.0 compliant SBOMs
- OpenVEX vulnerability status documents
- Comprehensive compliance reports

## Environment Variables

- `GITHUB_TOKEN`: GitHub API token for higher rate limits and private repo access

## License

MIT
