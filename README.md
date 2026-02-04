# NuGet Health Analyzer

Health scoring for NuGet dependencies - predicts maintenance risk and package abandonment. Includes EU Cyber Resilience Act (CRA) compliance tooling with SBOM and VEX generation.

![Health Score](https://img.shields.io/badge/health_score-70%2F100-blue?style=flat)
![Status](https://img.shields.io/badge/status-Watch-blue?style=flat)
![Vulnerabilities](https://img.shields.io/badge/vulnerabilities-none-brightgreen?style=flat)
![CRA Compliance](https://img.shields.io/badge/CRA-compliant-brightgreen?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

## Installation

```bash
dotnet tool install -g NuGetHealthAnalyzer
```

## Features

- **Health Scoring**: 0-100 score based on freshness, release cadence, download trends, repository activity, and vulnerabilities
- **Abandonment Prediction**: Identifies packages at risk of being abandoned
- **Transitive Dependencies**: Full dependency tree analysis with drill-down
- **SBOM Generation**: SPDX 3.0 and CycloneDX formats
- **VEX Generation**: OpenVEX vulnerability status documents
- **CRA Compliance Reports**: Interactive HTML reports for EU Cyber Resilience Act compliance
- **License Compatibility**: Detects copyleft and license conflicts
- **Badge Generation**: shields.io badges for your README
- **MSBuild Integration**: Build-time health checks

## Quick Start

```bash
# Analyze current project
nuget-health analyze

# Generate comprehensive HTML report
nuget-health cra-report

# Check license compatibility
nuget-health licenses

# Generate badges for README
nuget-health badge
```

## Commands

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

# Skip GitHub API (faster, less accurate)
nuget-health analyze --skip-github
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
# HTML report (default) - interactive with drill-down
nuget-health cra-report

# JSON report
nuget-health cra-report --format json

# Custom output path
nuget-health cra-report --output compliance-report.html
```

### Analyze License Compatibility

```bash
# Check licenses against MIT (default)
nuget-health licenses

# Check against your project's license
nuget-health licenses --project-license Apache-2.0

# Include transitive dependencies
nuget-health licenses --include-transitive

# JSON output
nuget-health licenses --format json
```

### Generate Badges

```bash
# Markdown format (default)
nuget-health badge

# HTML format
nuget-health badge --format html

# Different styles
nuget-health badge --style for-the-badge
nuget-health badge --style flat-square

# Save to file
nuget-health badge --output BADGES.md
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

## MSBuild Integration

Add to your `.csproj` to enable build-time health checks:

```xml
<PropertyGroup>
  <!-- Enable health checking during build -->
  <NuGetHealthEnabled>true</NuGetHealthEnabled>

  <!-- Fail build if score below threshold (0 = disabled) -->
  <NuGetHealthFailBelow>60</NuGetHealthFailBelow>

  <!-- Warn if score below threshold -->
  <NuGetHealthWarnBelow>80</NuGetHealthWarnBelow>

  <!-- Skip GitHub API for faster builds -->
  <NuGetHealthSkipGitHub>true</NuGetHealthSkipGitHub>
</PropertyGroup>
```

### MSBuild Targets

```bash
# Run health check manually
dotnet msbuild -t:NuGetHealthCheck

# Generate health report
dotnet msbuild -t:NuGetHealthReport

# Check license compatibility
dotnet msbuild -t:NuGetHealthLicenseCheck

# Generate badges
dotnet msbuild -t:NuGetHealthBadges
```

## License Compatibility

The `licenses` command detects potential license conflicts:

| Category | Licenses | Risk |
|----------|----------|------|
| Permissive | MIT, Apache-2.0, BSD, ISC | Low - compatible with most projects |
| Weak Copyleft | LGPL, MPL, EPL | Medium - modifications must be shared |
| Strong Copyleft | GPL, AGPL | High - may require open-sourcing your project |

Example output:
```
License Compatibility Report
╭─────────────────┬────────────╮
│ Project License │ MIT        │
│ Total Packages  │ 45         │
│ Overall Status  │ Compatible │
│ Errors          │ 0          │
│ Warnings        │ 2          │
╰─────────────────┴────────────╯

License Issues:
• Warning: SomePackage uses LGPL-3.0 (weak copyleft)
  Recommendation: Modifications to this package must be shared
```

## CRA Compliance

The EU Cyber Resilience Act (effective December 2027) requires:
- Software Bill of Materials (SBOM)
- Vulnerability documentation (VEX)
- Security update mechanisms

This tool helps meet these requirements by generating:
- SPDX 3.0 compliant SBOMs
- OpenVEX vulnerability status documents
- Comprehensive compliance reports with:
  - Interactive HTML dashboard
  - Package health drill-down
  - Transitive dependency tree
  - Vulnerability details
  - License information

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub API token for higher rate limits, vulnerability data, and private repo access |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Check NuGet Health
  run: |
    dotnet tool install -g NuGetHealthAnalyzer
    nuget-health analyze --fail-below 60
```

### Azure DevOps

```yaml
- script: |
    dotnet tool install -g NuGetHealthAnalyzer
    nuget-health analyze --fail-below 60
  displayName: 'Check NuGet Health'
```

## License

MIT
