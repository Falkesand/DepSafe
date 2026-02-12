# DepSafe User Manual

**Version 1.6 | February 2026**

DepSafe is a dependency safety and compliance tool for .NET (NuGet) and JavaScript (npm) projects. It analyzes package health, enforces EU Cyber Resilience Act (CRA) compliance, and manages supply chain security.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [Commands Reference](#3-commands-reference)
   - [cra-report](#cra-report)
   - [analyze](#analyze)
   - [check](#check)
   - [sbom](#sbom)
   - [vex](#vex)
   - [licenses](#licenses)
   - [typosquat](#typosquat)
   - [badge](#badge)
4. [Configuration](#4-configuration)
   - [Configuration File](#41-configuration-file-cra-configjson)
   - [Policy Rules](#42-policy-rules)
   - [Environment Variables](#43-environment-variables)
5. [CRA Compliance Report](#5-cra-compliance-report)
   - [Report Sections](#51-report-sections)
   - [Compliance Items](#52-compliance-items)
   - [CRA Readiness Score](#53-cra-readiness-score)
6. [Health Scoring](#6-health-scoring)
   - [Package Health Score](#61-package-health-score)
   - [Project Score](#62-project-score)
7. [Security Analysis](#7-security-analysis)
   - [Vulnerability Scanning](#71-vulnerability-scanning)
   - [CISA KEV Catalog](#72-cisa-kev-catalog)
   - [EPSS Scoring](#73-epss-scoring)
   - [Typosquatting Detection](#74-typosquatting-detection)
8. [Remediation Roadmap](#8-remediation-roadmap)
   - [Priority Ranking](#81-priority-ranking)
   - [Upgrade Tiers](#82-upgrade-tiers)
   - [Upgrade Risk Assessment](#83-upgrade-risk-assessment)
   - [Security Budget Optimizer](#84-security-budget-optimizer)
9. [Reporting Features](#9-reporting-features)
   - [HTML Dashboard](#91-html-dashboard)
   - [Release Gates](#92-release-gates)
   - [Evidence Packs](#93-evidence-packs)
   - [Audit Simulation](#94-audit-simulation)
   - [Trend Analysis](#95-trend-analysis)
10. [SBOM and VEX](#10-sbom-and-vex)
    - [SBOM Generation](#101-sbom-generation)
    - [SBOM Validation](#102-sbom-validation)
    - [VEX Documents](#103-vex-documents)
11. [License Analysis](#11-license-analysis)
12. [Artifact Signing](#12-artifact-signing)
13. [CI/CD Integration](#13-cicd-integration)
    - [Exit Codes](#131-exit-codes)
    - [GitHub Actions](#132-github-actions)
    - [Azure DevOps](#133-azure-devops)
    - [MSBuild Integration](#134-msbuild-integration)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Installation

### As a Global Tool

```bash
dotnet tool install -g DepSafe
```

### As a Local Tool

```bash
dotnet new tool-manifest   # if you don't have one yet
dotnet tool install DepSafe
```

### Verify Installation

```bash
depsafe --version
```

### Prerequisites

- .NET 10 SDK or later
- (Optional) `GITHUB_TOKEN` environment variable for enhanced data

---

## 2. Quick Start

```bash
# Generate a CRA compliance report
depsafe cra-report

# Quick health analysis of all dependencies
depsafe analyze

# Check a single package
depsafe check Newtonsoft.Json

# Generate SBOM
depsafe sbom --output sbom.spdx.json

# Check license compatibility
depsafe licenses
```

The most common workflow is `depsafe cra-report`, which produces a comprehensive HTML dashboard covering health, compliance, vulnerabilities, remediation, and more.

---

## 3. Commands Reference

### `cra-report`

Generate a comprehensive EU Cyber Resilience Act compliance report.

```bash
depsafe cra-report [<path>] [options]
```

| Argument | Description | Default |
|----------|-------------|---------|
| `<path>` | Path to project, solution, or directory | `.` (current directory) |

**Options:**

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--format` | `-f` | `Html`, `Json` | `Html` | Output format |
| `--output` | `-o` | string | `cra-report.html` | Output file path |
| `--deep` | `-d` | flag | off | Fetch full metadata for all transitive packages |
| `--skip-github` | | flag | off | Skip GitHub API calls (faster, less data) |
| `--licenses` | `-l` | `Txt`, `Html`, `Md` | | Generate license attribution file |
| `--sbom` | `-s` | `Spdx`, `CycloneDx` | | Export SBOM alongside report |
| `--check-typosquat` | | flag | off | Run typosquatting detection |
| `--sign` | | flag | off | Sign all generated artifacts with Sigil |
| `--sign-key` | | string | | Path to signing key (uses Sigil default if omitted) |
| `--release-gate` | | flag | off | Evaluate release readiness (blocking/advisory) |
| `--evidence-pack` | | flag | off | Bundle all artifacts into timestamped evidence directory |
| `--audit-mode` | | flag | off | Simulate CRA conformity assessment |
| `--snapshot` | | flag | off | Save snapshot for trend tracking |

**Examples:**

```bash
# Basic HTML report
depsafe cra-report

# Full deep scan with all artifacts
depsafe cra-report --deep --sbom spdx --licenses txt

# CI/CD pipeline with policy enforcement
depsafe cra-report --format json --output compliance.json

# Pre-release compliance check
depsafe cra-report --release-gate --evidence-pack --sbom spdx --sign

# Audit preparation
depsafe cra-report --audit-mode --deep

# Track compliance over time
depsafe cra-report --snapshot
```

---

### `analyze`

Analyze package health for a project with console output.

```bash
depsafe analyze [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--format` | `-f` | `Table`, `Json`, `Markdown` | `Table` | Output format |
| `--fail-below` | | int | | Exit with error if project score below threshold |
| `--skip-github` | | flag | off | Skip GitHub API calls |
| `--check-typosquat` | | flag | off | Run typosquatting detection |

**Examples:**

```bash
# Table output
depsafe analyze

# Fail CI if health below 60
depsafe analyze --fail-below 60

# JSON for automation
depsafe analyze --format json
```

---

### `check`

Check health of a single package.

```bash
depsafe check <package> [options]
```

| Argument | Description | Required |
|----------|-------------|----------|
| `<package>` | Package ID to check | Yes |

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--version` | `-v` | string | latest | Specific version to check |
| `--format` | `-f` | `Table`, `Json`, `Markdown` | `Table` | Output format |
| `--skip-github` | | flag | off | Skip GitHub API calls |

**Examples:**

```bash
depsafe check Newtonsoft.Json
depsafe check Serilog --version 3.1.1
depsafe check react --format json
```

---

### `sbom`

Generate a Software Bill of Materials.

```bash
depsafe sbom [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--format` | `-f` | `Spdx`, `CycloneDx` | `Spdx` | SBOM format |
| `--output` | `-o` | string | stdout | Output file path |
| `--skip-github` | | flag | off | Skip GitHub API calls |
| `--sign` | | flag | off | Sign the generated SBOM |
| `--sign-key` | | string | | Path to signing key |

**Examples:**

```bash
depsafe sbom --output sbom.spdx.json
depsafe sbom --format cyclonedx --output bom.json
depsafe sbom --output sbom.spdx.json --sign
```

---

### `vex`

Generate a VEX (Vulnerability Exploitability eXchange) document.

```bash
depsafe vex [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--output` | `-o` | string | stdout | Output file path |
| `--sign` | | flag | off | Sign the VEX document |
| `--sign-key` | | string | | Path to signing key |

**Examples:**

```bash
depsafe vex --output vulnerabilities.vex.json
depsafe vex --output vulnerabilities.vex.json --sign
```

---

### `licenses`

Analyze license compatibility of dependencies.

```bash
depsafe licenses [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--project-license` | `-l` | string | `MIT` | Your project's license |
| `--format` | `-f` | `Table`, `Json` | `Table` | Output format |
| `--include-transitive` | `-t` | flag | off | Include transitive dependencies |

**Exit codes:** `0` = no issues, `1` = compatibility issues found.

**Examples:**

```bash
depsafe licenses
depsafe licenses --project-license Apache-2.0
depsafe licenses --include-transitive --format json
```

---

### `typosquat`

Check dependencies for potential typosquatting attacks.

```bash
depsafe typosquat [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--format` | `-f` | `Table`, `Json`, `Markdown` | `Table` | Output format |
| `--offline` | | flag | off | Use embedded data only, no network calls |

**Exit codes:** `0` = no issues, `1` = potential typosquatting detected.

**Examples:**

```bash
depsafe typosquat
depsafe typosquat --offline
depsafe typosquat --format json
```

---

### `badge`

Generate shields.io badges for your README.

```bash
depsafe badge [<path>] [options]
```

| Option | Alias | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--format` | `-f` | `Markdown`, `Html`, `Json`, `Url` | `Markdown` | Output format |
| `--output` | `-o` | string | stdout | Output file path |
| `--style` | `-s` | string | `flat` | Badge style (`flat`, `flat-square`, `plastic`, `for-the-badge`) |
| `--skip-github` | | flag | off | Skip GitHub API calls |

Available badges: Health Score, Status, Packages, Transitive, Vulnerabilities, CRA Compliance.

**Examples:**

```bash
depsafe badge
depsafe badge --style for-the-badge --format html
```

---

## 4. Configuration

### 4.1 Configuration File (`.cra-config.json`)

Place a `.cra-config.json` file in your project root to customize behavior:

```json
{
  "licenseOverrides": {
    "SixLabors.ImageSharp": "Apache-2.0"
  },
  "excludePackages": [
    "MyCompany.Internal.Utils"
  ],
  "complianceNotes": {
    "OldLegacyPackage": "Approved for use until Q4 2025 migration"
  },
  "supportPeriodEnd": "2028-12",
  "securityContact": "security@example.com",
  "allowedLicenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "blockedLicenses": ["GPL-3.0-only"],
  "failOnKev": true,
  "failOnCraReadinessBelow": 70,
  "failOnReportableVulnerabilities": true,
  "noCriticalVulnerabilities": true
}
```

**General Settings:**

| Field | Type | Description |
|-------|------|-------------|
| `licenseOverrides` | `{string: string}` | Override detected licenses (package ID to SPDX identifier) |
| `excludePackages` | `string[]` | Package IDs to exclude from analysis |
| `complianceNotes` | `{string: string}` | Per-package compliance justifications |
| `supportPeriodEnd` | `string` | Declared end of support (e.g., `"2028-12"`) |
| `securityContact` | `string` | Security contact email or URL |

**License Policy:**

| Field | Type | Description |
|-------|------|-------------|
| `allowedLicenses` | `string[]` | SPDX identifiers that are explicitly allowed |
| `blockedLicenses` | `string[]` | SPDX identifiers that are explicitly blocked |

When `allowedLicenses` is set, only those licenses are permitted. `blockedLicenses` is ignored when `allowedLicenses` is set.

### 4.2 Policy Rules

All policy thresholds trigger **exit code 2** when violated. Configure in `.cra-config.json`:

| Rule | Type | Description |
|------|------|-------------|
| `failOnKev` | `bool` | Fail if any CISA KEV vulnerability exists |
| `failOnEpssThreshold` | `double` | Fail if EPSS probability exceeds threshold (0.0-1.0) |
| `failOnVulnerabilityCount` | `int` | Fail if total vulnerability count exceeds limit |
| `failOnCraReadinessBelow` | `int` | Fail if CRA readiness score below value (0-100) |
| `failOnReportableVulnerabilities` | `bool` | Fail if Art. 14 reportable vulnerabilities exist |
| `failOnUnpatchedDaysOver` | `int` | Fail if any vulnerability unpatched longer than N days |
| `failOnUnmaintainedPackages` | `bool` | Fail if any dependency inactive for 2+ years |
| `failOnSbomCompletenessBelow` | `int` | Fail if SBOM completeness below threshold (0-100) |
| `failOnAttackSurfaceDepthOver` | `int` | Fail if dependency tree depth exceeds value |
| `failOnDeprecatedPackages` | `bool` | Fail if any deprecated packages detected |
| `noCriticalVulnerabilities` | `bool` | Fail if any critical-severity vulnerability exists |
| `minHealthScore` | `int` | Minimum acceptable package health score (0-100) |
| `minPackageMaintainers` | `int` | Minimum number of contributors per package |
| `blockUnmaintainedMonths` | `int` | Maximum inactive months before failure |

### 4.3 Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token. Enables: higher API rate limits (5,000/hr vs 60/hr), vulnerability data from GitHub Advisory Database, private repository access, repository metadata (stars, issues, commit history). Recommended scope: `public_repo`. |

**Setting the token:**

```bash
# Linux / macOS
export GITHUB_TOKEN="ghp_your_token_here"

# Windows PowerShell
$env:GITHUB_TOKEN = "ghp_your_token_here"

# Windows Command Prompt
set GITHUB_TOKEN=ghp_your_token_here
```

Without a GitHub token, DepSafe still functions using OSV, NuGet, and npm registries directly. GitHub-dependent features (vulnerability data, repository activity, maintainer trust) will be unavailable or degraded.

---

## 5. CRA Compliance Report

The `cra-report` command generates a comprehensive report mapping your project's dependency posture against the EU Cyber Resilience Act requirements.

### 5.1 Report Sections

The HTML report contains these interactive sections:

1. **Executive Summary** - Overall health score, CRA readiness score, package counts, vulnerability summary
2. **CRA Readiness Score** - Weighted compliance gauge (0-100) with per-item breakdown
3. **Compliance Matrix** - Status of all 18 compliance items with evidence
4. **Package Health Cards** - Per-package health scores, versions, vulnerabilities, recommendations
5. **Art. 14 Reporting Obligations** - Vulnerabilities requiring CSIRT notification with deadlines
6. **Remediation Roadmap** - Prioritized update plan with upgrade risk assessment
7. **Security Budget** - ROI-ranked remediation priorities (High ROI vs Low ROI)
8. **Release Readiness** - Go/no-go signal with blocking and advisory items (when `--release-gate` used)
9. **Dependency Tree** - Interactive tree visualization with health indicators
10. **Attack Surface Analysis** - Dependency depth, transitive ratio, heavy packages
11. **Maintainer Trust** - Per-package trust scores with contributor analysis
12. **Trend Analysis** - Historical compliance tracking (when `--snapshot` used)
13. **Audit Simulation** - Zero-tolerance conformity assessment (when `--audit-mode` used)
14. **Policy Violations** - Threshold violations from `.cra-config.json`
15. **SBOM & VEX** - Embedded SBOM and VEX documents with export buttons

### 5.2 Compliance Items

DepSafe evaluates 18 CRA compliance items:

| # | Requirement | CRA Reference | Weight |
|---|-------------|---------------|--------|
| 1 | Software Bill of Materials | Art. 10 | 10 |
| 2 | Exploited Vulnerabilities (CISA KEV) | Art. 10(4) | 15 |
| 3 | Exploit Probability (EPSS) | Art. 10(4) | 7 |
| 4 | Security Updates | Art. 10(6) | 6 |
| 5 | License Information | Art. 10(9) | 2 |
| 6 | No Deprecated Components | Art. 10 | 1 |
| 7 | Cryptographic Compliance | Art. 10 | 1 |
| 8 | Supply Chain Integrity | Art. 10 | 1 |
| 9 | Vulnerability Handling | Art. 11 | 15 |
| 10 | Remediation Timeliness | Art. 11(4) | 8 |
| 11 | Security Policy | Art. 11(5) | 2 |
| 12 | Support Period | Art. 13(8) | 5 |
| 13 | Package Provenance | Art. 13(5) | 4 |
| 14 | Incident Reporting | Art. 14 | 12 |
| 15 | Release Readiness | Annex I Part I(1) | 10 |
| 16 | Attack Surface | Annex I Part I(10) | 5 |
| 17 | SBOM Completeness | Annex I Part II(1) | 5 |
| 18 | Documentation | Annex II | 3 |

Each item has a status:

| Status | Meaning | Score Contribution |
|--------|---------|-------------------|
| **Compliant** | Requirement fully met | 100% of weight |
| **Review** | Partial compliance, needs attention | 50% of weight |
| **ActionRequired** | Significant gaps | 25% of weight |
| **NonCompliant** | Requirement not met | 0% of weight |

### 5.3 CRA Readiness Score

The CRA Readiness Score (0-100) is a single metric reflecting overall compliance posture:

```
Score = (Sum of weighted item scores) / (Sum of all weights) x 100
```

Each item contributes: `weight x status_multiplier` where the multiplier is 1.0 (Compliant), 0.5 (Review), 0.25 (ActionRequired), or 0.0 (NonCompliant).

**Score interpretation:**

| Range | Assessment |
|-------|------------|
| 90-100 | Excellent CRA readiness |
| 70-89 | Good, minor gaps to address |
| 50-69 | Moderate risk, action needed |
| 0-49 | Significant compliance gaps |

---

## 6. Health Scoring

### 6.1 Package Health Score

Every package receives a health score (0-100) based on weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Freshness | 25% | Days since last release. Newer = healthier. |
| Release Cadence | 15% | Average releases per year. Regular cadence = healthier. |
| Download Trend | 20% | Download volume and growth trajectory. |
| Repository Activity | 25% | Recent commits, stars, open issues, contributor activity. |
| Vulnerabilities | 15% | Known CVEs affecting the installed version. |

**Score ranges:**

| Score | Status | Recommendation |
|-------|--------|----------------|
| 80-100 | Healthy | Actively maintained, low risk |
| 60-79 | Watch | Some concerns, monitor |
| 40-59 | Warning | Consider alternatives |
| 0-39 | Critical | High risk, action needed |

### 6.2 Project Score

The project score is a weighted average of all package health scores. It represents the overall dependency health posture of the project.

---

## 7. Security Analysis

### 7.1 Vulnerability Scanning

DepSafe scans for vulnerabilities using multiple sources:

- **OSV (Open Source Vulnerabilities)** - Primary source, no API key required
- **GitHub Advisory Database** - Requires `GITHUB_TOKEN`, provides CVE mappings and severity

All vulnerability scanning is **version-aware**: only vulnerabilities affecting your specific installed version are reported. DepSafe checks the vulnerable version range against your installed version to eliminate false positives.

### 7.2 CISA KEV Catalog

The CISA Known Exploited Vulnerabilities (KEV) catalog identifies vulnerabilities that are actively being exploited in the wild. DepSafe:

- Downloads and caches the KEV catalog (24-hour TTL)
- Cross-references all detected CVEs against the catalog
- Flags KEV vulnerabilities with highest priority in the remediation roadmap
- Triggers CRA Art. 14 incident reporting obligations

### 7.3 EPSS Scoring

The Exploit Prediction Scoring System (EPSS) provides a probability score (0.0-1.0) indicating how likely a vulnerability is to be exploited in the next 30 days:

| EPSS Range | Risk Level |
|------------|------------|
| 0.0 - 0.1 | Low exploitation probability |
| 0.1 - 0.5 | Moderate probability |
| 0.5 - 1.0 | High probability, triggers Art. 14 reporting |

Vulnerabilities with EPSS >= 0.5 are treated similarly to KEV entries for CRA compliance purposes.

### 7.4 Typosquatting Detection

DepSafe uses a 5-layer detection system to identify potential typosquatting attacks:

1. **Edit Distance** - Damerau-Levenshtein distance against popular packages
2. **Separator Substitution** - Detects `-` vs `.` vs `_` swaps
3. **Scope Confusion** - npm scoped package impersonation
4. **Character Substitution** - Homoglyph and character swap detection
5. **Prefix/Suffix Manipulation** - Common prefix/suffix-based attacks

Each detection produces a confidence level: Low, Medium, High, or Critical.

---

## 8. Remediation Roadmap

The remediation roadmap is a prioritized action plan for addressing vulnerable and problematic dependencies.

### 8.1 Priority Ranking

Packages are ranked by these criteria (highest priority first):

1. **CISA KEV listed** - Actively exploited vulnerabilities (+10,000 priority)
2. **EPSS >= 0.5** - High exploitation probability (+5,000 priority)
3. **Severity** - Critical (+500), High (+250), Moderate/Medium (+100), Low (+25)
4. **CRA Score Lift** - Estimated improvement to CRA readiness score

The roadmap shows the top 20 most impactful updates.

### 8.2 Upgrade Tiers

For each vulnerable package, DepSafe shows available upgrade paths at each semver level:

| Tier | Risk | Description |
|------|------|-------------|
| **Patch** | Low | Bug fixes only, API-compatible |
| **Minor** | Moderate | New features, backward-compatible |
| **Major** | High | Potential breaking changes |

Each tier shows how many CVEs it fixes out of the total. The recommended tier (lowest effort that fixes the most CVEs) is marked with a checkmark.

### 8.3 Upgrade Risk Assessment

Each upgrade tier receives a composite risk score (0-100) based on four weighted factors:

| Factor | Weight | Calculation |
|--------|--------|-------------|
| **Semver Signal** | 40% | Patch = 0, Minor = 25, Major = 50 |
| **Changelog Signals** | 35% | `min(breaking_keywords x 10 + deprecation_keywords x 5, 100)` |
| **Maintainer Stability** | 15% | `100 - maintainer_trust_score` (lower trust = higher risk) |
| **Time Gap** | 10% | `min(days_between_versions / 730 x 100, 100)` |

**Changelog analysis** scans GitHub release note bodies for signal keywords:

- **Breaking signals**: `breaking`, `removed`, `renamed`, `incompatible`, `migration required`, `no longer supports`
- **Deprecation signals**: `deprecated`, `obsolete`, `will be removed`, `end of life`

**Risk levels:**

| Score | Level | Badge Color |
|-------|-------|-------------|
| 0-25 | Low | Green |
| 26-50 | Medium | Yellow |
| 51-75 | High | Orange |
| 76-100 | Critical | Red |

Risk badges appear in the remediation roadmap table. Hover over a badge to see the specific risk factors.

### 8.4 Security Budget Optimizer

The security budget section helps teams maximize risk reduction with limited time:

- Sorts all remediation items by **ROI** (priority score / effort weight)
- Identifies the smallest set of fixes that covers **80% of total risk**
- Classifies items as **High ROI** (top 80%) or **Low ROI** (remaining 20%)

Effort weights: Patch = 1, Minor = 2, Major = 3.

---

## 9. Reporting Features

### 9.1 HTML Dashboard

The default HTML report is an interactive dashboard with:

- Dark theme with professional styling
- Collapsible sections with navigation sidebar
- Click-to-expand package cards
- Interactive dependency tree with expand/collapse
- Export buttons for SBOM and VEX
- CRA readiness gauge with color-coded compliance matrix

### 9.2 Release Gates

Use `--release-gate` to evaluate release readiness:

```bash
depsafe cra-report --release-gate
```

The report classifies findings as:

- **Blocking** - Must be resolved before release (KEV vulnerabilities, critical compliance gaps)
- **Advisory** - Should be addressed but not release-blocking (license concerns, stale dependencies)

The dashboard shows a GO / NO-GO signal based on blocking items.

### 9.3 Evidence Packs

Use `--evidence-pack` to bundle all compliance artifacts:

```bash
depsafe cra-report --evidence-pack --sbom spdx --licenses txt --sign
```

Produces a timestamped directory containing:
- CRA compliance report (HTML and/or JSON)
- SBOM document
- VEX document
- License attribution file
- Signed artifact signatures
- `manifest.json` linking all artifacts with checksums

Evidence packs are useful for regulatory submissions, audits, and release archiving.

### 9.4 Audit Simulation

Use `--audit-mode` to simulate a CRA conformity assessment:

```bash
depsafe cra-report --audit-mode --deep
```

Audit mode applies zero-tolerance thresholds and generates findings from an auditor's perspective. It checks for:

- Vulnerabilities in dependencies (any severity)
- Missing security policies
- Incomplete SBOM metadata
- Missing documentation (README, SECURITY.md, changelog)
- Unmaintained or archived dependencies
- Insufficient maintainer diversity

### 9.5 Trend Analysis

Use `--snapshot` to track compliance posture over time:

```bash
depsafe cra-report --snapshot
```

Each run saves a snapshot to `.depsafe-snapshots/`. The HTML report displays a trend chart showing how your CRA readiness score, vulnerability count, and health score change over time.

---

## 10. SBOM and VEX

### 10.1 SBOM Generation

DepSafe generates Software Bills of Materials in two formats:

**SPDX 3.0:**
```bash
depsafe sbom --format spdx --output sbom.spdx.json
```

**CycloneDX 1.5:**
```bash
depsafe sbom --format cyclonedx --output bom.cdx.json
```

SBOM documents include:
- All direct and transitive dependencies
- Package versions and download locations
- License information (SPDX identifiers)
- Package integrity hashes (when available)
- Dependency relationships

### 10.2 SBOM Validation

The CRA report automatically validates generated SBOMs against BSI TR-03183-2 requirements:

| Field | Requirement |
|-------|-------------|
| Timestamp | Document creation date |
| Creator | Tool identification |
| Supplier | Package publisher/author |
| PURL | Package URL identifier |
| Checksum | Package integrity hash |

Completeness is reported as a percentage. Configure minimum threshold via `failOnSbomCompletenessBelow` in `.cra-config.json`.

### 10.3 VEX Documents

VEX (Vulnerability Exploitability eXchange) documents describe the exploitability status of known vulnerabilities:

```bash
depsafe vex --output vulnerabilities.vex.json
```

DepSafe generates VEX documents in OpenVEX format with:
- Vulnerability status: `affected`, `fixed`, `not_affected`
- Version-aware filtering (only reports vulnerabilities affecting installed versions)
- CVE identifiers mapped from OSV advisories

---

## 11. License Analysis

DepSafe classifies licenses into compatibility categories:

| Category | Examples | Risk |
|----------|----------|------|
| **Permissive** | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause | Low |
| **Weak Copyleft** | LGPL-2.1, LGPL-3.0, MPL-2.0 | Medium |
| **Strong Copyleft** | GPL-2.0, GPL-3.0, AGPL-3.0 | High |
| **Public Domain** | Unlicense, CC0-1.0 | None |

Use `--project-license` to check compatibility against your project's license:

```bash
depsafe licenses --project-license Apache-2.0
```

Override incorrect license detection using `licenseOverrides` in `.cra-config.json`:

```json
{
  "licenseOverrides": {
    "PackageName": "MIT"
  }
}
```

Generate attribution files for compliance:

```bash
depsafe cra-report --licenses txt    # THIRD-PARTY-NOTICES.txt
depsafe cra-report --licenses html   # Styled HTML attribution
depsafe cra-report --licenses md     # ATTRIBUTION.md
```

---

## 12. Artifact Signing

DepSafe can sign generated artifacts using Sigil detached signatures:

```bash
# Sign with default key
depsafe cra-report --sbom spdx --sign

# Sign with specific key
depsafe sbom --output sbom.json --sign --sign-key ./keys/my-key.pem
```

Signing produces `.sig.json` files alongside each artifact. Consumers verify signatures externally using `sigil verify`.

Signable artifacts: SBOM, VEX, license attribution files, CRA reports.

---

## 13. CI/CD Integration

### 13.1 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, all checks passed |
| `1` | Error or failure (non-compliant, package not found, etc.) |
| `2` | Policy violation (threshold exceeded in `.cra-config.json`) |

### 13.2 GitHub Actions

```yaml
name: Dependency Compliance
on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Install DepSafe
        run: dotnet tool install -g DepSafe

      - name: Run CRA Compliance Check
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: depsafe cra-report --format json --output compliance.json

      - name: Upload Compliance Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cra-compliance
          path: compliance.json
```

**With policy enforcement:**

```yaml
      - name: Run Compliance with Policies
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          depsafe cra-report --release-gate --evidence-pack --sbom spdx
          # Exit code 2 fails the build on policy violations
```

### 13.3 Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UseDotNet@2
    inputs:
      version: '10.0.x'

  - script: dotnet tool install -g DepSafe
    displayName: 'Install DepSafe'

  - script: depsafe cra-report --format json --output $(Build.ArtifactStagingDirectory)/compliance.json
    displayName: 'CRA Compliance Check'
    env:
      GITHUB_TOKEN: $(GITHUB_TOKEN)

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'compliance'
    condition: always()
```

### 13.4 MSBuild Integration

Add to your `.csproj` to run DepSafe during builds:

```xml
<PropertyGroup>
  <DepSafeEnabled>true</DepSafeEnabled>
  <DepSafeFailBelow>60</DepSafeFailBelow>
  <DepSafeWarnBelow>80</DepSafeWarnBelow>
  <DepSafeSkipGitHub>true</DepSafeSkipGitHub>
  <DepSafeRunOnBuild>true</DepSafeRunOnBuild>
  <DepSafeCacheMinutes>60</DepSafeCacheMinutes>
</PropertyGroup>
```

Available MSBuild targets:

```bash
dotnet msbuild -t:DepSafeCheck        # Health check
dotnet msbuild -t:DepSafeReport       # Generate report
dotnet msbuild -t:DepSafeLicenseCheck # License check
dotnet msbuild -t:DepSafeBadges       # Generate badges
```

---

## 14. Troubleshooting

### "GitHub API rate limited"

**Cause:** Exceeded GitHub API rate limit (60/hr unauthenticated, 5,000/hr authenticated).

**Fix:** Set `GITHUB_TOKEN` environment variable. Use `--skip-github` for faster runs without GitHub data.

### "No packages found"

**Cause:** DepSafe could not find a project file at the specified path.

**Fix:** Ensure you're pointing to a directory containing `*.csproj`, `*.sln`, `*.fsproj`, `package.json`, or `package-lock.json`.

### Exit code 2 in CI

**Cause:** A policy threshold in `.cra-config.json` was violated.

**Fix:** Review the JSON or HTML report to identify which threshold was exceeded. Adjust thresholds or fix the underlying issue.

### Missing vulnerability data

**Cause:** Running without `GITHUB_TOKEN` limits vulnerability data to OSV only.

**Fix:** Set `GITHUB_TOKEN` for GitHub Advisory Database integration.

### Slow analysis

**Cause:** Deep scans with many transitive packages and GitHub API calls.

**Fixes:**
- Use `--skip-github` for faster runs
- Omit `--deep` unless you need transitive package scores
- Results are cached for 24 hours; subsequent runs are faster
- Use `--snapshot` for trend tracking instead of running full scans repeatedly

### "Package not found" for npm packages

**Cause:** npm package resolution requires `package-lock.json` for accurate version information.

**Fix:** Run `npm install` to generate `package-lock.json` before running DepSafe.

### Incorrect license detection

**Cause:** Some packages have ambiguous or missing license metadata.

**Fix:** Use `licenseOverrides` in `.cra-config.json` to manually specify the correct license.
