# DepSafe

**Dependency Safety and Compliance for .NET and npm Projects**

DepSafe is a comprehensive dependency analysis tool that helps development teams assess package health, ensure EU Cyber Resilience Act (CRA) compliance, and manage supply chain security for both .NET (NuGet) and JavaScript (npm) projects.

[![NuGet](https://img.shields.io/nuget/v/DepSafe.svg)](https://www.nuget.org/packages/DepSafe)
[![NuGet Downloads](https://img.shields.io/nuget/dt/DepSafe.svg)](https://www.nuget.org/packages/DepSafe)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat)

---

## Disclaimer

This is a personal hobby project built and maintained by a single developer in my spare time, with the goal of giving something useful back to the community. It is provided as-is, with no warranties or guarantees of any kind. There is no company, organization, or dedicated team behind it -- just one person who cares about dependency safety and open source.

Please use it at your own risk. While I do my best to keep things working and accurate, I cannot promise timely fixes, support, or continued development. If you find it helpful, that's wonderful -- but please do not rely on it as your sole source of truth for compliance or security decisions.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [cra-report](#cra-report---generate-cra-compliance-report)
  - [analyze](#analyze---analyze-project-health)
  - [check](#check---check-single-package)
  - [sbom](#sbom---generate-software-bill-of-materials)
  - [vex](#vex---generate-vulnerability-exchange-document)
  - [licenses](#licenses---analyze-license-compatibility)
  - [typosquat](#typosquat---detect-typosquatting-attacks)
  - [badge](#badge---generate-readme-badges)
- [Configuration](#configuration)
- [CRA Compliance Report](#cra-compliance-report)
- [CRA Readiness Score](#cra-readiness-score)
- [Health Score Calculation](#health-score-calculation)
- [License Compatibility](#license-compatibility)
- [Environment Variables](#environment-variables)
- [CI/CD Integration](#cicd-integration)
- [MSBuild Integration](#msbuild-integration)
- [License](#license)

---

## Features

### Multi-Ecosystem Support
- **NuGet packages** - Full support for .NET projects, solutions, and Directory.Build.props
- **npm packages** - Full support for package.json and package-lock.json
- **Mixed projects** - Analyze repositories containing both .NET and npm components

### Health Scoring
- **0-100 health score** based on freshness, release cadence, download trends, repository activity, and vulnerabilities
- **Abandonment prediction** - Identifies packages at risk of being abandoned
- **Version status tracking** - Shows available updates with color-coded urgency indicators
- **Peer dependency analysis** - Lists peer dependencies with version requirements (npm)

### EU Cyber Resilience Act (CRA) Compliance (18 items)
- **Article 10 - SBOM** - Software Bill of Materials generation (SPDX 3.0 and CycloneDX)
- **Article 10(4) - KEV Monitoring** - CISA Known Exploited Vulnerabilities catalog integration
- **Article 10(4) - EPSS Scoring** - Exploit Prediction Scoring System for vulnerability prioritization
- **Article 10(6) - Security Updates** - Data-driven detection of archived and stale dependencies
- **Article 10(9) - License Information** - SPDX license identification and compatibility
- **Article 10 - Deprecated Components** - Identifies deprecated packages requiring replacement
- **Article 10 - Cryptographic Compliance** - Detects deprecated crypto algorithms and libraries
- **Article 10 - Supply Chain Integrity** - Typosquatting detection for dependency verification
- **Article 11 - Vulnerability Handling** - VEX document generation with OSV vulnerability data
- **Article 11(4) - Remediation Timeliness** - Tracks unpatched vulnerabilities with available fixes
- **Article 11(5) - Security Policy** - GitHub security policy detection
- **Article 13(5) - Package Provenance** - NuGet and npm registry signature verification
- **Article 13(8) - Support Period** - Detects unmaintained packages lacking ongoing support
- **Article 14 - Incident Reporting** - CSIRT notification detection for actively exploited vulnerabilities (24h/72h/14d deadlines)
- **Annex I Part I(1) - Release Readiness** - Verifies no known exploitable vulnerabilities at release
- **Annex I Part I(10) - Attack Surface** - Dependency tree depth and transitive ratio analysis
- **Annex I Part II(1) - SBOM Completeness** - BSI TR-03183-2 field validation
- **Annex II - Documentation** - Project documentation requirements (README, SECURITY.md, support period)
- **CRA Readiness Score** - Weighted compliance gauge (0-100) across all items

### Security Analysis
- **OSV Vulnerability Database** - Real-time vulnerability scanning (no API key required)
- **CISA KEV Catalog** - Actively exploited vulnerability detection
- **EPSS Scoring** - Exploit probability prediction for prioritization
- **GitHub Advisory Database** - Additional vulnerability context via GitHub API
- **Version-aware filtering** - Only reports vulnerabilities affecting your specific versions

### Reporting
- **Interactive HTML reports** - Dashboard with drill-down, filtering, dependency trees, and force-directed risk heatmap
- **Art. 14 Reporting Obligations** - Flags vulnerabilities requiring CSIRT notification with 24h/72h/14d deadlines
- **Remediation Roadmap** - Prioritized update plan ranked by CRA score improvement, KEV status, and EPSS probability, with per-tier upgrade risk assessment
- **JSON export** - Machine-readable format for automation
- **License attribution files** - Generate THIRD-PARTY-NOTICES in TXT, HTML, or Markdown
- **shields.io badges** - Embeddable status badges for your README

---

## Installation

### As a Global Tool

```bash
dotnet tool install -g DepSafe
```

### As a Local Tool

```bash
dotnet new tool-manifest  # If you don't have a manifest yet
dotnet tool install DepSafe
```

### Verify Installation

```bash
depsafe --version
```

---

## Quick Start

```bash
# Navigate to your project directory
cd /path/to/your/project

# Generate comprehensive CRA compliance report
depsafe cra-report

# Quick health analysis
depsafe analyze

# Check a single package
depsafe check Newtonsoft.Json

# Generate SBOM
depsafe sbom --output sbom.spdx.json

# Check license compatibility
depsafe licenses
```

---

## Commands

### `cra-report` - Generate CRA Compliance Report

Generates a comprehensive EU Cyber Resilience Act compliance report with interactive HTML dashboard.

```bash
depsafe cra-report [<path>] [options]
```

**Arguments:**

| Argument | Description | Default |
|----------|-------------|---------|
| `<path>` | Path to project, solution, or directory | `.` (current directory) |

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <Html\|Json>` | Output format | `Html` |
| `-o, --output <path>` | Output file path | `cra-report.html` |
| `-d, --deep` | Fetch full metadata for all transitive packages | `false` |
| `--skip-github` | Skip GitHub API calls (faster, less data) | `false` |
| `-l, --licenses <Html\|Md\|Txt>` | Generate license attribution file | - |
| `-s, --sbom <CycloneDx\|Spdx>` | Export SBOM in specified format | - |
| `--check-typosquat` | Run typosquatting detection on all dependencies | `false` |
| `--sign` | Sign all generated artifacts with sigil | `false` |
| `--sign-key <path>` | Path to signing key (uses sigil default if omitted) | - |
| `--release-gate` | Evaluate release readiness (blocking/advisory classification) | `false` |
| `--evidence-pack` | Bundle all artifacts into timestamped evidence directory with manifest | `false` |

**Exit Codes:**

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error or non-compliant status |
| `2` | CI/CD policy violation (configured in `.cra-config.json`) |

**Examples:**
```bash
# Basic report
depsafe cra-report

# Full analysis with transitive packages
depsafe cra-report --deep

# Generate report with SBOM and license file
depsafe cra-report --sbom spdx --licenses txt

# JSON output for automation
depsafe cra-report --format json --output compliance.json

# Analyze specific solution
depsafe cra-report ./src/MyApp.sln --deep

# Sign all generated artifacts
depsafe cra-report --sbom spdx --sign

# Sign with a specific key
depsafe cra-report --sign --sign-key ./keys/signing.pem

# Release gate with blocking/advisory classification
depsafe cra-report --release-gate

# Generate evidence pack with all compliance artifacts
depsafe cra-report --evidence-pack --sbom spdx --licenses txt
```

---

### `analyze` - Analyze Project Health

Performs health analysis on all direct dependencies with console output.

```bash
depsafe analyze [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <Table\|Json\|Markdown>` | Output format | `Table` |
| `--fail-below <score>` | Exit with error if project score below threshold | - |
| `--skip-github` | Skip GitHub API calls | `false` |
| `--check-typosquat` | Run typosquatting detection on all dependencies | `false` |

**Examples:**
```bash
# Analyze current project
depsafe analyze

# CI/CD - fail if health score drops below 60
depsafe analyze --fail-below 60

# Generate markdown report
depsafe analyze --format markdown > health-report.md
```

---

### `check` - Check Single Package

Check health of a specific NuGet or npm package.

```bash
depsafe check <package> [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-v, --version <version>` | Specific version to check | Latest |
| `-f, --format <Table\|Json\|Markdown>` | Output format | `Table` |
| `--skip-github` | Skip GitHub API calls | `false` |

**Examples:**
```bash
# Check latest version
depsafe check Newtonsoft.Json

# Check specific version
depsafe check Serilog --version 3.1.1

# JSON output
depsafe check react --format json
```

---

### `sbom` - Generate Software Bill of Materials

Generate SBOM in SPDX 3.0 or CycloneDX format.

```bash
depsafe sbom [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <Spdx\|CycloneDx>` | Output format | `Spdx` |
| `-o, --output <path>` | Output file path | stdout |
| `--skip-github` | Skip vulnerability enrichment | `false` |
| `--sign` | Sign the generated SBOM with sigil | `false` |
| `--sign-key <path>` | Path to signing key | - |

**Examples:**
```bash
# SPDX format to stdout
depsafe sbom

# CycloneDX to file
depsafe sbom --format cyclonedx --output bom.json

# SPDX with full vulnerability data
depsafe sbom --output sbom.spdx.json

# Sign the SBOM
depsafe sbom --output sbom.spdx.json --sign
```

---

### `vex` - Generate Vulnerability Exchange Document

Generate OpenVEX document with vulnerability status for all dependencies.

```bash
depsafe vex [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <path>` | Output file path | stdout |
| `--sign` | Sign the generated VEX document with sigil | `false` |
| `--sign-key <path>` | Path to signing key | - |

**Examples:**
```bash
# Output to console
depsafe vex

# Save to file
depsafe vex --output vulnerabilities.vex.json

# Sign the VEX document
depsafe vex --output vulnerabilities.vex.json --sign
```

---

### Artifact Signing & Verification

DepSafe uses [Sigil.Sign](https://github.com/Falkesand/Sigil.Sign) for detached artifact signing. When you pass `--sign`, each generated artifact gets a `.sig.json` envelope file alongside it containing a cryptographic signature.

**Signing produces:**

| Artifact | Signature File |
|----------|----------------|
| `cra-report.html` | `cra-report.html.sig.json` |
| `sbom.spdx.json` | `sbom.spdx.json.sig.json` |
| `vulnerabilities.vex.json` | `vulnerabilities.vex.json.sig.json` |
| `LICENSES.txt` | `LICENSES.txt.sig.json` |

**Prerequisites:**

Install [Sigil.Sign](https://github.com/Falkesand/Sigil.Sign) as a global tool:

```bash
dotnet tool install -g Sigil.Sign
```

**Signing artifacts:**

```bash
# Sign with default key
depsafe cra-report --sbom spdx --licenses txt --sign

# Sign with a specific key
depsafe cra-report --sign --sign-key ./keys/signing.pem
```

**Verifying artifacts (consumer responsibility):**

Verification is performed externally by the consumer using the `sigil` CLI:

```bash
# Basic verification
sigil verify cra-report.html.sig.json

# Verify with a trust bundle
sigil verify cra-report.html.sig.json --trust-bundle keys.pem

# Verify with DNS discovery
sigil verify cra-report.html.sig.json --discover example.com
```

---

### `licenses` - Analyze License Compatibility

Analyze dependency licenses for compatibility with your project license.

```bash
depsafe licenses [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --project-license <license>` | Your project's SPDX license identifier | `MIT` |
| `-f, --format <table\|json>` | Output format | `table` |
| `-t, --include-transitive` | Include transitive dependencies | `false` |

**Examples:**
```bash
# Check against MIT license
depsafe licenses

# Check against Apache-2.0
depsafe licenses --project-license Apache-2.0

# Include transitive dependencies
depsafe licenses --include-transitive

# JSON output
depsafe licenses --format json
```

---

### `typosquat` - Detect Typosquatting Attacks

Scan project dependencies for potential typosquatting attacks using edit distance analysis, separator substitution, scope confusion, and other detection heuristics.

```bash
depsafe typosquat [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <Table\|Json\|Markdown>` | Output format | `Table` |
| `--offline` | Use embedded popular package data only (skip online refresh) | `false` |

**Examples:**
```bash
# Scan current project
depsafe typosquat

# Offline mode (no network calls for package index)
depsafe typosquat --offline

# JSON output for automation
depsafe typosquat --format json
```

---

### `badge` - Generate README Badges

Generate shields.io badges for your README.

```bash
depsafe badge [<path>] [options]
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <Markdown\|Html\|Json\|Url>` | Output format | `Markdown` |
| `-o, --output <path>` | Output file path | stdout |
| `-s, --style <style>` | Badge style (flat, flat-square, plastic, for-the-badge) | `flat` |
| `--skip-github` | Skip GitHub API calls | `false` |

**Examples:**
```bash
# Generate markdown badges
depsafe badge

# Different style
depsafe badge --style for-the-badge

# HTML format
depsafe badge --format html --output badges.html
```

---

## Configuration

### `.cra-config.json`

Create a `.cra-config.json` file in your project root to customize CRA analysis:

```json
{
  "licenseOverrides": {
    "SixLabors.ImageSharp": "Apache-2.0",
    "SomeInternalPackage": "MIT"
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
  "failOnDeprecatedPackages": true,
  "minHealthScore": 50,
  "failOnKev": true,
  "failOnEpssThreshold": 0.5,
  "failOnVulnerabilityCount": 0,
  "failOnCraReadinessBelow": 70,
  "failOnReportableVulnerabilities": true,
  "failOnUnpatchedDaysOver": 30,
  "failOnUnmaintainedPackages": false,
  "failOnSbomCompletenessBelow": 80,
  "failOnAttackSurfaceDepthOver": 10
}
```

**Configuration Options:**

| Option | Description |
|--------|-------------|
| `licenseOverrides` | Override detected licenses for packages (useful when detection fails) |
| `excludePackages` | Exclude specific packages from analysis (internal/private packages) |
| `complianceNotes` | Add notes/justifications for compliance decisions |
| `supportPeriodEnd` | Declared end of support period, e.g. `"2028-12"` (CRA Annex II) |
| `securityContact` | Security contact email or URL (CRA Annex II) |
| `allowedLicenses` | Allow only these SPDX licenses (packages with other licenses fail CI) |
| `blockedLicenses` | Block specific SPDX licenses (packages with these licenses fail CI) |
| `failOnDeprecatedPackages` | Fail with exit code 2 if any deprecated package is detected |
| `minHealthScore` | Fail if any package health score is below this value (0-100) |
| `failOnKev` | Fail with exit code 2 if any CISA KEV vulnerability is present |
| `failOnEpssThreshold` | Fail if any EPSS probability exceeds this value (0.0-1.0) |
| `failOnVulnerabilityCount` | Fail if active vulnerability count exceeds this number |
| `failOnCraReadinessBelow` | Fail if CRA readiness score is below this value (0-100) |
| `failOnReportableVulnerabilities` | Fail if any CRA Art. 14 reportable vulnerabilities exist |
| `failOnUnpatchedDaysOver` | Fail if any vulnerability has been unpatched longer than N days |
| `failOnUnmaintainedPackages` | Fail if any dependency has no activity for 2+ years |
| `failOnSbomCompletenessBelow` | Fail if SBOM completeness percentage is below threshold (0-100) |
| `failOnAttackSurfaceDepthOver` | Fail if max dependency tree depth exceeds this value |

---

## CRA Compliance Report

The HTML report includes comprehensive compliance information:

### Dashboard
- **CRA Readiness Score** gauge (0-100, weighted across all compliance items)
- Overall CRA compliance status with requirement count
- CRA compliance score gauge
- Health score gauge
- Package count breakdown (direct vs transitive)
- Vulnerability summary and version conflicts
- License status summary
- Recommended actions for non-compliant items

### CRA Requirements Checklist (18 items)
| # | Requirement | CRA Reference | Description |
|---|-------------|---------------|-------------|
| 1 | SBOM | Art. 10 | Software Bill of Materials with all components |
| 2 | Exploited Vulnerabilities | Art. 10(4) | No CISA KEV actively exploited vulnerabilities |
| 3 | Exploit Probability | Art. 10(4) | EPSS scoring for vulnerability prioritization |
| 4 | Security Updates | Art. 10(6) | Data-driven: no archived repos, <10% stale dependencies |
| 5 | License Information | Art. 10(9) | All licenses identified and documented |
| 6 | Deprecated Components | Art. 10 | No deprecated or abandoned packages |
| 7 | Cryptographic Compliance | Art. 10 | No deprecated crypto algorithms or libraries |
| 8 | Supply Chain Integrity | Art. 10 | Typosquatting detection (when `--check-typosquat` enabled) |
| 9 | Vulnerability Handling | Art. 11 | Documentation of known vulnerabilities and status |
| 10 | Remediation Timeliness | Art. 11(4) | Patches applied without delay (NonCompliant if >30 days) |
| 11 | Security Policy | Art. 11(5) | Coordinated vulnerability disclosure (SECURITY.md) |
| 12 | Support Period | Art. 13(8) | Components have ongoing active maintenance |
| 13 | Package Provenance | Art. 13(5) | NuGet and npm registry signature verification |
| 14 | Incident Reporting | Art. 14 | CSIRT notification for actively exploited vulnerabilities (24h/72h/14d) |
| 15 | Release Readiness | Annex I Part I(1) | No known exploitable vulnerabilities at release |
| 16 | Attack Surface | Annex I Part I(10) | Dependency tree depth and transitive ratio analysis |
| 17 | SBOM Completeness | Annex I Part II(1) | BSI TR-03183-2 field validation (supplier, PURL, checksum) |
| 18 | Documentation | Annex II | README, security contact, support period, changelog |

### Package Cards
Each package displays:
- **Health score** (0-100) with status indicator
- **CRA compliance score** (0-100)
- **License** information
- **Version status** - Shows if update available with upgrade urgency
- **Release information** - Last release date, releases per year
- **Repository stats** - Stars, last commit (when GitHub token available)
- **Vulnerabilities** - CVE IDs with links to details
- **Peer dependencies** - For npm packages
- **Dependencies** - Clickable links to navigate dependency tree
- **Recommendations** - Actionable improvement suggestions

### Art. 14 Reporting Obligations
When actively exploited or high-probability vulnerabilities are detected:
- **CSIRT notification deadlines** — 24-hour early warning, 72-hour full notification, 14-day final report
- **Detection criteria** — CISA KEV catalog (confirmed exploitation) or EPSS probability >= 0.5
- **Trigger badges** — KEV, EPSS, or Both indicators per package
- **Overdue tracking** — Highlights deadlines that have already passed
- Shows a success card when no reportable vulnerabilities are found

### Remediation Roadmap
Prioritized update plan for vulnerable dependencies:
- **Priority ranking** — KEV > EPSS >= 0.5 > Critical > High severity > CRA score lift
- **Score Lift** — Estimated CRA readiness score improvement per package update
- **Effort indicator** — Patch (low risk), Minor (new features), Major (breaking changes)
- **Upgrade Risk Assessment** — Composite risk score (0-100) per upgrade tier based on changelog analysis, semver signal, maintainer trust, and version time gap. Risk badges (Low/Medium/High/Critical) with hover tooltips showing risk factors
- **Version recommendations** — Current vs recommended version with CVE count
- Top 20 most impactful updates, sorted by priority
- Shows a success card when no remediation actions are needed

### Dependency Tree
Interactive tree visualization showing:
- Full dependency hierarchy
- Health status per node
- Vulnerability indicators (red highlight for KEV)
- Expand/collapse navigation

### Risk Heatmap
Interactive force-directed graph visualization showing:
- **Node size** proportional to reverse dependency count (how many packages depend on it)
- **Node color** reflects health score (green/yellow/orange/red)
- **Node border** indicates vulnerability status (solid for CVE, dashed for KEV)
- **Edges** show dependency relationships
- Hover to highlight connected packages and view details
- Click to navigate to package details
- Drag nodes, zoom, toggle labels

### SBOM & VEX
- Embedded SBOM (SPDX 3.0 format)
- Embedded VEX document
- Export buttons for both formats

---

## CRA Readiness Score

The CRA Readiness Score is a single weighted metric (0-100) that reflects overall compliance posture. Each compliance item is weighted by CRA importance:

| Weight | Compliance Items |
|--------|-----------------|
| 15 | Exploited Vulnerabilities (KEV), Vulnerability Handling |
| 12 | Incident Reporting (Art. 14) |
| 10 | SBOM, Release Readiness |
| 8 | Remediation Timeliness |
| 7 | Exploit Probability (EPSS) |
| 6 | Security Updates |
| 5 | Support Period, Attack Surface, SBOM Completeness |
| 4 | Package Provenance |
| 3 | Documentation |
| 2 | License Information, Security Policy |
| 1 | Deprecated Components, Cryptographic Compliance, Supply Chain Integrity |

**Score calculation per item:**

| Item Status | Score Multiplier |
|-------------|-----------------|
| Compliant | 100% of weight |
| Review | 50% of weight |
| ActionRequired | 25% of weight |
| NonCompliant | 0% of weight |

---

## Health Score Calculation

Each package receives a health score (0-100) based on weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Freshness** | 25% | Days since last release |
| **Release Cadence** | 15% | Average releases per year |
| **Download Trend** | 20% | Growing/stable/declining downloads |
| **Repository Activity** | 25% | Recent commits, stars, open issues |
| **Vulnerabilities** | 15% | Known security vulnerabilities |

### Score Interpretation

| Score | Status | Description |
|-------|--------|-------------|
| 80-100 | **Healthy** | Actively maintained, low risk |
| 60-79 | **Watch** | Some concerns, monitor closely |
| 40-59 | **Warning** | Consider alternatives |
| 0-39 | **Critical** | High abandonment risk, action needed |

### CRA Compliance Score

Separate from health score, focuses on regulatory requirements:

| Factor | Points | Description |
|--------|--------|-------------|
| No vulnerabilities | 60 | Critical/High = 0-15 pts, Medium/Low = 30 pts |
| License identified | 25 | SPDX license = 25 pts, Non-standard = 15 pts |
| Package identifiable | 15 | Name + version present |

---

## License Compatibility

The `licenses` command detects potential license conflicts:

| Category | Licenses | Risk Level |
|----------|----------|------------|
| **Permissive** | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense | Low |
| **Weak Copyleft** | LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0 | Medium |
| **Strong Copyleft** | GPL-2.0, GPL-3.0, AGPL-3.0 | High |

### Compatibility Matrix

| Your License | Can Use Permissive | Can Use Weak Copyleft | Can Use Strong Copyleft |
|--------------|-------------------|----------------------|------------------------|
| MIT | ✅ | ⚠️ (with care) | ❌ |
| Apache-2.0 | ✅ | ⚠️ (with care) | ❌ |
| GPL-3.0 | ✅ | ✅ | ✅ |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token for higher API rate limits, vulnerability data, and private repository access |

### Setting Up GitHub Token

For best results, create a GitHub personal access token with `public_repo` scope:

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate a new token with `public_repo` scope
3. Set the environment variable:

**Windows (PowerShell):**
```powershell
$env:GITHUB_TOKEN = "ghp_your_token_here"
```

**Linux/macOS:**
```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

---

## CI/CD Integration

### Build Gate with `.cra-config.json`

DepSafe supports config-driven CI/CD build gates via `.cra-config.json`. When thresholds are violated, DepSafe returns **exit code 2** (distinct from exit code 1 for tool errors), making it easy to fail builds on policy violations.

```json
{
  "failOnKev": true,
  "failOnVulnerabilityCount": 0,
  "failOnCraReadinessBelow": 70,
  "failOnReportableVulnerabilities": true,
  "failOnUnpatchedDaysOver": 30,
  "failOnUnmaintainedPackages": true,
  "failOnSbomCompletenessBelow": 80,
  "failOnAttackSurfaceDepthOver": 10
}
```

| Exit Code | Meaning |
|-----------|---------|
| `0` | All checks passed |
| `1` | Tool error or non-compliant status |
| `2` | CI/CD policy violation (threshold exceeded) |

### GitHub Actions

```yaml
name: Dependency Health Check

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday

jobs:
  health-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Install DepSafe
        run: dotnet tool install -g DepSafe

      - name: Run Health Analysis
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: depsafe analyze --fail-below 60

      - name: CRA Compliance Gate
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          depsafe cra-report --deep --output cra-report.html
          # Exit code 2 = policy violation (from .cra-config.json thresholds)

      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cra-compliance-report
          path: cra-report.html
```

### Azure DevOps

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

  - script: depsafe analyze --fail-below 60
    displayName: 'Check Dependency Health'
    env:
      GITHUB_TOKEN: $(GITHUB_TOKEN)

  - script: depsafe cra-report --deep --output $(Build.ArtifactStagingDirectory)/cra-report.html
    displayName: 'Generate CRA Report'
    env:
      GITHUB_TOKEN: $(GITHUB_TOKEN)

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: compliance-reports
```

### GitLab CI

```yaml
dependency-health:
  image: mcr.microsoft.com/dotnet/sdk:10.0
  script:
    - dotnet tool install -g DepSafe
    - export PATH="$PATH:$HOME/.dotnet/tools"
    - depsafe analyze --fail-below 60
    - depsafe cra-report --deep --output cra-report.html
  artifacts:
    paths:
      - cra-report.html
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

---

## MSBuild Integration

Add to your `.csproj` to enable build-time health checks:

```xml
<PropertyGroup>
  <!-- Enable health checking during build -->
  <DepSafeEnabled>true</DepSafeEnabled>

  <!-- Fail build if score below threshold (0 = disabled) -->
  <DepSafeFailBelow>60</DepSafeFailBelow>

  <!-- Warn if score below threshold -->
  <DepSafeWarnBelow>80</DepSafeWarnBelow>

  <!-- Skip GitHub API for faster builds -->
  <DepSafeSkipGitHub>true</DepSafeSkipGitHub>
</PropertyGroup>
```

### MSBuild Targets

```bash
# Run health check manually
dotnet msbuild -t:DepSafeCheck

# Generate health report
dotnet msbuild -t:DepSafeReport

# Check license compatibility
dotnet msbuild -t:DepSafeLicenseCheck

# Generate badges
dotnet msbuild -t:DepSafeBadges
```

---

## Data Sources

DepSafe integrates with multiple data sources:

| Source | Data | Authentication |
|--------|------|----------------|
| **NuGet API** | Package metadata, versions, downloads, provenance | None required |
| **npm Registry** | Package metadata, versions, dependencies, provenance | None required |
| **OSV Database** | Vulnerability data for all ecosystems | None required |
| **CISA KEV** | Actively exploited vulnerabilities | None required |
| **FIRST EPSS** | Exploit prediction probability scores | None required |
| **GitHub API** | Repository stats, security policies, advisories | Optional (GITHUB_TOKEN) |

---

## Troubleshooting

### Rate Limiting

If you encounter rate limiting errors:
1. Set `GITHUB_TOKEN` environment variable
2. Use `--skip-github` for faster runs without GitHub data
3. Run during off-peak hours

### Mixed Project Detection

DepSafe automatically detects project type:
- **.NET only** - Contains `.csproj`, `.sln`, or `Directory.Build.props`
- **npm only** - Contains `package.json` without .NET files
- **Mixed** - Contains both .NET and npm files

### False Positive Vulnerabilities

If a vulnerability doesn't apply to your usage:
1. Check the vulnerability details in the report
2. Create a VEX document to document your assessment
3. Use `.cra-config.json` to add compliance notes

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## Disclaimer

**This software is provided for informational purposes only and does not constitute legal, compliance, or security advice.**

The compliance assessments, health scores, vulnerability reports, and other outputs generated by this software are based on automated analysis and publicly available data sources. They may be incomplete, inaccurate, or outdated.

- Users are solely responsible for verifying compliance requirements with qualified professionals
- Security assessments should be validated with appropriate security experts
- Use of this software does not establish compliance with any regulation, including the EU Cyber Resilience Act (CRA)
- The authors are not liable for any damages resulting from use of this software

**USE AT YOUR OWN RISK.**

---

## License

AGPL-3.0 - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [OSV](https://osv.dev/) - Open Source Vulnerability database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known Exploited Vulnerabilities catalog
- [FIRST EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [BSI TR-03183-2](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html) - SBOM requirements for CRA
- [SPDX](https://spdx.dev/) - Software Package Data Exchange
- [CycloneDX](https://cyclonedx.org/) - Software Bill of Materials standard
- [OpenVEX](https://openvex.dev/) - Vulnerability Exploitability eXchange
- [Sigil.Sign](https://github.com/Falkesand/Sigil.Sign) - Artifact signing and verification
