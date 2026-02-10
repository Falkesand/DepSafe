# DepSafe Roadmap

## Current State (v1.5.1)

DepSafe is a CLI tool for .NET and npm dependency health analysis with EU Cyber Resilience Act (CRA) compliance reporting. Current capabilities:

- Multi-ecosystem support (.NET + npm, mixed projects)
- Health scoring (0-100) per package with 8 weighted factors
- CRA compliance reporting (18 items) with readiness score
- SBOM generation (SPDX 3.0, CycloneDX 1.5)
- VEX document generation (OpenVEX)
- License compatibility analysis
- Vulnerability scanning (OSV, CISA KEV, EPSS)
- Typosquatting detection (Damerau-Levenshtein + heuristics)
- Artifact signing via Sigil.Sign
- Remediation roadmap with prioritized fix recommendations
- Art. 14 incident reporting obligation detection
- CI/CD integration with configurable policy thresholds

---

## Phase 1 — Make Findings More Actionable

Low-to-medium effort features that build directly on existing infrastructure.

### 1.1 Policy as Code (Enhanced)

**Effort:** Low | **Builds on:** CraConfig, CI/CD thresholds

Expand `.cra-config.json` into a full policy engine. Teams define rules declaratively:

```json
{
  "rules": {
    "noCriticalVulns": true,
    "minPackageMaintainers": 2,
    "blockUnmaintainedMonths": 18,
    "allowedLicenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
    "blockDeprecatedPackages": true
  }
}
```

Fail CI with clear, developer-readable explanations — not just exit codes.

**Already have:** `CraConfig` with 5 CI/CD thresholds, exit code 2 for violations.
**Gap:** More rule types, human-readable failure messages, license allowlist enforcement.

### 1.2 Compliance Auto-Evidence Pack

**Effort:** Low | **Builds on:** SBOM, VEX, CRA report, license output

One command bundles all compliance artifacts for a release:

```bash
depsafe evidence-pack --release 2.4.0 --output evidence/
```

Produces a timestamped directory with:
- CRA compliance report (HTML + JSON)
- SBOM (SPDX + CycloneDX)
- VEX document
- License attribution
- Signed artifacts (`.sig.json`)
- Manifest file linking everything together

**Already have:** All individual generators. **Gap:** Bundling orchestration and manifest.

### 1.3 Release Readiness Score (Enhanced)

**Effort:** Low | **Builds on:** CRA Readiness Score, compliance items

Reframe the existing CRA readiness score into a release go/no-go signal:

```
Release Risk Score: 72 / 100

Blocking:
- 1 exploitable HIGH vulnerability (CISA KEV)
- 2 packages with no maintainer activity in 3+ years

Advisory:
- 1 GPL transitive license risk
- 3 packages behind latest patch version
```

**Already have:** CRA readiness score, compliance items, remediation roadmap.
**Gap:** Blocking vs advisory classification, release-oriented output format.

### 1.4 Security Budget Optimizer

**Effort:** Medium | **Builds on:** RemediationPrioritizer, health scores

Given limited dev time, suggest highest-ROI fixes:

```
Fixing these 3 issues reduces total risk by 62%:
  1. Upgrade Newtonsoft.Json 12.0.1 → 13.0.3 (fixes 2 CVEs, 15min effort)
  2. Replace Moq 4.18.0 (single maintainer, 0 releases in 2y)
  3. Pin transitive yaml-parser to 2.1.4 (KEV listed)

These 10 others only reduce risk by 4%.
```

**Already have:** `RemediationPrioritizer` with KEV > EPSS > severity ranking.
**Gap:** Effort estimation, cumulative risk reduction calculation, grouping.

---

## Phase 2 — Deeper Dependency Intelligence

Medium effort features requiring new data analysis on top of existing data sources.

### 2.1 Safe Upgrade Path Suggestions

**Effort:** Medium | **Builds on:** NuGet/npm version data, vulnerability data

Instead of just "upgrade to latest", show the safest path:

```
Newtonsoft.Json 12.0.1:
  Patch fix:   12.0.3 — fixes CVE-2024-xxxx, no API changes
  Minor bump:  12.0.3 → 13.0.3 — fixes all CVEs, minor API changes
  Major bump:  13.0.3 → 14.0.0 — breaking changes in JToken API
  Recommended: 12.0.3 (lowest risk, fixes known vulnerabilities)
```

**Already have:** Version fetching from NuGet/npm, vulnerability-to-version mapping.
**Gap:** Semantic version diffing, breaking change detection heuristics, patch-only recommendations.

### 2.2 Maintainer Trust Score

**Effort:** Medium | **Builds on:** GitHub API data, typosquatting detection

Score packages based on maintainer health signals:

- Maintainer count and recent churn
- Sudden maintainer changes (ownership transfer risk)
- Release frequency anomalies (long gaps then sudden burst)
- Account age of publishers
- Bus factor (single-maintainer risk)

**Already have:** GitHub repo info (stars, last commit, archived status), bus factor via contributor data.
**Gap:** Maintainer change tracking, anomaly detection, composite trust score.

### 2.3 Security Debt Trend

**Effort:** Medium | **Requires:** Persistence layer

Track risk posture over time:

- Risk score per release/commit
- Percentage of exploitable vulnerabilities fixed
- Mean time to remediate
- New vs inherited vulnerabilities per sprint

**Already have:** All scoring infrastructure.
**Gap:** Persistence (JSON file store or SQLite), historical comparison, trend visualization.

### 2.4 Audit Simulation Mode

**Effort:** Medium | **Builds on:** Compliance items, policy engine

Simulate what an external security auditor would flag:

```bash
depsafe cra-report --audit-mode
```

```
Findings a security auditor would likely raise:
- Logging library last updated 2017 (Art. 13(8) Support Period)
- Package with single maintainer and 10M downloads (supply chain risk)
- 3 dependencies without license metadata (Art. 10(9))
- Transitive dependency 4 levels deep with known CVE (Annex I Part I(10))
```

**Already have:** All compliance checks. **Gap:** Stricter thresholds, auditor-perspective framing, policy presets (e.g., `--policy strict`).

### 2.5 Upgrade Risk Predictor

**Effort:** Medium | **Builds on:** Version data, GitHub data, vulnerability data

Before bumping a major dependency, estimate combined risk:

- API break likelihood (semver analysis + changelog parsing)
- Security posture improvement (CVEs fixed)
- Maintainer stability trend (active vs declining)

**Already have:** Version data, maintainer activity signals. **Gap:** Changelog analysis, composite risk model.

---

## Phase 3 — Visualization & Reporting

### 3.1 Transitive Dependency Risk Heatmap

**Effort:** Medium | **Builds on:** Dependency trees, health scores

Visual graph in the HTML report:

- Node size = how widely depended on (reverse dependency count)
- Color = risk score (green/yellow/red)
- Border = has known vulnerabilities
- Edges = dependency relationships

**Already have:** Full dependency trees, health scores, reverse dependency lookup.
**Gap:** Graph rendering (D3.js or similar in HTML report).

---

## Future Exploration

Ideas with high potential but requiring capabilities beyond current architecture. These would represent a significant expansion of DepSafe's scope.

### Reachability / Code Path Awareness

Determine whether a vulnerable function is actually called from application code. Would require static analysis / call graph construction (similar to Snyk Code, CodeQL). Cuts ~70% of vulnerability noise but is a multi-year engineering effort and effectively a different product category.

### Exploit Context Enrichment

For each vulnerability, provide attacker preconditions and app-specific risk assessment. Would require LLM integration or a curated knowledge base. Turns scanner output into decision support.

### PR Security Diff Bot

GitHub App / PR bot that comments on dependency changes with risk assessment. Requires a service deployment model rather than CLI. Natural evolution if DepSafe gains a server component.

### IDE Risk Lens

IDE extension (VS Code, Rider) showing risk scores on hover over package references. Different product surface (extension vs CLI) but high developer experience value.

### Feature-to-Dependency Mapping

Map business features to their dependency chains to quantify "if we rewrite feature X, we remove Y high-risk packages." Requires application architecture understanding beyond dependency scanning.

### Dependency Behavior Profiling

Flag packages that open network connections, spawn processes, use reflection, or access filesystem broadly — even without known CVEs. Behavioral supply chain risk analysis (similar to Socket.dev). Requires package binary/source analysis capabilities.

### Attacker Simulation Mode

Model "if package X is compromised, what can an attacker reach?" Requires call graph + taint analysis. High-value for supply chain threat modeling.

---

## Positioning

DepSafe aims to be:

> "The tool that helps developers make smart dependency decisions, not just safe ones."

The roadmap prioritizes features that build on existing infrastructure (scoring, compliance, dependency trees) before expanding into new capability domains. Each phase delivers standalone value while building toward a comprehensive dependency intelligence platform.
