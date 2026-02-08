# DepSafe Release Notes

## v1.5.1

### License Change

DepSafe is now licensed under the GNU Affero General Public License v3.0 (AGPL-3.0), replacing the previous MIT license. This ensures that modifications to DepSafe — including use as a network service — must be shared under the same terms, strengthening alignment with the open-source transparency principles of the EU Cyber Resilience Act.

### Code Quality

- Extracted OSV DTO models to a partial class file (`OsvApiClient.Models.cs`), reducing `OsvApiClient.cs` to pure HTTP/business logic
- Replaced hardcoded API URLs with named constants in `PackageProvenanceChecker`
- Fixed README documentation discrepancies (outdated command examples, incorrect default values, missing options)

---

## v1.5.0

### CRA Art. 14 — Reporting Obligation Detection

DepSafe now detects vulnerabilities that trigger mandatory CSIRT notification under EU CRA Article 14. A vulnerability is flagged as reportable if it appears in the CISA KEV catalog (confirmed active exploitation) or has an EPSS probability >= 0.5 (high likelihood of exploitation within 30 days). The report displays computed deadlines for each obligation:

- **24 hours** — Early warning to CSIRT (Art. 14(2)(a))
- **72 hours** — Full vulnerability notification with details and mitigations (Art. 14(2)(b))
- **14 days** — Final report including root cause and corrective measures (Art. 14(2)(c))

This is compliance item #18, weighted at 12 in the CRA readiness score. When no reportable vulnerabilities exist, the section displays a success card confirming no CSIRT notification is required.

### Remediation Roadmap

A new prioritized update plan ranks vulnerable dependencies by their impact on CRA compliance. Packages are sorted by: actively exploited (CISA KEV) first, then high EPSS probability, then by vulnerability severity and estimated CRA readiness score improvement. Each entry shows:

- **Score Lift** — Estimated CRA readiness score improvement if the package is updated
- **Effort** — Whether the update is a Patch (low risk), Minor (new features), or Major (potential breaking changes) version bump
- **Version recommendation** — Current vs recommended version with CVE count

The roadmap displays the top 20 most impactful updates. Both the reporting obligations and remediation roadmap use version-aware filtering, only considering vulnerabilities that actually affect the installed package version.

### Expanded CI/CD Policy Thresholds

Five new build gate thresholds in `.cra-config.json`, bringing the total to nine:

| Threshold | CRA Reference | Description |
|-----------|---------------|-------------|
| `failOnReportableVulnerabilities` | Art. 14 | Fail if any CSIRT-reportable vulnerabilities exist |
| `failOnUnpatchedDaysOver` | Art. 11(4) | Fail if any vulnerability unpatched longer than N days |
| `failOnUnmaintainedPackages` | Art. 13(8) | Fail if any dependency has no activity for 2+ years |
| `failOnSbomCompletenessBelow` | Annex I Part II(1) | Fail if SBOM completeness below N% |
| `failOnAttackSurfaceDepthOver` | Annex I Part I(10) | Fail if dependency tree depth exceeds N |

All thresholds return exit code 2 for CI/CD integration.

### Complete SBOM Generation with Transitive Dependencies

The standalone `depsafe sbom` command now generates complete SBOMs that include all transitive dependencies and npm packages, matching the completeness of the CRA report's SBOM output. Previously, the SBOM command only included direct NuGet packages parsed from project files.

- **.NET transitive resolution** via `dotnet list package --include-transitive`, capturing the full dependency graph
- **npm support** with dependency tree walking, package-lock.json integrity hashes, and scope-based author extraction
- **Mixed project support** for solutions containing both .NET and npm projects, with automatic deduplication
- **Parallel npm fetching** with semaphore-based concurrency (10 concurrent requests) for fast metadata collection

For a typical mixed project, SBOM output increased from ~22 packages (direct NuGet only) to ~600+ packages (direct + transitive, NuGet + npm). This brings the standalone SBOM command into compliance with SPDX/CycloneDX completeness requirements and CRA Annex I Part II(1).

### Always-Visible Report Sections

Art. 14 Reporting and Remediation Roadmap sections are now always visible in the sidebar navigation, even when no data is present. Empty sections display a success card explaining why the view is empty and what the section monitors.

---

## v1.4.0

### .NET 10 and .NET Framework Support

Upgraded the target framework from .NET 8 to .NET 10, bringing automatic runtime improvements including better GC compaction, improved JIT escape analysis, and reduced LINQ abstraction overhead.

DepSafe now also supports .NET Framework 4.8 projects that use `packages.config` for dependency management. When no `<PackageReference>` elements are found in a project file, DepSafe automatically falls back to parsing `packages.config` in the same directory. Since `packages.config` is a flat resolved list, no separate transitive resolution is needed. The false-positive SBOM completeness warning that previously triggered for these projects has been fixed.

### Performance Optimizations

- **Frozen collections** for read-heavy lookup tables (license maps, SPDX identifiers, typosquatting index) using `FrozenDictionary` and `FrozenSet`
- **Shared JSON serializer options** via a centralized `JsonDefaults` class, eliminating 13 repeated `JsonSerializerOptions` allocations across all commands
- **`System.Threading.Lock`** for faster locking in concurrent vulnerability fetching
- **Hot-path fixes in HTML report generation**: cached `ToLowerInvariant()` calls, materialized LINQ group counts, and eliminated redundant `Distinct()` enumerations in dependency tree rendering
- **O(1) CVE deduplication** using `HashSet<string>` instead of `List.Contains()` in vulnerability parsing

---

## v1.3.0

### npm Provenance Verification

Added package provenance checking for npm packages, verifying registry signatures and attestations to support CRA Article 13(5) compliance. SBOM generation now tracks missing fields per-package for more accurate completeness reporting.

### Code Quality

- Extracted ~2,500 lines of CSS from `CraReportGenerator` into a separate embedded resource file
- Removed the 8-parameter `SetHandler` limitation using `BinderBase<T>`
- Eliminated double report generation via a `GenerateArtifacts`/`Generate` split
- Fixed resource leaks, thread safety issues, and regex compilation patterns
- Reduced memory allocations with switch-based HTML escaping and dictionary-based health lookups

---

## v1.2.0

### CRA Deeper Compliance

Expanded CRA compliance coverage from 10 to 17 items with seven new checks:

- **Article 13(8)** - Support period detection for unmaintained packages
- **Article 11(4)** - Remediation timeliness tracking for unpatched vulnerabilities
- **Article 13(5)** - Package provenance verification via NuGet signatures
- **Annex I Part I(1)** - Release readiness validation (no known exploitable vulnerabilities)
- **Annex I Part I(10)** - Attack surface analysis (dependency tree depth and transitive ratio)
- **Annex I Part II(1)** - SBOM completeness validation against BSI TR-03183-2
- **Annex II** - Documentation requirements verification (README, SECURITY.md)

Article 10(6) was reworked to be data-driven, detecting archived and stale dependencies from actual repository metadata rather than heuristics.

### CRA Readiness Score

Introduced a weighted compliance gauge (0-100) that aggregates all CRA compliance items into a single actionable score, shown as an interactive gauge in HTML reports.

### CI/CD Policy Enforcement

Added `.cra-config.json` support for defining compliance thresholds. DepSafe exits with code 2 when policy violations are detected, enabling automated quality gates in CI/CD pipelines.

---

## v1.1.0

### EPSS Integration

Added Exploit Prediction Scoring System (EPSS) support for vulnerability prioritization. Each vulnerability now includes its probability of exploitation and percentile ranking, helping teams focus remediation on the most likely threats.

### Typosquatting Detection

New `typosquat` command that checks project dependencies against a curated index of popular packages using five detection layers:

- Damerau-Levenshtein edit distance
- Separator manipulation (e.g., `lodash` vs `lo-dash`)
- Scope/prefix confusion (e.g., `@types/react` vs `types-react`)
- Character substitution (e.g., `rn` vs `m`)
- Repeated character detection

Includes embedded seed data for both NuGet and npm ecosystems with length-bucketed indexing for fast similarity search.

---

## v1.0.1

Patch release with early performance and correctness improvements.

---

## v1.0.0

Initial release with core functionality:

- Health scoring (0-100) for NuGet and npm packages
- CRA compliance reporting with 10 compliance items
- Interactive HTML reports with dependency tree visualization
- SPDX 3.0 and CycloneDX SBOM generation
- VEX document generation with OSV vulnerability data
- License compatibility analysis and attribution file generation
- CISA KEV catalog integration
- shields.io badge generation
