# DepSafe Release Notes

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

Introduced a weighted compliance gauge (0-100) that aggregates all 17 CRA items into a single actionable score, shown as an interactive gauge in HTML reports.

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
