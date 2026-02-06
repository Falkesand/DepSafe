# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in DepSafe, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](../../security/advisories) of this repository
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Email**
   - Send details to the repository maintainers
   - Use a descriptive subject line: `[SECURITY] Brief description`

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., injection, information disclosure, authentication bypass)
- **Affected component** (e.g., specific command, API client, report generator)
- **Steps to reproduce** the vulnerability
- **Proof of concept** code or commands if available
- **Impact assessment** - what could an attacker achieve?
- **Suggested fix** if you have one

### Severity Classification

We use the following severity levels to prioritize issues:

| Severity | Description |
|----------|-------------|
| **Critical** | Remote code execution, credential theft |
| **High** | Significant data exposure, privilege escalation |
| **Medium** | Limited data exposure, denial of service |
| **Low** | Minor information disclosure |

## Security Practices

### In This Tool

DepSafe implements the following security practices:

#### Input Validation
- All file paths are validated and sanitized
- Output paths are restricted to prevent directory traversal
- User input is escaped in HTML reports to prevent XSS

#### Network Security
- All API calls use HTTPS
- HTTP timeouts prevent hanging connections
- No sensitive data is transmitted to external services

#### Data Handling
- GitHub tokens are read from environment variables only
- Tokens are never logged or included in reports
- No persistent storage of credentials

#### Dependencies
- Dependencies are regularly updated
- Vulnerability scanning is performed on our own dependencies
- Only well-maintained packages from trusted sources are used

### Recommended Practices for Users

When using DepSafe:

1. **Protect your GitHub token**
   - Use environment variables, not command-line arguments
   - Use tokens with minimal required permissions (`public_repo` scope)
   - Rotate tokens regularly

2. **Review generated reports**
   - HTML reports may contain package names and versions
   - SBOM/VEX files contain detailed dependency information
   - Consider these files sensitive in some contexts

3. **CI/CD Security**
   - Store tokens in secure secret management
   - Limit access to generated reports
   - Consider running in isolated environments

4. **Output File Security**
   - Generated reports are written to the current directory by default
   - Ensure appropriate file permissions on output files
   - Be cautious when generating reports in shared directories

## Security Features

DepSafe helps you maintain security in your projects:

| Feature | Description |
|---------|-------------|
| **Vulnerability Scanning** | Checks dependencies against OSV database |
| **CISA KEV Monitoring** | Alerts on actively exploited vulnerabilities |
| **EPSS Scoring** | Exploit probability prediction for vulnerability prioritization |
| **License Compliance** | Identifies potential license conflicts |
| **SBOM Generation** | Creates software inventory for security audits |
| **SBOM Validation** | Validates SBOM completeness per BSI TR-03183-2 |
| **VEX Documents** | Documents vulnerability status for compliance |
| **Health Scoring** | Identifies potentially abandoned packages |
| **Package Provenance** | Verifies NuGet and npm registry signatures |
| **Attack Surface Analysis** | Evaluates dependency tree depth and transitive ratio |
| **Remediation Tracking** | Monitors unpatched vulnerabilities with available fixes |
| **Typosquatting Detection** | Supply chain integrity verification |
| **CI/CD Build Gates** | Config-driven policy enforcement with exit code 2 |

## Disclosure Policy

We follow a coordinated disclosure policy:

1. **Reporter submits vulnerability** via private channel
2. **We acknowledge receipt**
3. **We investigate and develop fix**
4. **We release patched version**
5. **We publish security advisory** with credit to reporter (if desired)
6. **Reporter may publish details** after advisory is public

We kindly ask reporters to:
- Give us reasonable time to address the issue before public disclosure
- Make a good faith effort to avoid privacy violations and data destruction
- Not access or modify other users' data without permission

## Security Updates

Security updates are distributed through:

- **GitHub Releases** - Patch releases for security fixes
- **GitHub Security Advisories** - Detailed vulnerability information
- **NuGet Package Updates** - Updated tool packages

To stay informed:
- Watch this repository for releases
- Enable GitHub security alerts
- Regularly update to the latest version

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Reporters who follow this policy will be:

- Credited in the security advisory (unless anonymity is preferred)
- Thanked in release notes
- Added to our security acknowledgments

---

Thank you for helping keep DepSafe and its users secure.
