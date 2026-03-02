# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ShieldClaw, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisory** (preferred): Use [GitHub's private vulnerability reporting](https://github.com/Zandereins/openclaw-skill-shieldclaw/security/advisories/new)
2. **Email**: Contact the maintainer via the email listed in the Git commit history

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected versions
- Potential impact assessment

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix or mitigation**: Depends on severity, typically within 30 days

### Scope

The following are in scope:

- Pattern bypass techniques (evasion of detection)
- ReDoS (Regular Expression Denial of Service) in patterns
- Path traversal or self-path exclusion bypass
- Hook bypass or manipulation
- Information disclosure through error messages
- Canary token detection evasion

The following are **out of scope**:

- Novel prompt injection techniques not covered by current patterns (submit as feature request instead)
- Issues in dependencies (report upstream)
- Issues in OpenClaw core (report to OpenClaw)

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations and disruption
- Provide sufficient detail for us to reproduce and fix the issue
- Do not exploit the vulnerability beyond what is necessary to demonstrate it

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Design Philosophy

ShieldClaw is a defense-in-depth tool. Its pattern database is intentionally public — security through obscurity is not a goal. Detection patterns should remain effective even when fully disclosed.
