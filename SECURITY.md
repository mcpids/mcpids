# Security Policy

MCPIDS is a security project, so vulnerability reports are handled privately
first and disclosed responsibly after a fix is available.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | Best-effort security fixes |
| Latest tagged release | Security fixes |
| Older releases | Not guaranteed |

## Report a Vulnerability

Use GitHub's private vulnerability reporting flow:

[Report a private vulnerability](https://github.com/mcpids/mcpids/security/advisories/new)

If private vulnerability reporting is unavailable, open a **low-detail** public
issue asking maintainers for a private security contact channel. Do not include
exploit payloads, bypass details, logs with secrets, or tenant data in that
public issue.

## What to Include

- Affected component and version/commit
- Impact summary and expected attacker capabilities
- Reproduction steps or a minimal proof of concept
- Relevant logs, traces, or packet captures with secrets removed
- Suggested fix or mitigation, if known

## Response Targets

- Acknowledgement: within 2 business days
- Triage/update: within 7 business days
- Fix timeline: depends on severity and release scope

## Disclosure

Please give maintainers a reasonable remediation window before public
disclosure. Once a fix is ready, we will publish release notes and credit the
reporter if they want attribution.

## Security Boundaries

The current repository includes intentionally defensive inspection logic and
mock threat fixtures. Please do not submit PRs that add offensive automation,
credential harvesting, or production exploit chains unless the content is
clearly framed as a bounded regression test and reviewed through the security
process.
