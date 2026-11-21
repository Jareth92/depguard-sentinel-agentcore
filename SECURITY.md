# Security Policy

## Project Status

DepGuard Sentinel is a security engineering prototype. It is not a
production vulnerability scanner or a guarantee of protection against
all prompt-injection or agent-security attacks.

## Reporting a Vulnerability

Please do not disclose suspected vulnerabilities in public issues.

Use GitHub's private vulnerability reporting feature if it is enabled
for this repository.

If private reporting is unavailable, contact the maintainer through
their GitHub profile and request a private reporting channel.

Please include:

- The affected component and revision.
- A concise description of the security impact.
- Reproduction steps and a minimal proof of concept.
- Any relevant mitigation or proposed fix.

Do not include AWS credentials, access tokens, private account data,
or confidential package manifests in reports.

## Scope and Limitations

The project includes an AgentCore client, a local Red Team adapter,
manifest analysis, input validation, and approval-binding components.

Known limitations are documented in the README and
docs/threat-model.md.

The current prototype does not perform CVE database lookups and does
not provide universal confidentiality or network-isolation guarantees.
