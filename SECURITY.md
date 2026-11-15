# Security Policy

## Supported versions

Only the latest published release on [GitHub Releases](https://github.com/mesflit/TrustCheck/releases)
receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub’s **“Report a vulnerability”** button (Security → Advisories) on
`mesflit/TrustCheck`. Include:

- affected version and device / Android version,
- a description of the issue and its impact,
- steps or a proof of concept (defang any live malicious URLs).

We aim to acknowledge reports within 7 days and to publish a fix or mitigation within 90 days,
coordinating disclosure with you.

## Scope

In scope: the Android client in this repository (data leakage, bypass of consent settings,
detection bypasses that are systematic, signing/release pipeline issues).

Out of scope: individual phishing URLs that are not detected (please report them as regular
issues or to the threat-intelligence providers), findings that need a rooted device or physical
access, and the private backend (report those through the same channel; they will be forwarded).

## Detection limits

TrustCheck reduces risk but cannot detect every malicious site. No result is a guarantee of safety.
