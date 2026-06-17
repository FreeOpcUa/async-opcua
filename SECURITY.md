# Security Policy

OPC UA for Rust is a network-facing protocol stack. We take security reports seriously and ask
that potential vulnerabilities be disclosed **privately** so a fix can be prepared before details
become public.

## Supported Versions

Vulnerabilities will be patched in the master branch and potentially the last released branch
depending on the severity and nature of the issue.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.** Public disclosure before a fix
is available puts all users at risk.

Instead, report privately via one of:

- **GitHub private security advisories** — use the repository's *Security → Report a vulnerability*
  ("Report a vulnerability" / private advisory) form. This is the preferred channel.
- **Email** the maintainers (see the contact addresses in `Cargo.toml` / the crate authors) with
  the details, marking the subject as a security report.

Please include: a description of the issue and its impact, a way to reproduce it (or a
proof-of-concept), affected versions/configuration, and a proposed fix if you have one.

## Coordinated disclosure

We aim to acknowledge a report promptly, work with you on a fix and a coordinated disclosure
timeline, and credit you in the advisory/changelog unless you prefer to remain anonymous. Please
allow a reasonable embargo period before any public disclosure so users can upgrade.
