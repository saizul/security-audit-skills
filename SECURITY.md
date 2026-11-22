# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## What counts as a vulnerability

These skills are run by AI agents on real codebases that may contain secrets, so unsafe
behaviour is treated like a code vulnerability:

- A script that prints a full secret value (token, password, cookie, JWT signature) in text or
  JSON output, or writes one to a file (baselines must contain fingerprints only)
- A script that makes a network request, writes outside the file it was asked to create, or
  executes content from the files it scans
- Crafted input files (source code, Dockerfiles, HAR, audit JSON) that make a script execute
  something, hang indefinitely or crash in a way that hides findings
- A `SKILL.md` workflow that tells the agent to rotate credentials, rewrite history, change
  accounts or modify code without asking the user first, or that produces offensive content
  (exploit code, attack instructions)

A check that misses a problem (false negative) or flags safe code (false positive) is a normal
bug: please open an issue with a minimal, redacted example.

## Reporting

Please **do not** open a public issue. Use
[GitHub private vulnerability reporting](https://github.com/saizul/security-audit-skills/security/advisories/new)
with the affected skill, version, impact and steps to reproduce. Use obviously fake values in
examples; never send real secrets.

You will get an answer within 5 working days. Fixes are released as soon as possible and
credited in the changelog unless you prefer otherwise.
