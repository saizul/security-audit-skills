# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `auth-session-review`: `jwt_lint.py` reports `iat-future`/`nbf-future` when a time claim is
  ahead of the clock by more than `--leeway` seconds (default 300), and `exp-before-start` when
  `exp` is not after `iat`/`nbf`.

## [0.1.0] - 2026-11-22

### Added

- `secrets-scan`: redacting scanner for provider tokens, private keys, JWTs, URL credentials,
  high-entropy secret assignments and sensitive files; inline allow markers, fingerprint
  baselines; rotation and prevention guides.
- `dependency-audit`: parser for npm audit (v2 and legacy), pip-audit and composer audit JSON
  with P1/P2/P3 prioritisation and upgrade commands; triage guide.
- `owasp-web-review`: OWASP Top 10:2025 review workflow and per-category checklist with the
  2021 mapping.
- `threat-modeling`: STRIDE-per-element threat table generator (Markdown, CSV, JSON) from a JSON
  system model with trust zones; model template and guide.
- `auth-session-review`: Set-Cookie checker for HAR files and raw headers, offline JWT linter,
  and an authentication/session checklist (hashing parameters, reset, MFA, JWT, OIDC).
- `security-headers-check`: A-F header grader for HAR files and `curl -I` output with CSP
  analysis; configuration snippets for common servers and frameworks.
- `input-validation-review`: sink scanner for SQL/command/code injection, XSS, SSRF, path
  traversal, open redirect, deserialization and XXE in Python, JS/TS, PHP, Go, Java/Kotlin,
  Ruby and templates; safe patterns per language.
- `dockerfile-security`: Dockerfile linter (root user, unpinned bases, secrets in ENV/ARG/RUN,
  ADD from URL, curl | sh, copied keys, disabled TLS verification) and hardened examples.
- `incident-response-playbook`: playbooks for leaked secrets, compromised accounts and malicious
  dependencies; incident record helper with checklist and timeline; communication templates.
- Claude Code plugin marketplace manifest, `tools/validate_skills.py`, CI and release workflows.

[Unreleased]: https://github.com/saizul/security-audit-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/security-audit-skills/releases/tag/v0.1.0
