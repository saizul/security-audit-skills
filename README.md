# security-audit-skills

[![CI](https://github.com/saizul/security-audit-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/security-audit-skills/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saizul/security-audit-skills?sort=semver)](https://github.com/saizul/security-audit-skills/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/saizul/security-audit-skills?style=social)](https://github.com/saizul/security-audit-skills/stargazers)

**Agent Skills that help Claude Code and Codex review your own code for security problems and fix them, without ever printing your secrets.**

Nine defensive application-security skills for the checks every web project needs: leaked
secrets, vulnerable dependencies, OWASP Top 10 review, threat modeling, login/session/JWT
design, security headers, injection bugs, Dockerfiles and what to do when something leaks.
Each skill is a step-by-step workflow plus, where it adds reliability, a tested
standard-library-only Python script, so the agent works from exact findings instead of guesses.

- **Defensive only.** Review and fix code you own. No exploit code, no attack tooling, no
  scanning of other people's systems.
- **Secrets stay secret.** Scripts show names, prefixes, lengths and fingerprints, never full
  values. Tokens are read from stdin, not command lines.
- **Read-only by default.** Scripts inspect and report; the workflows ask before changing code,
  accounts or infrastructure.
- **Offline.** No script makes network calls: headers and cookies are graded from HAR files or
  `curl -I` output you capture yourself.
- **Tested.** 150+ tests with fixtures on Python 3.11-3.13 in CI. Scripts run on Python 3.8+.

## Skills

| Skill | What it does | Try asking |
| --- | --- | --- |
| [secrets-scan](skills/secrets-scan/SKILL.md) | Finds provider tokens (AWS, GitHub, Stripe, Slack, Google, npm, LLM keys), private keys, JWTs, URL passwords, high-entropy secrets and `.env`/key files; redacted output, baseline, rotation guide | "Scan this repo for secrets before I make it public" |
| [dependency-audit](skills/dependency-audit/SKILL.md) | Turns `npm audit`, `pip-audit` and `composer audit` JSON into a P1/P2/P3 fix plan with exact upgrade commands | "npm audit shows 40 vulnerabilities, what do I fix first?" |
| [owasp-web-review](skills/owasp-web-review/SKILL.md) | OWASP Top 10:2025 code review (with 2021 mapping): where to look, what to ask, evidence-based findings table | "Do a security review of this Express API" |
| [threat-modeling](skills/threat-modeling/SKILL.md) | STRIDE-per-element threat table from a small JSON model of components, flows and trust boundaries | "Threat model our new webhook integration" |
| [auth-session-review](skills/auth-session-review/SKILL.md) | Password hashing, login/reset/MFA, sessions; checks Set-Cookie flags from a HAR and lints JWTs offline | "Are our session cookies and JWTs set up securely?" |
| [security-headers-check](skills/security-headers-check/SKILL.md) | A-F grade for HSTS, CSP quality, framing, nosniff, Referrer-Policy, CORS and version leaks; fixes for nginx, Apache, Express, Django, Next.js | "Check my site's security headers and write a CSP" |
| [input-validation-review](skills/input-validation-review/SKILL.md) | Finds SQLi, command injection, XSS, SSRF, path traversal, open redirect, deserialization sinks in 7 languages; safe pattern per language | "Is this PHP code vulnerable to SQL injection?" |
| [dockerfile-security](skills/dockerfile-security/SKILL.md) | Lints Dockerfiles: root user, `:latest`, secrets in ENV/ARG, ADD from URL, `curl \| sh`, copied keys; hardened rewrite with BuildKit secrets | "Harden this Dockerfile and fix how we pass NPM_TOKEN" |
| [incident-response-playbook](skills/incident-response-playbook/SKILL.md) | Leaked key, compromised account and malicious dependency playbooks; Markdown incident record with timeline and checklist | "I just pushed my AWS key to GitHub, what now?" |

## Install

### Claude Code: plugin marketplace (recommended)

```text
/plugin marketplace add saizul/security-audit-skills
/plugin install security-audit-skills@security-audit-skills
```

Or from your shell:

```bash
claude plugin marketplace add saizul/security-audit-skills
claude plugin install security-audit-skills@security-audit-skills
```

Plugin skills are namespaced, e.g. `/security-audit-skills:secrets-scan`. Claude also picks
them up automatically when your request matches a skill's description. Update later with
`/plugin marketplace update security-audit-skills`.

### Claude Code: copy the skills

```bash
git clone https://github.com/saizul/security-audit-skills.git
# all projects (personal skills)
mkdir -p ~/.claude/skills && cp -r security-audit-skills/skills/* ~/.claude/skills/
# or just one project
mkdir -p .claude/skills && cp -r security-audit-skills/skills/secrets-scan .claude/skills/
```

`owasp-web-review` calls the `secrets-scan` and `input-validation-review` scripts through
sibling paths, so copy all skills (or adjust the paths) if you use it.

Each release also has one zip per skill and an all-skills zip under
[Releases](https://github.com/saizul/security-audit-skills/releases).

### Codex CLI

Codex reads skills from `~/.agents/skills` (all repositories) and `.agents/skills` in a
repository (from the current directory up to the repository root):

```bash
git clone https://github.com/saizul/security-audit-skills.git
mkdir -p ~/.agents/skills && cp -r security-audit-skills/skills/* ~/.agents/skills/
```

Codex also ships a `$skill-installer` skill that can install skills from a GitHub repository;
ask it to install from `saizul/security-audit-skills`. Skill locations and the installer are
described in the [Codex skills documentation](https://developers.openai.com/codex/skills);
check it if your Codex version behaves differently. [AGENTS.md](AGENTS.md) explains how
Codex and other agents should use these skills.

### Any other agent

The skills follow the open [Agent Skills format](https://agentskills.io/specification):
a folder with `SKILL.md` (YAML frontmatter + instructions), `scripts/`, `references/` and
`assets/`. Point your agent at the folder, or run the scripts yourself; every script has `--help`.

## Usage examples

```text
> We're open-sourcing this repo on Friday. Make sure there are no secrets in it.
  (secrets-scan: working tree + history check, redacted findings, rotation plan for the two
   real keys, a pre-commit hook so it doesn't happen again.)

> Review the orders API for security issues before the pentest.
  (owasp-web-review: maps routes and auth, runs the sink and secret scans, walks A01..A10,
   returns a findings table with file:line evidence: an IDOR and a knex.raw injection.)

> GitHub just emailed me that my Stripe key is public.
  (incident-response-playbook: opens an incident record, roll the key in the dashboard first,
   check Stripe logs for the exposure window, then clean up history and add push protection.)
```

Run the scripts directly too:

```bash
python3 skills/secrets-scan/scripts/secrets_scan.py . --exclude 'tests/fixtures/*'
npm audit --json > npm.json && python3 skills/dependency-audit/scripts/audit_report.py npm.json
curl -sIL https://example.com | python3 skills/security-headers-check/scripts/headers_grade.py -
python3 skills/auth-session-review/scripts/cookie_check.py login.har
python3 skills/input-validation-review/scripts/risky_patterns.py src/ --category sql-injection
python3 skills/dockerfile-security/scripts/dockerfile_lint.py . --json
python3 skills/threat-modeling/scripts/stride.py model.json > THREATS.md
```

## How skills work

At startup the agent loads only each skill's `name` and `description` (about 100 tokens
each). When your request matches a description, it reads that skill's `SKILL.md`: the
workflow, decision points and safety rules. Longer material lives in `references/` and is
read only when a step needs it. Scripts run as normal commands, so their output is exact
and repeatable.

```
skills/<skill-name>/
  SKILL.md          frontmatter (name, description) + workflow
  scripts/          standalone Python 3 helpers (stdlib only, --help, --json, exit codes)
  references/       checklists, playbooks, safe code patterns, config snippets
  assets/           templates (for example the threat model JSON)
```

## FAQ

**Is this a replacement for Semgrep, CodeQL, gitleaks or a pentest?**
No. The scripts are fast, dependency-free first passes with deliberately simple rules, and the
workflows add the human-style reasoning (data-flow tracing, business logic, triage) that tools
miss. Use them alongside dedicated scanners in CI and a professional test for high-risk systems.

**Will the agent see my secrets?**
The scripts never print full secret values, and the skills instruct the agent not to open
flagged lines in a way that echoes them. Your agent can still read any file it has access to,
so keep using your agent's permission settings and `.gitignore`/ignore files for secrets.

**Does anything leave my machine?**
No script sends telemetry or makes network requests. Producing audit input (`npm audit`,
`pip-audit`, `composer audit`) or capturing headers with `curl` uses the network, and the
skills ask before running those.

**Can I use this to test someone else's site?**
No. The skills are for code and systems you own or are authorised to assess, and they contain
no exploit code.

**Why are some findings "info"?**
Severity reflects typical risk for an internet-facing web app: high = likely exploitable with
real impact, medium = needs preconditions, low = defence in depth, info = context or hardening.

## Roadmap

Ideas for new skills (great first contributions; see [CONTRIBUTING.md](CONTRIBUTING.md)):

- `csrf-review` - token, SameSite and Origin checks per framework
- `file-upload-review` - type checks, storage, image processing, zip slip
- `github-actions-security` - unpinned actions, `pull_request_target`, token permissions, script injection
- `cors-review` - parse CORS config and test origin allow-lists offline
- `logging-pii-review` - find secrets and personal data written to logs
- `iac-security-review` - public buckets, open security groups, unencrypted storage in Terraform
- `api-authorization-matrix` - generate a role x endpoint matrix from route files for IDOR review
- C# / .NET rules for `input-validation-review`

## Contributing

Contributions are welcome: new rules, new skills, fewer false positives, better docs. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the skill template, the quality bar and how to run the
validator and tests:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python tools/validate_skills.py && ruff check . && ruff format --check . && pytest
```

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and report security issues privately
as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) (c) Saizul Amin
