# AGENTS.md

Guidance for Codex CLI and other coding agents that use or work on this repository.

## Using the skills

The skills live in `skills/<name>/SKILL.md` and follow the Agent Skills format. Codex
discovers them when they are copied to `~/.agents/skills/` or `.agents/skills/` (see
README "Install"). If you are reading this file inside the repository instead:

1. Pick the skill whose `description` matches the user's request:

   | Request is about | Skill |
   | --- | --- |
   | secrets, API keys, `.env` or keys committed to a repo | `secrets-scan` |
   | npm audit, pip-audit, composer audit, Dependabot alerts | `dependency-audit` |
   | general security review of a web app, API or pull request | `owasp-web-review` |
   | threat model, STRIDE, security design review | `threat-modeling` |
   | login, password hashing, reset, MFA, sessions, cookies, JWT, OAuth | `auth-session-review` |
   | HSTS, CSP, security headers, CORS headers | `security-headers-check` |
   | SQL injection, XSS, command injection, SSRF, path traversal | `input-validation-review` |
   | Dockerfile / Containerfile hardening, build secrets | `dockerfile-security` |
   | leaked key, compromised account, malicious package, incident runbook | `incident-response-playbook` |

2. Read that `SKILL.md` completely and follow its Workflow section in order.
3. Paths such as `scripts/x.py`, `references/y.md` and `assets/z.json` are relative to the
   skill folder. `${CLAUDE_SKILL_DIR}` in the text means that folder; Codex does not expand it.
4. Read files in `references/` only when a workflow step points to them.

## Safety rules (apply to every skill)

- Defensive scope only: review and fix code and systems the user owns or is authorised to
  assess. Do not write exploit code, attack payloads or instructions for attacking others.
- Never print, quote or paste a full secret value (keys, tokens, passwords, cookies, JWTs).
  Scripts redact values; keep it that way when summarising. Read tokens from stdin or files,
  never put them on a command line.
- Run only the read-only commands and scripts a workflow lists without asking. Commands that
  use the network (`npm audit`, `pip-audit`, `curl`) run only against targets the user named.
- Before changing code, rotating or revoking credentials, rewriting git history, contacting
  people or changing provider accounts: show the exact steps and wait for explicit confirmation.
- HAR files and audit outputs may contain sensitive data; do not paste them into the chat and
  remind the user to delete them afterwards.

## Working on this repository

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python tools/validate_skills.py   # frontmatter, sections, links, marketplace listing
ruff check . && ruff format --check .
pytest
```

- Scripts: Python 3.8+ standard library only, `#!/usr/bin/env python3`, `argparse` with
  `--help`, `--json` where output is structured, exit 0/1/2 (ok / findings / error), no network.
- Every script needs tests in `tests/test_<skill_with_underscores>.py` with fixtures in
  `tests/fixtures/<skill>/`. Never commit realistic secrets: assemble token-shaped strings at
  test time (see `tests/test_secrets_scan.py`) and use `example.com` and obviously fake values.
- Keep each `SKILL.md` under 400 lines; move detail to `references/`.
- A new skill must be added to `.claude-plugin/marketplace.json` (`plugins[0].skills`), the
  README table, the table above, the bug report template and `CHANGELOG.md`. The validator
  enforces the manifest.
