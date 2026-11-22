---
name: secrets-scan
description: Scan your own repository or files for hardcoded secrets - AWS, GitHub, GitLab, Slack, Stripe, Google, npm, SendGrid and LLM API keys, private key blocks, JWTs, passwords in URLs and high-entropy values assigned to password/token/api_key names - plus sensitive files such as .env, id_rsa, *.pem and terraform.tfstate. Output is always redacted (prefix, length, fingerprint), supports a baseline and inline allow markers, and ends with a rotation plan for anything real. Use when the user asks to check a repo for leaked secrets or credentials before pushing or open-sourcing, mentions "API key in git", "did I commit my .env", GitHub push protection or secret scanning alerts, or wants a pre-commit / CI secret check.
license: MIT
compatibility: Python 3.8+ standard library. Optional for git history - gitleaks or trufflehog if installed.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Secrets scan

Find credentials in the working tree, never display them, and get real ones rotated.
Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

**Safety rules for this skill**

- Never print, quote, paste or summarise a full secret value - not even "to confirm". Refer to
  findings by file, line, rule and the redacted prefix the script prints.
- Do not `cat`, `grep` or open a flagged file in a way that echoes the secret into the chat.
  If you must inspect context, read only neighbouring lines, or ask the user to look.
- Do not test whether a key works by calling the provider API. Treat every match as live until
  the owner says otherwise.

## When to use

- "Scan this repo for secrets / API keys / passwords before I push or make it public"
- "Did I commit my .env?", "GitHub says it found a secret", "push protection blocked my push"
- Setting up a pre-commit hook or CI job that blocks secrets
- After a contractor leaves or a laptop is lost: what credentials live in our code?

## When not to use

- A secret is already confirmed leaked publicly: start with `incident-response-playbook`
  (rotate first, investigate second) and use this skill afterwards to find other copies.
- Scanning repositories or systems the user does not own or is not authorised to audit.
- Dependency vulnerabilities (`dependency-audit`) or secrets inside Docker images
  (`dockerfile-security` covers ENV/ARG and copied key files).

## Workflow

1. **Scope it.** Confirm the directory and whether the repo is (or will become) public. Note
   test fixtures that intentionally contain fake keys so they can be excluded.
2. **Scan the working tree (read-only).**
   ```bash
   python3 scripts/secrets_scan.py .
   python3 scripts/secrets_scan.py . --exclude 'tests/fixtures/*' --json > secrets.json
   ```
   Skips `.git`, `node_modules`, `vendor`, virtualenvs, build output, lockfiles, binaries and
   files over 1 MB. Exit 1 = findings at or above `--fail-on` (default `low`), 2 = bad input.
3. **Scan git history too** when the repo has a history (deleted files still leak). Prefer an
   installed scanner; do not install tools without asking:
   ```bash
   gitleaks git -v --redact .          # gitleaks 8.19+; older versions: gitleaks detect --redact
   git log --all --oneline -- '*.env' '*.pem' 'id_*'    # quick check for removed key files
   ```
   trufflehog can verify keys against providers, which sends them over the network - only with
   the user's explicit consent.
4. **Triage each finding** using the table below. A finding is a false positive only if the
   value is a placeholder, a published example, or a test fixture that never worked anywhere.
   Mark accepted false positives with a `secrets-scan:allow` comment on the line, or record
   them in a baseline:
   ```bash
   python3 scripts/secrets_scan.py . --write-baseline .secrets-baseline.json
   python3 scripts/secrets_scan.py . --baseline .secrets-baseline.json
   ```
   The baseline stores fingerprints only (truncated SHA-256 of rule + value), never values.
5. **Real secret found: rotate, then clean up.** Removing it from the code is not enough once it
   has been committed or pushed. Follow [references/rotation.md](references/rotation.md):
   revoke/rotate at the provider, deploy the new value from an environment variable or secret
   manager, check the provider's audit log, then decide whether history rewriting is worth it.
   Propose every rotation and history rewrite as exact steps and wait for the user to confirm.
6. **Prevent recurrence.** Offer the pre-commit and CI setup in
   [references/prevention.md](references/prevention.md) and make sure `.gitignore` covers
   `.env*` (but not `.env.example`), key files and Terraform state.

| Rule | Typical meaning | Action |
| --- | --- | --- |
| `private-key`, `aws-*`, `github-*`, `stripe-live-key`, provider tokens | real credential format | rotate unless clearly fake |
| `generic-secret` | high-entropy literal assigned to a secret-like name | ask the owner; move to env/secret store |
| `url-credentials` | `scheme://user:password@host` | rotate DB/service password; use env vars |
| `jwt` | token in code or logs | usually a test token; check expiry and where it came from |
| `stripe-test-key` (low) | test-mode key | still move to env; rotate if repo is public |
| `sensitive-file` | `.env`, keys, tfstate present | `git rm --cached`, add to `.gitignore`, rotate contents |

## Output

```
secrets scan: 214 files, 3 high, 1 medium, 0 low, 0 info (values redacted)
HIGH   src/config.py:12  aws-access-key-id  AKIA******** (len 20)  fp=3f9c0a...
HIGH   deploy/id_rsa  sensitive-file  SSH private key
MEDIUM docker-compose.yml:31  url-credentials  Tr0u******** (len 14)

Real credentials: 2 (AWS key in src/config.py, SSH key in deploy/). Both were committed in
a1b2c3d (2026-10-02) and pushed to origin -> treat as exposed.
Plan (needs your confirmation): 1) deactivate the AWS key and create a new one ...
False positives: 1 (fixture in tests/, added to baseline).
```

Always end with: what is real, what was already pushed, the rotation plan, and the prevention step.
