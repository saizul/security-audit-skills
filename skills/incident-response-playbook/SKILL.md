---
name: incident-response-playbook
description: Guided first response for common developer security incidents - a leaked secret or API key (GitHub, AWS, Stripe, database, SSH), a compromised developer, admin or cloud account, and a malicious or hijacked dependency - with triage, contain, eradicate, recover and learn phases, provider-specific rotation steps, evidence preservation, communication templates and a Markdown incident record with a timestamped timeline and checklist tracker. Use when the user says they leaked or committed a key, got a GitHub secret scanning or provider abuse alert, sees suspicious logins or unknown resources, a package they use was reported malicious, or asks for an incident response plan, runbook or post-mortem template.
license: MIT
compatibility: Python 3.8+ standard library (only for the incident record helper).
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Incident response playbook

Calm, ordered first response for small teams. Contain first, investigate second, and write
everything down with timestamps. Paths below are relative to this skill's folder (in Claude
Code: `${CLAUDE_SKILL_DIR}`).

**Ground rules**

- Every action that changes a provider account, revokes access, deletes data or contacts
  people is proposed as an exact step and done by the user, or by you only after explicit
  confirmation. Many steps (password resets, MFA, revoking keys) must happen in provider
  consoles the user controls.
- Never ask for, print or store secret values. Refer to keys by type, last characters or ID.
- Preserve evidence before cleaning up: export logs, note commit SHAs and timestamps. Do not
  "fix" by deleting the attacker's artefacts before they are recorded.
- This skill covers defensive response for the user's own systems. For legal, regulatory or
  law-enforcement questions, tell the user to involve their legal/privacy contact.

## When to use

- "I accidentally pushed my AWS key / .env to GitHub", "GitHub emailed me about a secret"
- "Someone logged into our admin account", "unknown EC2 instances / OAuth apps / deploy keys"
- "Package X we depend on was compromised", "malicious postinstall script"
- "Write an incident response runbook / post-mortem template for our team"

## When not to use

- Routine secret hygiene with nothing leaked: `secrets-scan`
- Production outages without a security cause: use your ops runbooks
- Large breaches with legal exposure, ransomware or active intrusions on infrastructure: this
  playbook still helps with the first hour, but escalate to a professional incident response
  provider and legal counsel early

## Workflow

1. **Open a record** so nothing is lost:
   ```bash
   python3 scripts/incident_log.py new --type leaked-secret --title "AWS key pushed to public repo" --severity SEV1 --out incidents/
   python3 scripts/incident_log.py add incidents/incident-20261122-1015-aws-key-pushed-to-public-repo.md "key deactivated in IAM"
   python3 scripts/incident_log.py check incidents/incident-20261122-1015-aws-key-pushed-to-public-repo.md
   ```
   Types: `leaked-secret`, `compromised-account`, `malicious-dependency`, `other`. `check`
   exits 1 while checklist items are open. Times are UTC. The record must not contain secrets.
2. **Triage (minutes).** What leaked or who is affected, since when, where (public or private),
   what it can access. Severity: SEV1 = public exposure or production/admin access or active
   misuse; SEV2 = limited scope or private exposure; SEV3 = no realistic access. Name one
   incident lead.
3. **Contain** using the matching playbook in [references/playbooks.md](references/playbooks.md):
   - leaked secret: rotate/revoke at the provider first, then deploy the new value
   - compromised account: reset credentials, revoke sessions/tokens, enforce MFA
   - malicious dependency: pin/remove, rotate every secret the install environment could read
4. **Eradicate**: review audit logs for the exposure window, remove persistence (new keys,
   users, OAuth apps, webhooks, forwarding rules, deploy keys, cron jobs), fix the root cause.
5. **Recover**: restore known-good state, monitor closely, confirm with the provider that usage
   is back to normal.
6. **Communicate** with the templates in [references/communication.md](references/communication.md):
   internal status updates, customer notice if their data or service was affected, and
   regulator notification if personal data was breached (in the EU/UK under GDPR the
   supervisory authority generally within 72 hours of becoming aware - confirm with legal).
7. **Learn**: blameless post-incident review within a week (template in communication.md);
   turn follow-ups into tracked tasks (for example secret scanning in CI, MFA everywhere,
   short-lived credentials).

## Output

```
Incident record: incidents/incident-20261122-1015-aws-key-pushed-to-public-repo.md (SEV1)

Do now (you, in the AWS console):
1. IAM > Users > ci-deploy > Security credentials > deactivate key ending ...XYZ1
2. Create a replacement key; update the GitHub Actions secret AWS_ACCESS_KEY_ID/SECRET
3. CloudTrail: filter by access key ID from 2026-11-22T09:40Z (first push) until now
Next: review findings, then delete the old key; decide on history rewrite.
Checklist: Triage 3/3, Contain 1/3, Eradicate 0/3 ...
```
