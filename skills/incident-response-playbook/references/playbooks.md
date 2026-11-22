# Playbooks

Console paths change over time; confirm them in the provider's current documentation.
All provider-side actions are performed or approved by the user.

## A. Leaked secret

**Triage**
- Type, owner, permissions/scope, environments that use it.
- Exposure: where (public repo, private repo, CI log, issue, chat, screenshot, package),
  first exposure time (commit date + push time), whether forks/mirrors/caches exist.
- Public exposure of a cloud or payment key = SEV1 regardless of how quickly it was removed.

**Contain**
1. Rotate or revoke at the provider (see the table in the `secrets-scan` rotation guide).
   For keys you cannot rotate immediately, restrict them (IP allow-list, reduce scopes) first.
2. Deploy the replacement from a secret store/env var; restart consumers; verify.
3. Revoke the old value; verify it fails.

**Eradicate**
- Audit logs for the exposure window: AWS CloudTrail (by access key ID), GCP Cloud Audit Logs,
  Azure Activity Log, GitHub audit/security log, Stripe logs and events, database login logs.
- Look for persistence an attacker would create: new IAM users/keys/roles, new SSH keys,
  OAuth apps, webhooks, deploy keys, Lambda functions, compute instances in unused regions,
  changed DNS records, new payout destinations.
- Remove the secret from code; optionally rewrite history (after rotation; see secrets-scan).
- Search for other copies: `secrets-scan` over all repos, CI variables, container images
  (`docker history --no-trunc`), wikis.

**Recover / learn**
- Enable secret scanning + push protection, pre-commit hook, short-lived credentials (OIDC from
  CI), least-privilege keys with expiry.

## B. Compromised account (developer, admin, cloud, SaaS)

**Triage**
- Which account, what it can reach (repos, production, billing, customer data, email).
- Signals: sign-in logs (new country/ASN/device), MFA changes, new tokens, mail rules,
  unexpected commits or deployments.
- Preserve: export sign-in and audit logs now; note IDs of suspicious sessions and objects.

**Contain**
1. Reset the password (from a clean device) and sign out all sessions / revoke refresh tokens.
2. Revoke personal access tokens, API keys, app passwords, OAuth grants, SSH and GPG keys,
   and re-add only known-good ones.
3. Enforce MFA (prefer passkeys/security keys); remove unknown MFA devices and recovery options.
4. For admins: temporarily reduce privileges or use a break-glass account while investigating.
5. If the email account is affected, secure it first: password resets for everything else go there.

**Eradicate**
- Remove persistence: mail forwarding and filter rules, new users or role assignments, OAuth
  apps, webhooks, deploy keys, CI secrets, scheduled jobs, branch protection changes.
- Review changes during the window: commits (verify signatures), releases, packages published,
  infrastructure changes, payouts/billing changes, data exports.
- Check password reuse: any other account with the same password gets reset too.
- If a device was compromised (malware, infostealer), reimage it and treat every credential
  and browser session on it as leaked.

**Recover / learn**
- Restore changed resources from known-good state; monitor the account for 30 days.
- Phishing-resistant MFA for all admins, SSO with conditional access, alerts on new tokens.

## C. Malicious or hijacked dependency

**Triage**
- Package name, malicious versions, what the payload does (advisory, maintainer statement).
- Which repositories reference it (lockfiles: `npm ls pkg`, `pip show`, `composer why`) and
  where it was installed or executed: developer laptops, CI runners, build servers, production
  images, during which time window.
- Install-time payloads (`postinstall`, `setup.py`) run with the permissions of whoever
  installed the package: CI secrets and developer credentials are the usual target.

**Contain**
1. Pin to a known-good version or remove the package; regenerate lockfiles; block the bad
   version (npm `overrides`, constraints) so it cannot come back.
2. Rotate every secret available where it ran: CI/CD variables, cloud keys, registry tokens
   (npm/PyPI/Docker), GitHub tokens, SSH keys, `.env` files on affected laptops.
3. Isolate affected runners/machines; rebuild ephemeral runners; reimage developer machines if
   the payload was a stealer or backdoor.

**Eradicate**
- Rebuild and redeploy artifacts and images built during the window.
- Look for persistence the payload documents (startup items, cron, shell profile changes, SSH
  keys, browser extensions).
- Check whether your own packages were published from compromised credentials.

**Recover / learn**
- `npm ci` / `pip install --require-hashes` / `composer install` from lockfiles, a delay before
  adopting new versions, dependency review in pull requests, `--ignore-scripts` where feasible,
  minimal CI permissions and secrets scoped per job.

## Severity guide

| Level | Examples | Response |
| --- | --- | --- |
| SEV1 | public cloud/payment key, admin account takeover, malicious package ran in CI with secrets, data exfiltration seen | all hands, contain within the hour, leadership informed |
| SEV2 | private-repo leak of a scoped key, compromised non-admin account, malicious package only on one laptop | same day |
| SEV3 | expired/test credentials, blocked attempt, no access gained | track, fix root cause |
