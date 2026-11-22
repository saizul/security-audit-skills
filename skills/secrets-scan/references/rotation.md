# Rotating a leaked secret

Order matters: **contain first** (make the leaked value useless), then clean up. A secret that
reached a remote (GitHub, GitLab, a CI log, a ticket, a chat) must be treated as compromised
even if the repository is private or the commit was deleted minutes later. Automated scrapers
harvest public commits within minutes.

Every step that changes a provider account, deploys a new value or rewrites history is shown to
the user and done only after they confirm.

## Generic procedure

1. **Identify** the credential: provider, account/project, owner, what it can access.
2. **Create a replacement** (new key, new password) with the least privilege it actually needs.
3. **Deploy the replacement** to every consumer (env vars, secret manager, CI variables,
   servers), loaded at runtime - not committed.
4. **Revoke the old value** and confirm it is rejected.
5. **Review usage** of the old value in the provider's audit log from the first exposure time
   until revocation. Unexpected use = escalate to `incident-response-playbook`.
6. **Remove it from code** and, if worthwhile, from history (see below).

## Provider notes

Exact console paths change; check the provider's current documentation.

| Secret | Rotate | Check for misuse |
| --- | --- | --- |
| AWS access key (`AKIA...`) | IAM > user > Security credentials: create a new key, update consumers, deactivate the old key, then delete it. Prefer roles / IAM Identity Center over long-lived keys. | CloudTrail events filtered by the access key ID; billing for new regions/instances. AWS may attach a quarantine policy to keys it finds exposed. |
| GitHub token (`ghp_`, `github_pat_`, `gho_`) | Settings > Developer settings > Personal access tokens: revoke; create a fine-grained token with minimal repo scope and an expiry. For GitHub Apps rotate the private key. | Account/org security log; new deploy keys, webhooks, OAuth apps, collaborators. |
| GitLab token (`glpat-`) | User settings > Access tokens: revoke and recreate with expiry. | Audit events. |
| Slack token / webhook | Revoke the token or regenerate the webhook URL in the app config. | Workspace access logs. |
| Stripe key (`sk_live_`, `rk_live_`) | Dashboard > Developers > API keys: roll the key (you can set an expiry for the old one). Prefer restricted keys. | Logs and Events for unexpected API calls, refunds, payouts. |
| Google API key (`AIza`) | Cloud console > Credentials: regenerate or delete; add API and HTTP referrer/IP restrictions. | API metrics and billing. |
| npm token (`npm_`) | npmjs.com > Access Tokens: revoke; use granular tokens scoped to packages. | Package versions published since exposure. |
| OpenAI / Anthropic style keys (`sk-`, `sk-ant-`) | Provider console: delete the key, create a new one per environment. | Usage dashboard for unexpected spend. |
| Database password / URL credentials | Change the password for that DB user (create a new user if many apps share it), update apps, then remove the old credential. Restrict network access to the DB. | DB logs for logins from unknown IPs; unexpected data reads/exports. |
| SSH private key | Remove the public key from every `authorized_keys`, deploy key and Git host; generate a new key pair (ed25519) with a passphrase. | `last`, `auth.log`/`journalctl -u ssh`, Git host security log. |
| JWT signing secret / private key | Generate a new key, publish it (JWKS) or deploy it, stop accepting the old one; this logs everyone out. | Tokens with unusual `sub`/roles in logs. |
| `.env` / tfstate committed | Rotate **every** value in the file - assume all are exposed. | Per provider above. |

## Removing it from git history

Rotation makes the leaked value harmless; history rewriting only reduces noise and the chance
someone reuses an unrotated sibling secret. Rewriting is disruptive: every clone, fork and open
pull request keeps the old commits.

If the user decides to rewrite (after rotating):

```bash
# work on a fresh mirror clone; back it up first
git clone --mirror git@github.com:OWNER/REPO.git
cd REPO.git
git filter-repo --invert-paths --path path/to/.env          # remove a file everywhere
git filter-repo --replace-text ../replacements.txt          # or replace values (one per line)
git push --force --mirror                                    # only after explicit confirmation
```

`git filter-repo` is a separate tool (`pip install git-filter-repo` or a package manager).
Afterwards collaborators must re-clone, and hosted platforms may keep cached views of old
commits and pull requests - their support can purge those.

## Communicate

Tell the owners of affected systems what leaked, when, where, what was rotated and whether any
misuse was seen. Never include the secret itself in tickets or chat.
