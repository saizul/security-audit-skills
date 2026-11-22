# Preventing secret leaks

## .gitignore baseline

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
id_rsa*
id_ed25519*
*.tfstate
*.tfstate.*
.terraform/
credentials.json
service-account*.json
```

If a file was already committed, ignoring it is not enough: `git rm --cached .env`, commit, and
rotate its contents (see rotation.md).

## Pre-commit hook

With the [pre-commit](https://pre-commit.com) framework, run this skill's script on staged files:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secrets-scan
        name: secrets-scan
        entry: python3 path/to/secrets_scan.py --fail-on medium
        language: system
        pass_filenames: true
```

Or a plain git hook (`.git/hooks/pre-commit`, executable):

```sh
#!/bin/sh
files=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$files" ] && exit 0
exec python3 path/to/secrets_scan.py --fail-on medium $files
```

gitleaks also ships a pre-commit hook (`gitleaks git --pre-commit --staged` in recent versions).

## CI

```yaml
# GitHub Actions step
- name: Secret scan
  run: python3 path/to/secrets_scan.py . --exclude 'tests/fixtures/*' --fail-on medium
```

Also enable the hosting platform's own protection where available (for example GitHub secret
scanning and push protection), which checks provider-verified patterns server-side.

## Keep secrets out of code by design

- Read secrets from environment variables or a secret manager at runtime; commit only
  `.env.example` with placeholder values.
- Use short-lived credentials (OIDC from CI to the cloud, IAM roles, workload identity)
  instead of long-lived keys.
- Scope every key to the minimum permissions and set expiries.
- Never log request headers, full URLs with tokens, or config objects.
- Test fixtures: use obviously fake values (`not-a-real-password`), assemble token-shaped
  strings at test time, and mark unavoidable ones with `secrets-scan:allow` / `gitleaks:allow`.
