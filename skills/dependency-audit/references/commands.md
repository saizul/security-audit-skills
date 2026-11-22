# Producing audit JSON

All of these read lockfiles/environments and query an advisory database (network). None of
them modify the project unless you add a "fix" option.

## Node.js

| Tool | Command | Notes |
| --- | --- | --- |
| npm 7+ | `npm audit --json > npm-audit.json` | Supported directly. `--omit=dev` audits production deps only. |
| npm 6 | `npm audit --json` | Legacy `advisories` format, also supported. |
| pnpm | `pnpm audit --json` | Output resembles the legacy npm format; check it parses, otherwise read it manually. |
| Yarn 1 | `yarn audit --json` | Line-delimited JSON (not supported by the script). |
| Yarn 2+ | `yarn npm audit --json` | Different shape (not supported by the script). |

Fix commands: `npm audit fix` (semver-compatible only), `npm install pkg@version`, and for a
transitive package that its parent has not fixed yet, `overrides` in package.json:

```json
{ "overrides": { "vulnerable-pkg": "^2.1.0" } }
```

Run `npm install` and the test suite after adding an override.

## Python

```bash
pip install pip-audit                                     # in a dev virtualenv
pip-audit -f json -o pip-audit.json                       # audit the current environment
pip-audit -r requirements.txt -f json -o pip-audit.json   # audit a requirements file
```

For Poetry or uv, export requirements first (`poetry export -f requirements.txt`,
`uv export --format requirements-txt`) and audit the file. pip-audit reports fix versions but no
severity; look IDs up on https://osv.dev.

Fix: bump the pin in requirements / pyproject, regenerate the lock, run tests.

## PHP

```bash
composer audit --format=json > composer-audit.json          # installed packages
composer audit --format=json --locked > composer-audit.json  # from composer.lock only
```

Abandoned packages are reported under `abandoned`, with a suggested replacement when known.
Fix: `composer update vendor/package --with-all-dependencies`, or raise the constraint in
composer.json.

## CI gate (GitHub Actions example)

```yaml
- run: npm ci
- run: npm audit --json > npm-audit.json || true
- run: python3 path/to/audit_report.py npm-audit.json --fail-on high
```

Keep the gate at `high` or `critical`; lower thresholds tend to get disabled.
