## What does this pull request do?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type

- [ ] New skill
- [ ] New check or option in an existing script
- [ ] Workflow / reference improvement
- [ ] Bug fix
- [ ] Repository tooling (validator, CI)

## Checklist

- [ ] `python tools/validate_skills.py` passes
- [ ] `ruff check . && ruff format --check .` passes
- [ ] `pytest` passes; new script behaviour has tests with fixtures in `tests/fixtures/<skill>/`
- [ ] Scripts use only the Python standard library (or POSIX shell), support `--help`, have a
      `--json` option where output is structured, and exit non-zero on findings
- [ ] Read-only by default; any change to code, accounts or infrastructure is proposed and needs
      confirmation in the SKILL.md workflow
- [ ] Strictly defensive: no exploit code, attack payloads or instructions against third-party systems
- [ ] Scripts never print secret values (names, prefixes and fingerprints only)
- [ ] No real secrets in fixtures: token-shaped strings are assembled at test time or marked
      `gitleaks:allow`; use example.com and obviously fake values
- [ ] New skills: listed in `.claude-plugin/marketplace.json`, the README skills table and CHANGELOG.md
