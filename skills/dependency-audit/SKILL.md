---
name: dependency-audit
description: Run or read npm audit, pip-audit and composer audit JSON and turn it into one prioritized fix plan - P1 fix now (critical/high with a fix), P2 this sprint, P3 track - with direct vs transitive packages, semver-major warnings, abandoned Composer packages and the exact upgrade command per package. Includes triage guidance on reachability, overrides and when an advisory does not apply. Use when the user asks to fix npm audit / Dependabot / pip-audit / composer audit warnings, "which vulnerable dependencies matter", wants a dependency security report for a Node, Python or PHP project, or a CI gate on known-vulnerable packages.
license: MIT
compatibility: Python 3.8+ standard library. Producing the input needs npm, pip-audit (pip install pip-audit) or Composer 2.4+, which query their advisory databases over the network.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Dependency audit

Turn noisy audit output into a short, ordered list of upgrades the user can actually ship.
Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "npm audit shows 47 vulnerabilities, what do I fix first?"
- Dependabot / GitHub security alerts, pip-audit or `composer audit` output to review
- A dependency security section for a release checklist or a CI gate
- After a widely reported package vulnerability: "are we affected?"

## When not to use

- Container image / OS package CVEs (use Trivy, Grype or Docker Scout on the image)
- A package that is actively malicious (typosquat, hijacked release): go to
  `incident-response-playbook` (malicious-dependency) - rotating secrets matters more than upgrading
- Licence compliance or SBOM generation (use dedicated SBOM tools)

## Workflow

1. **Detect the ecosystems** from lockfiles: `package-lock.json` / `npm-shrinkwrap.json` (npm),
   `requirements*.txt` / `poetry.lock` / `uv.lock` / `Pipfile.lock` (Python), `composer.lock` (PHP).
   For yarn/pnpm, Poetry and others see [references/commands.md](references/commands.md).
2. **Produce JSON** (these read lockfiles and query advisory databases; they do not change the
   project). Ask before running them if the user has not, since they use the network:
   ```bash
   npm audit --json > npm-audit.json            # exit code is non-zero when vulns exist; that's fine
   pip-audit -r requirements.txt -f json -o pip-audit.json
   composer audit --format=json --locked > composer-audit.json
   ```
3. **Build the plan (read-only).**
   ```bash
   python3 scripts/audit_report.py npm-audit.json pip-audit.json composer-audit.json
   python3 scripts/audit_report.py npm-audit.json --json --fail-on critical
   ```
   Exit 1 = a finding at or above `--fail-on` (default `high`); `--fail-on any` for pip-audit,
   which reports no severity. Exit 2 = unreadable or unknown JSON.
4. **Triage before upgrading.** For each P1/P2 item decide with the user, using
   [references/triage.md](references/triage.md):
   - Is the vulnerable code reachable (server vs build-only/dev dependency, function used)?
   - Direct dependency (upgrade it) or transitive (upgrade the parent named in npm's `fixAvailable`,
     or pin with npm `overrides` / Composer constraint / pip constraint file)?
   - Semver-major fix: read the changelog; plan it as its own change with tests.
   - No fix: mitigate (input validation, config flag, WAF rule), replace the package, or accept
     with a written reason and review date.
   - pip-audit `unknown` severity: look up the ID on osv.dev and re-rank.
5. **Propose the change set** as exact commands grouped by priority, smallest safe step first
   (`npm audit fix` without `--force`; never `npm audit fix --force` without showing what majors it
   pulls). Run upgrades only after the user confirms; then run the tests and re-run the audit to
   prove the count went down.
6. **Gate CI** if asked: the audit command plus `audit_report.py --fail-on high` (see commands.md).

## Output

```
dependency audit: 13 finding(s) - P1 5, P2 4, P3 4

== P1 fix now ==
- [critical] npm:example-parser (<2.1.0) direct
    Prototype pollution in example-parser
    fix: npm install example-parser@2.1.0
- [high] npm:example-template (<5.0.0) direct
    fix: npm install example-template@5.0.0   # semver-major upgrade: read the changelog and test
...
```

Then summarise for the user: what to run now (P1), what needs a ticket (P2 with owner), what was
accepted and why (P3 / not reachable), and the before/after audit counts.
