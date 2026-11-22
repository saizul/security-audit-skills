# Contributing to security-audit-skills

Thank you for helping! New rules, new skills, false-positive fixes, redacted real-world
fixtures and clearer docs are all welcome.

- [Ground rules](#ground-rules)
- [Ways to contribute](#ways-to-contribute)
- [Good first issues](#good-first-issues)
- [Development setup](#development-setup)
- [Repository layout](#repository-layout)
- [Write a new skill](#write-a-new-skill)
- [Quality bar](#quality-bar)
- [Pull request process](#pull-request-process)

## Ground rules

- **Defensive only.** Skills help people review and fix their own code and systems. Pull
  requests that add exploit code, attack payloads, credential harvesting, scanning of
  third-party targets or evasion techniques will be closed.
- **Never leak secrets.** Scripts print names, prefixes, lengths or fingerprints, never full
  values. Do not commit real secrets, tokens, HAR files or private code, not even revoked ones.
- **Ask before acting.** Workflows must propose any change (code, accounts, git history) and wait
  for the user's confirmation.

## Ways to contribute

| Size | Idea |
| --- | --- |
| 10 minutes | Fix a typo, clarify a workflow step, add a FAQ entry |
| 30 minutes | Add a test case for a false positive or false negative you hit |
| 1-2 hours | Add a rule to an existing script (see below) |
| Half a day | Write a new skill from the template |

Comment on an issue before you start so nobody else picks the same one.

## Good first issues

Each of these is self-contained and touches one script and its test file.

1. **secrets-scan: more providers.** Add rules for Twilio, Mailgun, Shopify and Azure storage
   connection strings, with test-time assembled fake tokens and a placeholder that must not match.
2. **secrets-scan: `--staged` mode.** Scan only files from `git diff --cached --name-only`
   (via `subprocess` with an argument list) for fast pre-commit use.
3. **dependency-audit: Yarn 1 support.** Parse `yarn audit --json` (one JSON object per line,
   `auditAdvisory` records) into the same `Vuln` structure.
4. **dependency-audit: Markdown output.** Add `--format md` that prints the plan as a table for
   pull request comments.
5. **security-headers-check: `Cache-Control` on authenticated pages.** Report `low` when a
   response sets a session cookie but has no `Cache-Control: no-store`/`private`.
6. **security-headers-check: CSP `form-action` and `upgrade-insecure-requests`.** Report `info`
   when missing and explain the trade-offs in the reference.
7. **auth-session-review: cookie size and count.** Report `info` for cookies over 4 KB and
   more than 20 cookies per host (browser limits).
8. **input-validation-review: C# rules.** Add `.cs` support: `SqlCommand` with string
   concatenation, `Process.Start` with `UseShellExecute`, `BinaryFormatter`, `Html.Raw`.
9. **dockerfile-security: `apt-get` hygiene.** Report `info` for `apt-get install` without
   `--no-install-recommends` and missing `rm -rf /var/lib/apt/lists/*` in the same `RUN`.
10. **threat-modeling: Mermaid output.** Add `--format mermaid` that draws the data-flow diagram
    with trust zones as subgraphs.
11. **incident-response-playbook: `export` command.** Render the record's timeline as a
    Markdown table for the post-incident review.
12. **New skill: `github-actions-security`** (see the roadmap in the README).

## Development setup

```bash
git clone https://github.com/saizul/security-audit-skills.git
cd security-audit-skills
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

python tools/validate_skills.py   # SKILL.md frontmatter, sections, links, marketplace listing
ruff check . && ruff format --check .
pytest
```

To try your changes in Claude Code, either copy a skill to `~/.claude/skills/` or add your
checkout as a local marketplace:

```bash
claude plugin marketplace add ./security-audit-skills
claude plugin install security-audit-skills@security-audit-skills
```

For Codex, copy the skill folder to `~/.agents/skills/`.

If you have gitleaks installed, run `gitleaks dir .` (or `gitleaks detect --no-git` on older
versions) before opening a pull request; it should report nothing.

## Repository layout

```
.claude-plugin/
  marketplace.json      marketplace + plugin entry listing every skill
  plugin.json           plugin manifest (name, version, author)
skills/<name>/
  SKILL.md              frontmatter + workflow (the part agents read)
  scripts/*.py          standalone helpers, Python 3.8+ stdlib only
  references/*.md       detail loaded on demand
  assets/               templates used by the workflow
templates/skill/        copy this to start a new skill
tests/
  test_<skill>.py       one test module per skill
  fixtures/<skill>/     inputs for those tests
tools/validate_skills.py
```

## Write a new skill

1. Open a "New skill proposal" issue first so we can agree on scope.
2. Copy the template:
   ```bash
   cp -r templates/skill skills/my-new-skill
   mv skills/my-new-skill/scripts/your_script.py skills/my-new-skill/scripts/my_check.py
   ```
3. Edit `SKILL.md`:
   - `name` equals the folder name: lowercase letters, digits, single hyphens, max 64 chars.
   - `description` (max 1024 chars) says **what** it does with concrete keywords and **when**
     to use it, starting the second part with "Use when ...". This text decides whether
     the agent picks the skill, so list the phrases users actually type.
   - Required sections: `## When to use`, `## When not to use`, `## Workflow`, `## Output`.
   - Workflow steps are imperative and numbered, with exact commands, decision points and
     the point where the agent must ask before changing anything.
   - Keep it under 400 lines; move checklists and code samples to `references/`.
4. Write the script: `argparse` with a useful `--help`, `--json` output, exit codes
   0 (ok) / 1 (findings) / 2 (error), read-only, no network, never print secret values.
5. Add `tests/test_my_new_skill.py` and fixtures in `tests/fixtures/my-new-skill/`. Cover
   a "bad" input, a "good" input that produces no findings, edge cases and the CLI exit codes.
   Assemble any token-shaped test string from pieces at test time.
6. Add the skill to `.claude-plugin/marketplace.json` (`plugins[0].skills`), the README
   skills table, the table in `AGENTS.md`, the bug report template and `CHANGELOG.md` under
   "Unreleased".
7. Run the validator, ruff and pytest.

## Quality bar

- **Evidence over speculation.** Workflows ask for file:line evidence and a source-to-sink
  explanation before a finding is reported.
- **Deterministic where it matters.** If a step is "parse this and find X", write a script
  and test it rather than relying on the model reading a large file.
- **Low false positives.** A noisy rule gets ignored. Prefer a lower severity or an
  `info` level for heuristics, and document known false positives in the skill's references.
- **Accurate guidance.** Cite the source (OWASP cheat sheets, NIST, vendor docs) for parameters
  such as hashing costs, and keep version-specific advice dated.

## Pull request process

1. Fork, create a branch, make focused commits.
2. Make sure CI passes locally (validator, ruff, pytest).
3. Fill in the pull request template.
4. A maintainer reviews within a few days. Small, focused pull requests are merged fastest.

By contributing you agree that your contributions are licensed under the MIT License.
