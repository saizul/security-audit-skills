---
name: input-validation-review
description: Find and fix injection-class bugs in your own code - SQL injection, OS command injection, XSS, SSRF, path traversal, open redirects, unsafe deserialization, eval and XXE - across Python, JavaScript/TypeScript, PHP, Go, Java/Kotlin, Ruby and HTML templates. A stdlib scanner lists the dangerous sinks with file:line and the safe replacement, then the workflow traces whether untrusted input reaches each one and proposes the fix with safe code examples per language. Use when the user asks to check code for SQL injection, XSS, command injection, SSRF or path traversal, review input validation or sanitization, harden a form/API/file upload/webhook handler, or fix a scanner finding in one of these categories.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Input validation review

Sinks are where bugs become exploitable; sources are where untrusted data enters. This skill
finds the sinks fast, then spends the reviewer's time on the data flow between them.
Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

Defensive scope: explain the risk and the fix. Do not produce working attack payloads or
exploitation steps; to prove a fix, write a unit test that sends a harmless marker value
(for example a quote character or `../` segment) and asserts it is handled safely.

## When to use

- "Is this code vulnerable to SQL injection / XSS / command injection?"
- Reviewing handlers that take user input: forms, JSON APIs, query strings, headers, file
  uploads, webhooks, URL fetchers, import/export features
- Fixing a SAST/pentest finding in these categories
- The A05 (Injection) and SSRF parts of `owasp-web-review`

## When not to use

- Access control bugs (IDOR, missing auth) - `owasp-web-review` A01
- Secrets in code - `secrets-scan`; vulnerable libraries - `dependency-audit`
- Full SAST coverage: for CI use Semgrep or CodeQL as well; this scanner is a fast, dependency-free
  first pass with deliberately simple line-based rules

## Workflow

1. **List entry points**: routes/controllers, CLI args, message consumers, file parsers. Note
   which framework protections exist (ORM, template auto-escaping, validation library).
2. **Scan for sinks (read-only).**
   ```bash
   python3 scripts/risky_patterns.py src/
   python3 scripts/risky_patterns.py . --lang php --category sql-injection
   python3 scripts/risky_patterns.py . --json --fail-on none > sinks.json
   python3 scripts/risky_patterns.py --list-rules
   ```
   Categories: sql-injection, command-injection, code-injection, xss, ssrf, path-traversal,
   open-redirect, deserialization, xxe. Exit 1 = findings at or above `--fail-on` (default high).
3. **Trace each high/medium finding** from source to sink. A finding is real when data an
   attacker controls (request params, body, headers, cookies, uploaded file names/contents,
   webhook payloads, database values originally from users) reaches the sink without a
   control that is correct for that sink. Validation for a different context does not count
   (HTML escaping does not protect SQL). Record: source, path, sink, existing controls, verdict.
4. **Look for what the scanner cannot see**: second-order injection (stored, then used later),
   ORM raw fragments built in helpers, dynamic column/table names, template injection when user
   input becomes a template, header/CRLF injection, mass assignment, regex DoS on user input,
   zip/archive extraction paths.
5. **Fix with the safe pattern** for the language from
   [references/safe-patterns.md](references/safe-patterns.md). Prefer structural fixes
   (parameters, argument arrays, auto-escaping, allow-lists) over escaping or blocklists.
   Validate input at the boundary (type, length, format, allow-list) as an additional layer.
   Mark reviewed false positives with a `review:ok <reason>` comment on the line.
6. **Add a regression test** per fixed sink and re-run the scanner.

## Output

```
review points: 9 in 42 files (command-injection 1, sql-injection 3, ssrf 1, xss 4)
HIGH   src/routes/search.js:14  [sql-injection] js-sql-template
       db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`)
       safe: placeholders: db.query('... WHERE id = $1', [id]) ...

| # | Verdict | Category | Location | Source -> sink | Fix |
| 1 | vulnerable | SQLi | src/routes/search.js:14 | req.query.q -> db.query template | $1 placeholder + test |
| 2 | false positive | XSS | src/ui/Help.jsx:8 | constant markdown -> dangerouslySetInnerHTML | review:ok comment |
```
