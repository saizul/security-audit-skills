---
name: owasp-web-review
description: Structured security code review of your own web application against the OWASP Top 10 (2025, with the 2021 mapping) - broken access control and IDOR, security misconfiguration, software supply chain, cryptographic failures, injection, insecure design, authentication failures, integrity failures, logging and alerting, and mishandled exceptional conditions. Maps every category to concrete files to open, grep starting points, questions to answer and fixes, and produces a findings table with severity and evidence. Use when the user asks for a security review or audit of a web app, API or pull request, "check my code for OWASP Top 10 issues", a pre-launch or pentest-prep review, or wants to know what security bugs a codebase likely has.
license: MIT
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# OWASP Top 10 web review

A repeatable, evidence-based review of code the user owns. Findings must point at a file and
line and explain how untrusted input reaches the problem; no speculative lists.
Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

This skill is for defensive review. Describe impact and fixes; do not write exploit payloads,
attack scripts or instructions for attacking systems the user does not own.

## When to use

- "Do a security review of this app / API / PR", "check for OWASP Top 10 issues"
- Before launch, before a pentest, after a security incident in a similar app
- Reviewing a new feature touching auth, file upload, payments, admin, multi-tenant data

## When not to use

- Only secrets (`secrets-scan`), only dependencies (`dependency-audit`), only headers
  (`security-headers-check`) or only cookies/JWT (`auth-session-review`) - use those directly;
  this skill calls them as sub-steps.
- Designing a system that does not exist yet: start with `threat-modeling`.
- Dynamic testing of a live site you do not own - not in scope.

## Workflow

1. **Map the application** (10 minutes, read-only). Identify: framework and language, entry
   points (routes/controllers/handlers, GraphQL resolvers, queue consumers, webhooks, CLI),
   authentication mechanism, authorization model (roles, tenants, ownership), data stores,
   outbound calls, file handling, admin features. Write this down as a short inventory; it
   decides which checks matter.
2. **Run the fast automated passes** and keep their output for evidence:
   ```bash
   python3 ../secrets-scan/scripts/secrets_scan.py . --json > secrets.json
   python3 ../input-validation-review/scripts/risky_patterns.py src/ --json > sinks.json
   ```
   Plus the dependency audit (`dependency-audit`) and, if a URL or HAR is available, headers
   and cookies (`security-headers-check`, `auth-session-review`). When skills are installed
   individually, these sibling paths may differ; locate the scripts by skill name.
3. **Walk the Top 10** in the order below, using the per-category checklist in
   [references/top10-2025.md](references/top10-2025.md). Spend the most time on A01 and A05 for
   typical CRUD apps. For each category: open the files the checklist names, answer its
   questions, and record a finding only with evidence (file:line, the input source, the sink,
   why existing controls do not stop it).
   1. A01 Broken Access Control (incl. SSRF)
   2. A05 Injection (incl. XSS)
   3. A07 Authentication Failures
   4. A02 Security Misconfiguration
   5. A04 Cryptographic Failures
   6. A03 Software Supply Chain Failures
   7. A08 Software or Data Integrity Failures
   8. A10 Mishandling of Exceptional Conditions
   9. A09 Security Logging and Alerting Failures
   10. A06 Insecure Design (business logic, abuse cases, rate limits)
4. **Rate each finding**: High = exploitable remotely by an unauthenticated or low-privileged
   user with real impact (data of other users, account takeover, code execution); Medium =
   needs preconditions or limited impact; Low = defence in depth; Info = observation.
   Set confidence: confirmed (traced end to end) or needs verification.
5. **Propose fixes** as minimal diffs in the project's own style, using the framework's built-in
   protection first (ORM parameters, template auto-escaping, policy/guard objects, CSRF
   middleware). Apply code changes only when the user asks.
6. **Report** using the format below. If the user uses 2021 category names (for example in a
   compliance document), translate with [references/mapping-2021-2025.md](references/mapping-2021-2025.md).

## Output

```
## Security review: shop-api (commit a1b2c3d)
Scope: src/ (Express 4, Postgres via knex), JWT auth, S3 uploads. Not covered: infra, mobile app.

| # | Sev | OWASP | Finding | Evidence | Fix |
| 1 | High | A01 | Any user can read any order (IDOR) | src/routes/orders.js:42 uses req.params.id without owner check | scope query by req.user.id; add test |
| 2 | High | A05 | SQL injection in search | src/db/search.js:17 knex.raw with template literal | use bindings: knex.raw('... ?', [q]) |
| 3 | Med  | A07 | No login rate limit | src/routes/auth.js:10 | add per-IP and per-account limits |

Automated passes: secrets 0, dependency P1 2 (see appendix), headers grade C.
Top 3 to fix first: #1, #2, dependency P1.
```

Keep the table to real findings; list "checked, no issue" categories in one line each so the
user can see coverage.
