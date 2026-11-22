---
name: threat-modeling
description: Lightweight STRIDE threat modeling for a feature or system you are building - capture components, data stores, external actors, data flows and trust boundaries as a small JSON model, generate a STRIDE-per-element threat table (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) with likelihood, impact, risk and mitigations, then refine it with the team into tracked actions. Use when the user asks for a threat model, STRIDE analysis, security design review, "what could go wrong with this architecture", abuse cases for a new feature, or security requirements before building something.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Threat modeling (STRIDE)

Answer four questions: what are we building, what can go wrong, what are we going to do about
it, and did we do a good job. The script handles the mechanical part (every element gets the
applicable STRIDE categories, model facts raise risk); the value comes from reviewing the table
with someone who knows the system.
Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "Threat model this feature / service / architecture", "do a STRIDE analysis"
- A design doc or pull request introduces a new trust boundary: public API, webhook, file
  upload, third-party integration, admin tool, multi-tenant data, payments
- Preparing security requirements or test cases before implementation

## When not to use

- Reviewing existing code for bugs: `owasp-web-review` (it may suggest a threat model for
  risky features)
- Compliance risk registers or organisation-wide risk assessments (different granularity)
- Threat modeling systems you do not own or have no permission to assess

## Workflow

1. **Scope one thing.** A feature, a service or a user journey - not "the whole company". Ask
   for (or read) the design doc, architecture diagram, API routes and infrastructure files.
2. **Write the model** as JSON, starting from
   [assets/model-template.json](assets/model-template.json). Rules of thumb:
   - `external`: people and systems you do not control (browser, mobile app, payment provider).
   - `process`: code you run (API, worker, lambda, cron job). Mark `internet_facing: true`.
   - `store`: databases, caches, buckets, queues at rest, log stores. List sensitive `data`
     (`pii`, `credentials`, `payment`, `health`, `secrets`, `tokens`, `keys`, `financial`) and
     `encrypted_at_rest`.
   - `flows`: who sends data to whom, with `protocol`, `authenticated` and `data`.
   - `zone`: give elements in different trust levels different zones (`internet`, `dmz`,
     `internal`, `third-party`, `admin`). A flow between zones crosses a trust boundary.
   Show the model to the user and confirm it matches reality before generating threats.
3. **Generate the table.**
   ```bash
   python3 scripts/stride.py model.json > THREATS.md
   python3 scripts/stride.py model.json --format csv > threats.csv     # for a spreadsheet/tracker
   python3 scripts/stride.py model.json --format json --min-risk Medium
   ```
   Exit 2 = invalid model (unknown element id, bad type, duplicate id).
4. **Refine with judgment** using [references/stride-guide.md](references/stride-guide.md):
   - Replace generic threats with specific ones ("any merchant can call /refunds for another
     merchant's order") and delete threats that truly do not apply - say why.
   - Add threats the template cannot know: business logic abuse, race conditions, insider and
     support-tool misuse, data retention, account recovery.
   - Adjust likelihood/impact (1-3) with the user; note existing controls.
5. **Decide per threat**: mitigate (name the control and owner), accept (with reason and
   review date), transfer, or eliminate (remove the feature/data). Turn mitigations into
   tickets or acceptance criteria and tests.
6. **Keep it alive.** Commit the model and table next to the code (for example
   `docs/threat-model/`), and re-run when a flow, store or boundary changes.

## Output

```
# Threat model: Example shop
40 candidate threats - High 10, Medium 30, Low 0 ...
| ID | Element | STRIDE | Threat | Mitigation | L | I | Risk | Status |
| T01 | Payment webhook (Payment provider -> Web/API) | Spoofing | Requests ... without authentication ... | Require authentication ... | 3 | 3 | High | open |
```

Follow the table with: the top 5 risks in plain language, decisions taken (mitigate/accept),
open questions for the team, and what was out of scope.
