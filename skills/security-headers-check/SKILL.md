---
name: security-headers-check
description: Grade the HTTP security headers of your own site or API from a HAR file or curl -I output, offline - HSTS, Content-Security-Policy quality (unsafe-inline, unsafe-eval, wildcards, object-src, base-uri, frame-ancestors, report-only), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, version-leaking Server/X-Powered-By, permissive CORS and legacy X-XSS-Protection - with an A-F grade and copy-paste fixes for nginx, Apache, Express, Django, Laravel and Next.js. Use when the user asks to check or improve security headers, add a CSP, fix a securityheaders.com or Mozilla Observatory grade, harden a site before launch, or review CORS headers.
license: MIT
compatibility: Python 3.8+ standard library. curl to capture headers (the script itself makes no network calls).
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Security headers check

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

## When to use

- "Check the security headers of my site", "what headers am I missing?"
- "Help me add a Content-Security-Policy without breaking the site"
- A scanner or pentest report flagged HSTS/CSP/clickjacking/CORS
- Before launch, after moving to a new host/CDN/proxy

## When not to use

- Cookie flags and sessions: `auth-session-review` (its script reads the same HAR)
- TLS certificates and protocol versions: use a TLS checker (for example testssl.sh or an
  `ssl-tls-check` skill)
- Sites the user does not own or operate

## Workflow

1. **Capture headers** from the user's own site. Only fetch URLs the user names:
   ```bash
   curl -sIL https://www.example.com/ > headers.txt          # follows redirects
   curl -sI -X GET https://www.example.com/app > app.txt     # some apps answer HEAD differently
   ```
   Or export a HAR from the browser (DevTools > Network > Export HAR), which covers every page
   and API response loaded. HARs contain cookies; do not paste them into chat.
2. **Grade (offline, read-only).**
   ```bash
   python3 scripts/headers_grade.py headers.txt
   python3 scripts/headers_grade.py site.har                    # HTML documents only
   python3 scripts/headers_grade.py site.har --all --url /api/  # API responses too
   python3 scripts/headers_grade.py headers.txt --json --min-grade A
   ```
   With redirects the last response is graded (`--all` for each hop). Raw headers are treated
   as HTTPS unless `--http`. Exit 1 = a response below `--min-grade` (default B).
3. **Interpret.** HSTS, clickjacking protection, CSP and CORS matter most. Info items
   (Permissions-Policy, COOP) are hardening. API-only JSON responses need fewer headers
   (nosniff, CORS, cache control); CSP matters for HTML.
4. **Write the fix** for the user's stack from
   [references/recommended-headers.md](references/recommended-headers.md). Find where headers
   are set today (web server, CDN, framework middleware) and change them in one place; nginx
   `add_header` in a `location` block drops headers inherited from `server`.
5. **Roll out CSP safely**: send `Content-Security-Policy-Report-Only` first, watch the browser
   console or a report endpoint, fix violations (move inline scripts to files or add nonces),
   then enforce. HSTS: start with a short `max-age`, raise to one year, add `preload` only when
   every subdomain is HTTPS-only for good.
6. **Re-capture and re-grade** after deployment; show before/after grades.

## Output

```
F (10/100)  response (HTTP 200)
  HIGH   strict-transport-security: missing HSTS
  HIGH   access-control-allow-origin: wildcard origin with credentials
  MEDIUM content-security-policy: missing Content-Security-Policy
  ...
Proposed nginx snippet (server block, with `always`): ...
After deploy: A (100/100)
```
