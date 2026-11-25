---
name: auth-session-review
description: Review authentication and session handling in your own web app - password hashing (Argon2id, scrypt, bcrypt, PBKDF2 parameters), login throttling, password reset and MFA flows, session fixation and logout, cookie flags (Secure, HttpOnly, SameSite, __Host- prefix, lifetime) checked from a HAR file or curl headers, and JWT pitfalls (alg none, HS256 secrets, missing exp/aud, long lifetimes, sensitive claims, jku/jwk headers) checked offline without printing the token. Use when the user asks to review login, signup, password reset, sessions, cookies, "is my JWT setup secure", remember-me, OAuth/OIDC callback handling, or wants to check Set-Cookie headers.
license: MIT
compatibility: Python 3.8+ standard library.
metadata:
  author: Saizul Amin
  version: "0.1.0"
---

# Authentication and session review

Paths below are relative to this skill's folder (in Claude Code: `${CLAUDE_SKILL_DIR}`).

**Safety rules**: never ask the user to paste a real password, session cookie or production
token into the chat. HAR files contain cookies and tokens - only run the scripts on them (they
print names and flags, never values) and remind the user to delete or sanitise the HAR afterwards.
Use a test account on a non-production environment where possible.

## When to use

- "Review our login / signup / password reset / remember-me implementation"
- "Are our session cookies set correctly?", "is our JWT implementation secure?"
- Migrating password hashing, adding MFA, adding OAuth/OIDC login
- Findings from `owasp-web-review` in A07 (authentication) or A01 (session/authorization)

## When not to use

- Generic header grading (HSTS, CSP): `security-headers-check`
- Leaked credentials: `secrets-scan` / `incident-response-playbook`
- Attacking or testing third-party login systems - out of scope

## Workflow

1. **Locate the auth code.** Login/signup/reset controllers, password hashing calls, session
   middleware config, JWT issue/verify code, OAuth callback, MFA enrolment. Note the framework
   and whether it uses built-in auth (Django auth, Devise, Laravel Fortify/Breeze, Spring
   Security, ASP.NET Identity, Passport/Auth.js) - prefer fixing configuration over custom code.
2. **Walk the checklist** in [references/checklist.md](references/checklist.md): password
   storage, login throttling and enumeration, reset tokens, MFA, session lifecycle, JWT,
   OAuth/OIDC. Record findings with file:line evidence.
3. **Check cookies as the browser sees them.** Capture a HAR of login + one authenticated page
   (DevTools > Network > Export HAR) or headers with curl, then:
   ```bash
   python3 scripts/cookie_check.py login.har
   curl -sI https://staging.example.com/login | python3 scripts/cookie_check.py - --url https://staging.example.com/login
   python3 scripts/cookie_check.py login.har --json --fail-on high
   ```
   Session-like names (session, sid, auth, token, remember, PHPSESSID, JSESSIONID, connect.sid,
   laravel_session ...) get stricter checks. CSRF cookies are allowed to be readable by JavaScript.
4. **Lint a JWT** issued by the app (a test token, ideally already expired). Pipe it in - never
   pass it as a command-line argument:
   ```bash
   pbpaste | python3 scripts/jwt_lint.py               # macOS clipboard
   python3 scripts/jwt_lint.py --file token.txt --json --max-hours 1
   ```
   It decodes without verifying and prints only alg/typ/kid, iss/aud/time claims and the names
   of other claims. It also flags `iat`/`nbf` in the future beyond `--leeway` seconds (issuer
   clock skew, default 300) and `exp` at or before `iat`/`nbf` (often milliseconds vs seconds).
   Then read the **verification** code: the algorithm must be pinned, the key
   must come from server config (never from the token's `jku`/`jwk`/`x5u`), `exp`, `nbf`, `iss`
   and `aud` must be checked, and `alg: none` must be rejected.
5. **Prioritise**: account takeover paths first (reset flaws, missing throttling, session
   fixation, JWT verification bugs), then cookie flags, then hardening.
6. **Propose fixes** in the framework's idiom (config snippets in checklist.md). Changing the
   hashing algorithm needs a migration plan: rehash on next successful login, never ask users
   to reset unless hashes leaked.

## Output

```
cookie check: 4 cookie(s): PHPSESSID, csrftoken, remember_me, tracking (values not shown)
HIGH   PHPSESSID  httponly: session-like cookie without HttpOnly is readable by JavaScript
HIGH   PHPSESSID  secure: missing Secure
MEDIUM remember_me  lifetime: session-like cookie lives 365 days

## Auth review findings
| Sev | Area | Finding | Evidence | Fix |
| High | Reset | reset token is 6 digits, no expiry | app/Http/ResetController.php:33 | 32-byte random token, 30 min expiry, single use |
| High | Session | session id not regenerated after login | app/login.php:58 | session_regenerate_id(true) |
| Med | JWT | access token lifetime 30 days, no aud | jwt_lint output | 15 min access + rotating refresh token; set aud |
```
