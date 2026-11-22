# Authentication and session checklist

Parameters follow the OWASP Password Storage, Authentication and Session Management cheat
sheets and NIST SP 800-63B as of 2026. Check those sources when in doubt.

## 1. Password storage

| Algorithm | Minimum parameters | Notes |
| --- | --- | --- |
| Argon2id (preferred) | m=19 MiB, t=2, p=1 (or m=46 MiB, t=1) | `argon2-cffi`, PHP `PASSWORD_ARGON2ID`, libsodium |
| scrypt | N=2^17, r=8, p=1 | |
| bcrypt | cost >= 10 | input limited to 72 bytes; do not pre-hash with a fast hash without care |
| PBKDF2-HMAC-SHA256 | 600,000 iterations | FIPS environments |

- Never: MD5/SHA-x (even salted), reversible encryption, homemade schemes.
- Use the framework/library API (`password_hash`/`password_verify`, Django hashers,
  `bcrypt.hashpw`, Spring `DelegatingPasswordEncoder`) and constant-time verification.
- Upgrade path: on successful login, if the stored hash uses old parameters
  (`password_needs_rehash`, Django `must_update`), rehash with the new ones.
- Password rules: minimum 8 characters when MFA is enforced, 15 when the password is the only
  factor; allow at least 64 characters and all Unicode; check against a breached-password list;
  no composition rules or periodic forced changes.

## 2. Login

- Throttle per account and per IP (exponential backoff or temporary lock); CAPTCHA only as an
  escalation step.
- Same response and similar timing for "unknown user" and "wrong password" (also on signup and
  reset: "If an account exists, we sent an email").
- Log failures and alert on spikes (credential stuffing).
- Re-authenticate before sensitive actions (change email/password, disable MFA, payouts).

## 3. Password reset

- Token: >= 128 bits from a CSPRNG, stored hashed, single use, expires in 15-60 minutes,
  bound to the user, invalidated when used or when the password changes.
- Send the link to the address on file only; never trust a `Host` header to build the link
  (use a configured base URL).
- After reset: invalidate all sessions and refresh tokens, notify the user.
- Do not log reset URLs; set `Referrer-Policy: no-referrer` on the reset page.

## 4. MFA

- Offer WebAuthn/passkeys; TOTP as fallback; SMS only as a last resort.
- Rate-limit code entry; codes single use; recovery codes hashed and single use.
- Changing MFA settings requires re-authentication and sends a notification.

## 5. Sessions

- Session ID: framework-generated, >= 128 bits of entropy, stored server-side or as a signed
  and, if it holds data, encrypted cookie.
- Regenerate the ID at login and privilege change (prevents session fixation):
  PHP `session_regenerate_id(true)`, Django does it on `login()`, Express `req.session.regenerate`,
  Spring Security session-fixation protection (on by default).
- Logout invalidates the server-side session, not just the cookie.
- Idle timeout (15-30 min for sensitive apps) and absolute timeout (for example 8-24 h).
- Remember-me: separate long-lived random token, stored hashed, rotated on use, revocable from
  the account page.

### Cookie flags

| Attribute | Session cookie | Why |
| --- | --- | --- |
| `Secure` | required | never sent over HTTP |
| `HttpOnly` | required | not readable by injected scripts |
| `SameSite` | `Lax` (or `Strict`) | blocks most cross-site request forgery; still use CSRF tokens on state-changing forms |
| `Path=/`, no `Domain` | recommended | host-only; allows the `__Host-` prefix |
| `__Host-` prefix | recommended | browser enforces Secure, Path=/ and no Domain |
| `Max-Age`/`Expires` | omit or short | session cookies end with the browser session |

Framework settings:
- Django: `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True` (default),
  `SESSION_COOKIE_SAMESITE = "Lax"`, `CSRF_COOKIE_SECURE = True`.
- Laravel `config/session.php`: `'secure' => true`, `'http_only' => true`, `'same_site' => 'lax'`.
- Express `express-session`: `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }` and
  `app.set('trust proxy', 1)` behind a proxy.
- PHP: `session.cookie_secure=1`, `session.cookie_httponly=1`, `session.cookie_samesite=Lax`,
  `session.use_strict_mode=1`.
- Spring Boot: `server.servlet.session.cookie.secure=true`, `.http-only=true`, `.same-site=lax`.

## 6. JWT

- Prefer opaque server-side sessions for browser apps; JWTs fit service-to-service and
  short-lived API access.
- Verify with a pinned algorithm list (`algorithms=["RS256"]`), never the token's own `alg`;
  reject `none`.
- HS256: secret >= 32 random bytes from a secret store; every verifier can mint tokens, so
  prefer asymmetric keys (RS256/ES256/EdDSA) when more than one service verifies.
- Keys come from configuration or a pinned JWKS URL; ignore `jku`, `jwk`, `x5u`, `x5c` in
  the token header. Treat `kid` as a lookup key in an allow-list.
- Validate `exp`, `nbf`, `iss`, `aud` (small clock skew allowance).
- Access tokens: minutes (5-15). Refresh tokens: stored server-side or rotated with reuse
  detection; revocable.
- Payload is readable by anyone: no passwords, secrets, or unnecessary personal data.
- Storage in browsers: `HttpOnly` cookie over `localStorage` (XSS can read localStorage).

## 7. OAuth 2 / OIDC login

- Authorization code flow with PKCE; `state` (and `nonce` for OIDC) generated per request and
  checked.
- Redirect URIs registered as exact matches; no open redirects after login.
- Validate ID token signature, `iss`, `aud` (your client id), `exp`, `nonce`.
- Link accounts by the provider's stable subject (`sub`), not by email alone (unless the
  provider asserts a verified email you trust).
