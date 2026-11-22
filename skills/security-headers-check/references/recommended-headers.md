# Recommended headers and how to set them

Baseline for an HTML application served over HTTPS (adjust CSP to your assets):

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
```

Remove or neutralise: `X-Powered-By`, version numbers in `Server`, `X-AspNet-Version`.
`X-Frame-Options: DENY` (or `SAMEORIGIN`) is still useful for very old browsers; CSP
`frame-ancestors` supersedes it. `X-XSS-Protection` is obsolete: send `0` or nothing.

## CSP patterns

- **Strict CSP (recommended for apps with inline scripts):**
  `script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`
  Generate a new nonce per response and put it on every `<script nonce="...">`.
- **Allow-list CSP (static sites):** `script-src 'self' https://cdn.example.com`.
- Avoid `'unsafe-inline'` and `'unsafe-eval'` in `script-src`, `*`, `https:` and `data:` as
  script sources. `'unsafe-inline'` in `style-src` is a smaller risk.
- Add `report-to` / `report-uri` while testing.

## CORS

- Public, unauthenticated data: `Access-Control-Allow-Origin: *` is fine (no credentials).
- Authenticated APIs: compare the `Origin` request header to an allow-list and echo only allowed
  origins; add `Vary: Origin`. Never combine `*` with `Access-Control-Allow-Credentials: true`,
  never allow `null`, never use substring/regex checks that `evil-example.com` would pass.

## nginx

```nginx
server {
    # ...
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    fastcgi_hide_header X-Powered-By;    # or proxy_hide_header for proxied apps
}
```

`add_header` directives are inherited only if the inner block has none of its own: put them in
a snippet and `include` it in every `location` that adds headers.

## Apache

```apache
ServerTokens Prod
ServerSignature Off
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always unset X-Powered-By
```

PHP: `expose_php = Off` in php.ini.

## Express (Node.js)

```js
const helmet = require("helmet");
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: { directives: { "script-src": ["'self'"], "object-src": ["'none'"] } },
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
}));
```

## Django

```python
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
# CSP: Django 6.0+ has built-in CSP settings (SECURE_CSP); older versions use django-csp.
```

## Laravel

Add a middleware that sets the headers on every response (or use a package such as
`spatie/laravel-csp` for CSP), and register it in the global middleware stack.

## Next.js

```js
// next.config.js
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];
module.exports = {
  poweredByHeader: false,
  async headers() { return [{ source: "/:path*", headers: securityHeaders }]; },
};
```

For a nonce-based CSP in Next.js, generate the nonce in middleware (see the Next.js CSP guide).

## CDNs

Cloudflare (Transform Rules / Workers), CloudFront (response headers policies), Netlify
(`_headers` file) and Vercel (`vercel.json` `headers`) can set headers at the edge. Set each
header in one layer only to avoid duplicates.
