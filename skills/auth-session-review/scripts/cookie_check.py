#!/usr/bin/env python3
"""Check Set-Cookie headers from a HAR file or raw response headers for unsafe flags.

Input: a HAR export (browser DevTools > Network > "Save all as HAR") or plain text
headers such as `curl -sI https://example.com/login` output. Cookie values are never
printed; only names, attributes and lengths.

Checks: Secure, HttpOnly (session-like cookies), SameSite (missing, None without Secure),
__Host- / __Secure- prefix rules, broad Domain, long-lived session cookies, cookies set
over plain HTTP, and values that look like JWTs (data readable by anyone holding it).

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high"]
SESSION_RE = re.compile(
    r"(sess|sid$|^sid|auth|token|jwt|remember|login|identity|connect\.sid|phpsessid|jsessionid|"
    r"laravel_session|_session$|asp\.net_sessionid|aspxauth|refresh|access)",
    re.I,
)
CSRF_RE = re.compile(r"(csrf|xsrf)", re.I)
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
MAX_SESSION_SECONDS = 30 * 24 * 3600


@dataclass
class Cookie:
    name: str
    value_length: int
    attrs: dict
    url: str = ""
    https: bool | None = None
    response_time: datetime | None = None
    value_is_jwt: bool = False


@dataclass
class Finding:
    cookie: str
    url: str
    severity: str
    check: str
    message: str
    fix: str


def parse_set_cookie(header: str) -> tuple[str, str, dict]:
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs: dict = {}
    for part in parts[1:]:
        if not part:
            continue
        k, sep, v = part.partition("=")
        attrs[k.strip().lower()] = v.strip() if sep else True
    return name.strip(), value.strip().strip('"'), attrs


def _parse_dt(value: str) -> datetime | None:
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def cookies_from_har(data: dict) -> list[Cookie]:
    out = []
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url", "")
        headers = resp.get("headers") or []
        date = next((h.get("value") for h in headers if str(h.get("name")).lower() == "date"), None)
        when = _parse_dt(date) if date else _parse_dt(entry.get("startedDateTime", ""))
        for h in headers:
            if str(h.get("name", "")).lower() != "set-cookie":
                continue
            # Firefox joins several cookies with newlines in one header entry.
            for line in str(h.get("value", "")).split("\n"):
                if line.strip():
                    out.append(_cookie(line, url, when))
    return out


def cookies_from_headers(text: str, url: str = "", assume_https: bool = True) -> list[Cookie]:
    out = []
    when = None
    for line in text.splitlines():
        m = re.match(r"^\s*date\s*:\s*(.+)$", line, re.I)
        if m:
            when = _parse_dt(m.group(1).strip())
    for line in text.splitlines():
        m = re.match(r"^\s*set-cookie\s*:\s*(.+)$", line, re.I)
        if m:
            c = _cookie(m.group(1), url, when)
            if not url:
                c.https = assume_https
            out.append(c)
    return out


def _cookie(header: str, url: str, when: datetime | None) -> Cookie:
    name, value, attrs = parse_set_cookie(header)
    https = url.lower().startswith("https://") if url else None
    return Cookie(
        name=name,
        value_length=len(value),
        attrs=attrs,
        url=url,
        https=https,
        response_time=when,
        value_is_jwt=bool(JWT_RE.match(value)),
    )


def lifetime_seconds(c: Cookie) -> float | None:
    if "max-age" in c.attrs:
        try:
            return float(c.attrs["max-age"])
        except (TypeError, ValueError):
            return None
    exp = c.attrs.get("expires")
    if isinstance(exp, str):
        dt = _parse_dt(exp)
        if dt:
            base = c.response_time or datetime.now(timezone.utc)
            return (dt - base).total_seconds()
    return None


def check_cookie(c: Cookie) -> list[Finding]:
    f: list[Finding] = []
    a = c.attrs
    name = c.name
    session = bool(SESSION_RE.search(name)) and not CSRF_RE.search(name)
    lifetime = lifetime_seconds(c)
    if lifetime is not None and lifetime <= 0:
        return []  # deletion cookie

    def add(sev, check, msg, fix):
        f.append(Finding(name, c.url, sev, check, msg, fix))

    secure = "secure" in a
    samesite = str(a.get("samesite", "")).lower() if a.get("samesite") is not True else ""
    if c.https is False:
        add(
            "high" if session else "medium",
            "set-over-http",
            "cookie is set on a plain HTTP response",
            "serve the site only over HTTPS (redirect + HSTS) and add Secure",
        )
    if not secure:
        add(
            "high" if session else "low",
            "secure",
            "missing Secure: the browser also sends it over plain HTTP",
            "add Secure",
        )
    if session and "httponly" not in a:
        add(
            "high",
            "httponly",
            "session-like cookie without HttpOnly is readable by JavaScript (XSS steals it)",
            "add HttpOnly",
        )
    if "samesite" not in a:
        add(
            "medium" if session else "low",
            "samesite",
            "no SameSite attribute; browsers differ in the default",
            "add SameSite=Lax (or Strict for admin/session cookies); use CSRF tokens for unsafe methods",
        )
    elif samesite == "none" and not secure:
        add("high", "samesite-none", "SameSite=None without Secure is rejected by browsers", "add Secure")
    elif samesite == "none" and session:
        add(
            "medium",
            "samesite-none",
            "session cookie with SameSite=None is sent on cross-site requests (CSRF exposure)",
            "use Lax/Strict unless it must work in third-party iframes; then require CSRF tokens",
        )
    elif samesite and samesite not in ("lax", "strict", "none"):
        add("low", "samesite", f"unknown SameSite value '{a.get('samesite')}'", "use Lax, Strict or None")
    if name.startswith("__Host-"):
        problems = []
        if not secure:
            problems.append("Secure")
        if a.get("path") != "/":
            problems.append("Path=/")
        if "domain" in a:
            problems.append("no Domain")
        if problems:
            add(
                "high",
                "prefix",
                "__Host- cookie rejected by browsers: needs " + ", ".join(problems),
                "set Secure; Path=/ and remove Domain",
            )
    elif name.startswith("__Secure-") and not secure:
        add("high", "prefix", "__Secure- cookie without Secure is rejected", "add Secure")
    elif session and secure and "domain" not in a and a.get("path", "/") == "/":
        add(
            "info",
            "prefix",
            "eligible for the __Host- prefix, which locks the cookie to this exact origin",
            f"consider renaming to __Host-{name}",
        )
    if "domain" in a and session:
        add(
            "low",
            "domain",
            f"Domain={a['domain']} shares the cookie with every subdomain",
            "omit Domain (host-only) unless subdomains really need the session",
        )
    if session and lifetime is not None and lifetime > MAX_SESSION_SECONDS:
        days = int(lifetime // 86400)
        add(
            "medium",
            "lifetime",
            f"session-like cookie lives {days} days",
            "keep session cookies short (hours to days); use a separate revocable remember-me token",
        )
    if c.value_is_jwt:
        add(
            "info",
            "jwt-in-cookie",
            f"value is a JWT ({c.value_length} chars): its claims are readable by anyone holding it",
            "do not put sensitive data in claims; run jwt_lint.py on a sample token",
        )
    return f


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Check Set-Cookie flags from a HAR file or raw response headers.",
        epilog="Example: curl -sI https://example.com/login | cookie_check.py - --url https://example.com/login",
    )
    p.add_argument("input", help="HAR file or headers text file, or - for stdin")
    p.add_argument("--url", default="", help="URL the raw headers came from (default: assume HTTPS)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="medium")
    args = p.parse_args(argv)
    try:
        text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            cookies = cookies_from_har(json.loads(text))
        except ValueError as exc:
            print(f"error: invalid HAR JSON: {exc}", file=sys.stderr)
            return 2
    else:
        cookies = cookies_from_headers(text, args.url)

    findings: list[Finding] = []
    seen = set()
    for c in cookies:
        key = (c.name, tuple(sorted((k, str(v)) for k, v in c.attrs.items() if k != "expires")))
        if key in seen:
            continue
        seen.add(key)
        findings.extend(check_cookie(c))
    findings.sort(key=lambda x: (-SEVERITIES.index(x.severity), x.cookie, x.check))

    if args.json:
        print(
            json.dumps(
                {
                    "cookies": sorted({c.name for c in cookies}),
                    "findings": [asdict(x) for x in findings],
                },
                indent=2,
            )
        )
    else:
        names = sorted({c.name for c in cookies})
        print(f"cookie check: {len(names)} cookie(s): {', '.join(names) or 'none found'} (values not shown)")
        for x in findings:
            print(f"{x.severity.upper():6} {x.cookie}  {x.check}: {x.message}\n       fix: {x.fix}")
    if args.fail_on == "none":
        return 0
    t = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(x.severity) >= t for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
