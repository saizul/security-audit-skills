#!/usr/bin/env python3
"""Grade HTTP security headers from a HAR file or `curl -sI` output. Offline.

Input: a HAR export, or raw response headers (one or more responses, e.g. from
`curl -sIL https://example.com`; with redirects the last response is graded unless --all).
In a HAR, only HTML documents are graded unless --all is given.

Checks: Strict-Transport-Security, Content-Security-Policy quality (unsafe-inline,
unsafe-eval, wildcards, object-src, base-uri, frame-ancestors), X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy,
version-revealing Server / X-Powered-By, permissive CORS, deprecated X-XSS-Protection.

Score starts at 100: high -25, medium -10, low -5, info 0.
Grades: A >= 90, B >= 80, C >= 70, D >= 60, else F.
Exit codes: 0 = every graded response meets --min-grade, 1 = below, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PENALTY = {"high": 25, "medium": 10, "low": 5, "info": 0}
GRADES = ["A", "B", "C", "D", "F"]
VERSION_RE = re.compile(r"\d+\.\d+")


def grade(score: int) -> str:
    for g, minimum in zip("ABCD", (90, 80, 70, 60)):
        if score >= minimum:
            return g
    return "F"


def parse_raw(text: str) -> list[dict]:
    """Split curl -I style text into responses: {status, headers{name_lower: [values]}}."""
    responses: list[dict] = []
    current = None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if re.match(r"^HTTP/\d(\.\d)?\s+\d{3}", line):
            current = {"status": int(line.split()[1]), "headers": {}, "url": "", "mime": ""}
            responses.append(current)
            continue
        if ":" in line and not line.startswith((" ", "\t")):
            if current is None:  # headers without a status line
                current = {"status": 0, "headers": {}, "url": "", "mime": ""}
                responses.append(current)
            name, _, value = line.partition(":")
            current["headers"].setdefault(name.strip().lower(), []).append(value.strip())
    return responses


def parse_har(data: dict) -> list[dict]:
    out = []
    for entry in (data.get("log") or {}).get("entries") or []:
        resp = entry.get("response") or {}
        headers: dict = {}
        for h in resp.get("headers") or []:
            headers.setdefault(str(h.get("name", "")).lower(), []).append(str(h.get("value", "")))
        mime = str((resp.get("content") or {}).get("mimeType", "")) or ";".join(
            headers.get("content-type", [])
        )
        out.append(
            {
                "status": resp.get("status", 0),
                "headers": headers,
                "url": (entry.get("request") or {}).get("url", ""),
                "mime": mime,
            }
        )
    return out


def parse_csp(value: str) -> dict:
    directives = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_csp(value: str, add) -> bool:
    """Return True if the CSP sets frame-ancestors."""
    d = parse_csp(value)
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        add("medium", "csp", "CSP has neither script-src nor default-src", "add default-src 'self'")
    else:
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        if "'unsafe-inline'" in script and not has_nonce and "'strict-dynamic'" not in script:
            add(
                "medium",
                "csp",
                "script-src allows 'unsafe-inline' (CSP no longer stops injected scripts)",
                "use nonces or hashes ('nonce-...' + 'strict-dynamic') instead of 'unsafe-inline'",
            )
        if "'unsafe-eval'" in script:
            add(
                "medium",
                "csp",
                "script-src allows 'unsafe-eval'",
                "remove eval/new Function use, then drop it",
            )
        wild = [t for t in script if t in ("*", "http:", "https:", "data:") or t.startswith("http://")]
        if wild:
            add(
                "medium",
                "csp",
                f"script-src allows broad sources: {' '.join(wild)}",
                "list exact origins (or use nonces with 'strict-dynamic')",
            )
    default_none = d.get("default-src") == ["'none'"]
    if "object-src" not in d and not default_none:
        add("low", "csp", "no object-src (plugins inherit default-src)", "add object-src 'none'")
    if "base-uri" not in d:
        add(
            "low", "csp", "no base-uri (injected <base> can redirect relative scripts)", "add base-uri 'self'"
        )
    return "frame-ancestors" in d


def evaluate(resp: dict, https: bool) -> dict:
    h = resp["headers"]
    findings: list[dict] = []

    def add(sev, header, msg, fix):
        findings.append({"severity": sev, "header": header, "message": msg, "fix": fix})

    def first(name):
        vals = h.get(name)
        return vals[0] if vals else None

    hsts = first("strict-transport-security")
    if https:
        if not hsts:
            add(
                "high",
                "strict-transport-security",
                "missing HSTS",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                add(
                    "low",
                    "strict-transport-security",
                    f"max-age={age} is under 180 days",
                    "use max-age=31536000",
                )
            if "includesubdomains" not in hsts.lower():
                add(
                    "info",
                    "strict-transport-security",
                    "no includeSubDomains",
                    "add it once all subdomains use HTTPS",
                )

    csp = first("content-security-policy")
    csp_ro = first("content-security-policy-report-only")
    frame_ancestors = False
    if csp:
        frame_ancestors = check_csp(csp, add)
    elif csp_ro:
        add(
            "medium",
            "content-security-policy",
            "CSP is report-only, so it does not block anything",
            "after reviewing reports, send the same policy as Content-Security-Policy",
        )
    else:
        add(
            "medium",
            "content-security-policy",
            "missing Content-Security-Policy",
            "start with default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' "
            "(deploy as Report-Only first)",
        )

    xfo = first("x-frame-options")
    if not frame_ancestors and not xfo:
        add(
            "medium",
            "x-frame-options",
            "no clickjacking protection (frame-ancestors or X-Frame-Options)",
            "CSP frame-ancestors 'self' (or X-Frame-Options: DENY)",
        )
    elif xfo and xfo.strip().upper().startswith("ALLOW-FROM"):
        add("low", "x-frame-options", "ALLOW-FROM is ignored by modern browsers", "use CSP frame-ancestors")

    xcto = first("x-content-type-options")
    if not xcto or xcto.strip().lower() != "nosniff":
        add("low", "x-content-type-options", "missing nosniff", "X-Content-Type-Options: nosniff")

    rp = first("referrer-policy")
    if not rp:
        add(
            "low",
            "referrer-policy",
            "missing Referrer-Policy",
            "Referrer-Policy: strict-origin-when-cross-origin",
        )
    elif rp.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        add(
            "medium" if rp.strip().lower() == "unsafe-url" else "low",
            "referrer-policy",
            f"'{rp}' leaks full URLs (paths, query tokens) to other sites",
            "Referrer-Policy: strict-origin-when-cross-origin",
        )
    if not first("permissions-policy"):
        add(
            "info",
            "permissions-policy",
            "missing Permissions-Policy",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        )
    if not first("cross-origin-opener-policy"):
        add("info", "cross-origin-opener-policy", "missing COOP", "Cross-Origin-Opener-Policy: same-origin")

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        val = first(name)
        if val and (VERSION_RE.search(val) or name != "server"):
            add(
                "low",
                name,
                f"{name} reveals software/version ({val[:40]})",
                "remove the header or hide the version (server_tokens off; expose_php = Off)",
            )

    acao = first("access-control-allow-origin")
    acac = (first("access-control-allow-credentials") or "").lower() == "true"
    if acao:
        if acao.strip() == "*" and acac:
            add(
                "high",
                "access-control-allow-origin",
                "wildcard origin with credentials",
                "reflect only allow-listed origins; never combine * with credentials",
            )
        elif acao.strip() == "null":
            add(
                "high",
                "access-control-allow-origin",
                "origin 'null' is allowed",
                "never allow the null origin",
            )
        elif acao.strip() == "*":
            add(
                "info",
                "access-control-allow-origin",
                "any origin may read responses (fine for public, unauthenticated data only)",
                "restrict to known origins if responses depend on cookies or auth",
            )
    xxss = first("x-xss-protection")
    if xxss and xxss.strip().startswith("1"):
        add(
            "info",
            "x-xss-protection",
            "legacy XSS auditor setting",
            "set X-XSS-Protection: 0 and rely on CSP",
        )

    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    order = ["high", "medium", "low", "info"]
    findings.sort(key=lambda f: order.index(f["severity"]))
    return {
        "url": resp.get("url", ""),
        "status": resp.get("status", 0),
        "score": score,
        "grade": grade(score),
        "findings": findings,
    }


def select(responses: list[dict], from_har: bool, all_responses: bool, url_filter: str) -> list[dict]:
    if url_filter:
        responses = [r for r in responses if url_filter in r.get("url", "")]
    if all_responses:
        return responses
    if from_har:
        return [r for r in responses if "html" in r.get("mime", "").lower() and 200 <= r["status"] < 400]
    return responses[-1:]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Grade security headers from a HAR file or curl -sI output.",
        epilog="Example: curl -sIL https://example.com | headers_grade.py -",
    )
    p.add_argument("input", help="HAR file or headers text, or - for stdin")
    p.add_argument("--http", action="store_true", help="raw headers came from plain HTTP (skip HSTS)")
    p.add_argument("--all", action="store_true", help="grade every response, not just HTML / the last one")
    p.add_argument("--url", default="", help="only grade HAR entries whose URL contains this text")
    p.add_argument("--min-grade", choices=GRADES, default="B", help="exit 1 below this grade (default B)")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    try:
        text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    from_har = text.lstrip().startswith("{")
    try:
        responses = parse_har(json.loads(text)) if from_har else parse_raw(text)
    except ValueError as exc:
        print(f"error: invalid HAR JSON: {exc}", file=sys.stderr)
        return 2
    chosen = select(responses, from_har, args.all, args.url)
    if not chosen:
        print("error: no responses to grade (try --all)", file=sys.stderr)
        return 2
    results = []
    for r in chosen:
        https = r["url"].lower().startswith("https://") if r.get("url") else not args.http
        results.append(evaluate(r, https))
    if args.json:
        print(json.dumps({"results": results}, indent=2))
    else:
        for res in results:
            label = res["url"] or f"response (HTTP {res['status']})"
            print(f"{res['grade']} ({res['score']}/100)  {label}")
            for f in res["findings"]:
                print(f"  {f['severity'].upper():6} {f['header']}: {f['message']}\n         fix: {f['fix']}")
    limit = GRADES.index(args.min_grade)
    return 1 if any(GRADES.index(r["grade"]) > limit for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
