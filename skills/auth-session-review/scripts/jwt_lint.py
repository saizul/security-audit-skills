#!/usr/bin/env python3
"""Lint a JWT issued by your own application for common design pitfalls. Offline.

Reads the token from stdin or --file (never from the command line, so it does not end
up in shell history). Decodes the header and payload WITHOUT verifying the signature
and prints only: alg, typ, kid, iss, aud, time claims and the names of other claims.
The signature and other claim values are never printed.

Checks: alg "none", symmetric HS* algorithms (shared secret strength and algorithm
pinning), embedded key headers (jwk/jku/x5u/x5c), suspicious kid, missing or long exp,
missing iat/iss/aud, already expired, iat/nbf in the future (issuer clock skew),
exp at or before iat/nbf (a token that can never be valid), and sensitive data in claims (payloads are only
base64url-encoded, not encrypted).

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = not a JWT / error.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high"]
SENSITIVE_CLAIM_RE = re.compile(
    r"(passw|pwd|secret|ssn|social|card|cvv|iban|account_?number|dob|birth|address|phone|salary|"
    r"api_?key|private)",
    re.I,
)
SHOWN_CLAIMS = ("iss", "aud", "exp", "iat", "nbf", "scope", "typ", "token_use")


def b64url_json(segment: str) -> dict:
    pad = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + pad)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("segment is not a JSON object")
    return value


def decode(token: str) -> tuple[dict, dict, int]:
    parts = token.strip().split(".")
    if len(parts) == 5:
        raise ValueError("this is a JWE (encrypted token); its claims cannot be linted without the key")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected three dot-separated parts")
    try:
        header, payload = b64url_json(parts[0]), b64url_json(parts[1])
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"not a JWT: cannot decode header/payload ({exc})") from exc
    return header, payload, len(parts[2])


def lint(
    header: dict, payload: dict, sig_len: int, now: float, max_hours: float, *, leeway: float = 300.0
) -> list[dict]:
    out: list[dict] = []

    def add(sev, check, msg, fix):
        out.append({"severity": sev, "check": check, "message": msg, "fix": fix})

    alg = str(header.get("alg", ""))
    if alg.lower() == "none" or not alg:
        add(
            "high",
            "alg-none",
            "unsigned token (alg none) - anyone can forge it",
            "always sign tokens; verifiers must reject alg none and pin the expected algorithm",
        )
    elif alg.upper().startswith("HS"):
        add(
            "info",
            "alg-hmac",
            f"{alg} uses a shared secret: every verifier can also mint tokens",
            "use a random secret of at least 32 bytes from a secret store; prefer RS256/ES256/EdDSA "
            "when other services verify; pin the algorithm in the verifier",
        )
    if alg.lower() != "none" and alg and sig_len == 0:
        add("high", "signature", "signature part is empty", "reject tokens without a signature")
    for k in ("jwk", "jku", "x5u", "x5c"):
        if k in header:
            add(
                "medium",
                f"header-{k}",
                f"header carries '{k}': verifiers must never trust keys supplied by the token",
                "remove it and resolve keys from a pinned, server-side JWKS",
            )
    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"[/\\'\";]|\.\.", kid):
        add(
            "low",
            "kid",
            "kid contains path or quote characters",
            "treat kid as an opaque lookup key in an allow-list; never use it in file paths or SQL",
        )

    exp, iat, nbf = payload.get("exp"), payload.get("iat"), payload.get("nbf")
    if not isinstance(exp, (int, float)):
        add("high", "exp", "no exp claim: the token never expires", "set exp (minutes for access tokens)")
    else:
        if exp < now:
            add("info", "expired", "token is already expired", "use a fresh token for testing")
        start = iat if isinstance(iat, (int, float)) else (nbf if isinstance(nbf, (int, float)) else now)
        hours = (exp - start) / 3600
        if hours > max_hours:
            add(
                "medium",
                "lifetime",
                f"lifetime is {hours:.1f} h (limit {max_hours:g} h)",
                "keep access tokens short-lived and use refresh tokens with rotation and revocation",
            )
    for claim, value in (("iat", iat), ("nbf", nbf)):
        if isinstance(value, (int, float)) and value > now + leeway:
            add(
                "low",
                f"{claim}-future",
                f"{claim} is {value - now:.0f} s in the future (leeway {leeway:g} s)",
                "sync the issuer clock with NTP; verifiers should allow only a small leeway",
            )
    if isinstance(exp, (int, float)):
        starts = [(c, v) for c, v in (("iat", iat), ("nbf", nbf)) if isinstance(v, (int, float))]
        for claim, value in starts:
            if exp <= value:
                add(
                    "medium",
                    "exp-before-start",
                    f"exp is not after {claim}: the token can never be valid",
                    "compute exp as issue time + lifetime, in seconds (not milliseconds)",
                )
                break
    if not isinstance(iat, (int, float)):
        add("low", "iat", "no iat claim", "set iat so lifetimes and revocation-by-time can be checked")
    if "iss" not in payload:
        add("low", "iss", "no iss claim", "set iss and verify it")
    if "aud" not in payload:
        add(
            "low",
            "aud",
            "no aud claim: a token for one service may be accepted by another",
            "set aud per API and verify it",
        )
    for name, value in payload.items():
        if SENSITIVE_CLAIM_RE.search(name):
            add(
                "high",
                "sensitive-claim",
                f"claim '{name}' looks sensitive; JWT payloads are readable by anyone holding the token",
                "remove it; reference data by id or use an encrypted token (JWE)",
            )
        elif isinstance(value, str) and re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", value, re.I):
            add(
                "info",
                "pii-claim",
                f"claim '{name}' holds an email address",
                "fine for ID tokens; avoid PII in access tokens that are logged or sent to third parties",
            )
    return out


def summary(header: dict, payload: dict) -> dict:
    shown = {k: payload[k] for k in SHOWN_CLAIMS if k in payload}
    return {
        "header": {k: header[k] for k in ("alg", "typ", "kid") if k in header},
        "claims_shown": shown,
        "other_claim_names": sorted(k for k in payload if k not in SHOWN_CLAIMS),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Lint a JWT (from stdin or --file) for design pitfalls; never prints the signature.",
        epilog="Example: pbpaste | jwt_lint.py   or   jwt_lint.py --file token.txt --json",
    )
    p.add_argument("--file", help="file containing the token (default: read stdin)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--max-hours", type=float, default=24.0, help="longest acceptable lifetime (default 24)")
    p.add_argument("--now", type=float, help="current Unix time (for reproducible checks)")
    p.add_argument(
        "--leeway", type=float, default=300.0, help="allowed clock skew in seconds for iat/nbf (default 300)"
    )
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="medium")
    args = p.parse_args(argv)
    try:
        token = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        header, payload, sig_len = decode(token)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    now = args.now if args.now is not None else time.time()
    findings = lint(header, payload, sig_len, now, args.max_hours, leeway=args.leeway)
    findings.sort(key=lambda x: -SEVERITIES.index(x["severity"]))
    info = summary(header, payload)
    if args.json:
        print(json.dumps({**info, "findings": findings}, indent=2, default=str))
    else:
        print(f"header: {json.dumps(info['header'])}")
        print(f"claims: {json.dumps(info['claims_shown'], default=str)}")
        print(f"other claim names: {', '.join(info['other_claim_names']) or '-'}  (values not shown)")
        for x in findings:
            print(f"{x['severity'].upper():6} {x['check']}: {x['message']}\n       fix: {x['fix']}")
        if not findings:
            print("no findings")
    if args.fail_on == "none":
        return 0
    t = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(x["severity"]) >= t for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
