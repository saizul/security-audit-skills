#!/usr/bin/env python3
"""Generate a STRIDE-per-element threat table from a small JSON system model.

Model (JSON):
  {
    "system": "Shop",
    "elements": [
      {"id": "user", "type": "external", "name": "Customer browser"},
      {"id": "api", "type": "process", "name": "API", "zone": "dmz", "internet_facing": true},
      {"id": "db", "type": "store", "name": "Postgres", "zone": "internal",
       "data": ["pii", "credentials"], "encrypted_at_rest": true}
    ],
    "flows": [
      {"from": "user", "to": "api", "name": "HTTPS requests", "protocol": "https",
       "authenticated": true, "data": ["credentials"]}
    ]
  }

Element types: external (person or outside system), process, store, and flows between
elements. Zones mark trust boundaries: a flow whose ends are in different zones crosses a
boundary (elements without a zone are in "internet" when external, else "default").

Rules follow STRIDE-per-element: externals get S/R, processes get all six, stores get
T/R/I/D, flows get T/I/D. Likelihood and impact start at 2 (flows: 1, or 2 across a
boundary). Facts in the model raise them: internet_facing, a plain-text or unmarked
protocol, sensitive "data", no encrypted_at_rest, "authenticated": false across a
boundary. An encrypted protocol (https, tls, ...) lowers flow tampering/disclosure.
The output is a starting point for a human review, not a verdict.

Exit codes: 0 = table written, 2 = invalid model.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

TYPES = {"external", "process", "store"}
APPLICABLE = {
    "external": "SR",
    "process": "STRIDE",
    "store": "TRID",
    "flow": "TID",
}
CATEGORY = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}
SENSITIVE = {"pii", "credentials", "secrets", "payment", "health", "tokens", "keys", "financial"}
ENCRYPTED = {"https", "tls", "mtls", "wss", "grpcs", "ssh", "sftp", "ftps", "smtps", "imaps", "ldaps"}
PLAINTEXT = {
    "http",
    "ftp",
    "telnet",
    "smtp",
    "ldap",
    "tcp",
    "udp",
    "redis",
    "memcached",
    "mysql",
    "postgres",
    "amqp",
    "mqtt",
    "ws",
    "grpc",
}

TEMPLATES = {
    ("external", "S"): (
        "An attacker impersonates {name} (stolen credentials, forged identity or API key).",
        "Strong authentication (MFA, OAuth/OIDC, mTLS for systems); rate-limit and lock out guessing.",
    ),
    ("external", "R"): (
        "{name} denies having performed an action and there is no evidence either way.",
        "Log security-relevant actions with actor, time and request id; keep logs tamper-evident.",
    ),
    ("process", "S"): (
        "A caller or another service pretends to be {name} or a trusted peer of it.",
        "Authenticate service-to-service calls (mTLS, signed tokens); verify issuer and audience.",
    ),
    ("process", "T"): (
        "Inputs to {name} are manipulated to change its behaviour (injection, mass assignment, "
        "parameter tampering).",
        "Validate input against an allow-list schema; parameterized queries; server-side authorization.",
    ),
    ("process", "R"): (
        "Actions performed through {name} cannot be traced to a user.",
        "Audit log for authentication, authorization failures and data changes; synchronized clocks.",
    ),
    ("process", "I"): (
        "{name} leaks data through error messages, debug endpoints, logs or over-broad API responses.",
        "Generic errors to clients; return only needed fields; scrub secrets/PII from logs.",
    ),
    ("process", "D"): (
        "{name} is exhausted by request floods, expensive queries, large uploads or regex/zip bombs.",
        "Rate limits, timeouts, request size limits, pagination, quotas, autoscaling with caps.",
    ),
    ("process", "E"): (
        "A user of {name} gains rights they should not have (broken access control, IDOR, "
        "role confusion, code execution).",
        "Deny by default; check object-level authorization on every request; least-privilege runtime.",
    ),
    ("store", "T"): (
        "Data in {name} is modified by someone who should not be able to write it.",
        "Least-privilege DB accounts per service; integrity checks; backups with restore tests.",
    ),
    ("store", "R"): (
        "Changes in {name} cannot be attributed to a user or service.",
        "Record who/when on writes (audit tables or DB audit log); restrict direct admin access.",
    ),
    ("store", "I"): (
        "Data in {name} is read by an unauthorized party (exposed port, leaked backup, SQL injection, "
        "over-privileged account).",
        "Network isolation; encryption at rest; least privilege; protect and encrypt backups.",
    ),
    ("store", "D"): (
        "{name} becomes unavailable or full (disk exhaustion, lock contention, deletion).",
        "Monitoring and alerts on capacity; connection limits; backups and tested restore.",
    ),
    ("flow", "T"): (
        "Data on '{name}' is altered in transit.",
        "TLS 1.2+ with certificate validation; message signing (HMAC) for webhooks/queues.",
    ),
    ("flow", "I"): (
        "Data on '{name}' is observed in transit.",
        "TLS everywhere, including internal hops; do not put secrets in URLs or query strings.",
    ),
    ("flow", "D"): (
        "'{name}' is interrupted or flooded so the receiver cannot work.",
        "Timeouts, retries with backoff, circuit breakers, queue limits; rate limiting at the edge.",
    ),
}


class ModelError(ValueError):
    pass


def load_model(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ModelError("model must be a JSON object")
    elements = data.get("elements")
    if not isinstance(elements, list) or not elements:
        raise ModelError("model needs a non-empty 'elements' list")
    ids = {}
    for i, el in enumerate(elements):
        if not isinstance(el, dict) or not el.get("id"):
            raise ModelError(f"elements[{i}] needs an 'id'")
        if el.get("type") not in TYPES:
            raise ModelError(f"element '{el['id']}': type must be one of {sorted(TYPES)}")
        if el["id"] in ids:
            raise ModelError(f"duplicate element id '{el['id']}'")
        ids[el["id"]] = el
    flows = data.get("flows") or []
    if not isinstance(flows, list):
        raise ModelError("'flows' must be a list")
    for i, fl in enumerate(flows):
        if not isinstance(fl, dict):
            raise ModelError(f"flows[{i}] must be an object")
        for end in ("from", "to"):
            if fl.get(end) not in ids:
                raise ModelError(f"flows[{i}].{end} '{fl.get(end)}' is not an element id")
    return {"system": data.get("system", "system"), "elements": ids, "flows": flows}


def encrypted(proto: str) -> bool:
    return proto in ENCRYPTED or "tls" in proto or proto.endswith(("+ssl", "-ssl", "rediss", "amqps"))


def zone(el: dict) -> str:
    return el.get("zone") or ("internet" if el["type"] == "external" else "default")


def risk_label(score: int) -> str:
    return "High" if score >= 6 else "Medium" if score >= 3 else "Low"  # 9, 6 / 4, 3 / 2, 1


def generate(model: dict) -> list[dict]:
    rows: list[dict] = []
    els = model["elements"]

    def add(kind, target, letter, threat, mitigation, likelihood, impact, notes):  # noqa: PLR0917
        score = likelihood * impact
        rows.append(
            {
                "id": "",
                "element": target,
                "element_type": kind,
                "stride": letter,
                "category": CATEGORY[letter],
                "threat": threat,
                "mitigation": mitigation,
                "likelihood": likelihood,
                "impact": impact,
                "risk": risk_label(score),
                "score": score,
                "notes": "; ".join(notes),
                "status": "open",
            }
        )

    for el in els.values():
        kind = el["type"]
        name = el.get("name", el["id"])
        sensitive = SENSITIVE & {str(d).lower() for d in el.get("data", [])}
        for letter in APPLICABLE[kind]:
            threat, mitigation = TEMPLATES[(kind, letter)]
            likelihood, impact, notes = 2, 2, []
            if el.get("internet_facing") and letter in "TDE":
                likelihood = 3
                notes.append("internet-facing")
            if sensitive and letter in "IT":
                impact = 3
                notes.append("holds " + ", ".join(sorted(sensitive)))
            if kind == "store" and letter == "I" and not el.get("encrypted_at_rest"):
                likelihood = max(likelihood, 2)
                notes.append("not marked encrypted_at_rest")
                if sensitive:
                    likelihood = 3
            add(kind, name, letter, threat.format(name=name), mitigation, likelihood, impact, notes)

    for fl in model["flows"]:
        src, dst = els[fl["from"]], els[fl["to"]]
        name = fl.get("name") or f"{src.get('name', src['id'])} -> {dst.get('name', dst['id'])}"
        proto = str(fl.get("protocol", "")).lower()
        crosses = zone(src) != zone(dst)
        sensitive = SENSITIVE & {str(d).lower() for d in fl.get("data", [])}
        label = f"{src.get('name', src['id'])} -> {dst.get('name', dst['id'])}"
        for letter in APPLICABLE["flow"]:
            threat, mitigation = TEMPLATES[("flow", letter)]
            likelihood, impact, notes = 2 if crosses else 1, 2, []
            if crosses:
                notes.append(f"crosses trust boundary {zone(src)} -> {zone(dst)}")
            if letter in "TI":
                if encrypted(proto):
                    likelihood = 1
                elif proto in PLAINTEXT:
                    likelihood = 3 if crosses else 2
                    notes.append(f"plain-text protocol '{proto}'")
                else:
                    likelihood = 2
                    notes.append("protocol not marked as encrypted")
            if sensitive and letter in "TI":
                impact = 3
                notes.append("carries " + ", ".join(sorted(sensitive)))
            add(
                "flow",
                f"{name} ({label})",
                letter,
                threat.format(name=name),
                mitigation,
                likelihood,
                impact,
                notes,
            )
        if crosses and fl.get("authenticated") is False:
            add(
                "flow",
                f"{name} ({label})",
                "S",
                f"Requests on '{name}' cross a trust boundary without authentication, so anyone who "
                f"can reach {dst.get('name', dst['id'])} can send them.",
                "Require authentication (session, token or mTLS) or restrict the network path.",
                3,
                3 if sensitive else 2,
                ["authenticated: false across a boundary"],
            )

    rows.sort(key=lambda r: (-r["score"], r["element"], "STRIDE".index(r["stride"])))
    for i, r in enumerate(rows, 1):
        r["id"] = f"T{i:02d}"
    return rows


COLUMNS = ["id", "element", "category", "threat", "mitigation", "likelihood", "impact", "risk", "status"]


def to_markdown(model: dict, rows: list[dict]) -> str:
    out = [f"# Threat model: {model['system']}", ""]
    counts = {k: sum(1 for r in rows if r["risk"] == k) for k in ("High", "Medium", "Low")}
    out.append(
        f"{len(rows)} candidate threats - High {counts['High']}, Medium {counts['Medium']}, "
        f"Low {counts['Low']}. Likelihood and impact are 1-3; risk = likelihood x impact."
    )
    boundaries = sorted({zone(e) for e in model["elements"].values()})
    out += ["", f"Trust zones: {', '.join(boundaries)}", ""]
    out.append("| ID | Element | STRIDE | Threat | Mitigation | L | I | Risk | Status |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in rows:
        threat = r["threat"] + (f" _({r['notes']})_" if r["notes"] else "")
        cells = [
            r["id"],
            r["element"],
            r["category"],
            threat,
            r["mitigation"],
            str(r["likelihood"]),
            str(r["impact"]),
            r["risk"],
            r["status"],
        ]
        out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(out) + "\n"


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=[*COLUMNS, "notes"], extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate a STRIDE threat table from a JSON system model.",
        epilog="Example: stride.py model.json --format md > THREATS.md",
    )
    p.add_argument("model", help="model JSON file, or - for stdin")
    p.add_argument("--format", choices=["md", "json", "csv"], default="md")
    p.add_argument("--min-risk", choices=["Low", "Medium", "High"], default="Low", help="hide lower risks")
    args = p.parse_args(argv)
    try:
        text = sys.stdin.read() if args.model == "-" else Path(args.model).read_text(encoding="utf-8")
        model = load_model(json.loads(text))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rows = generate(model)
    order = ["Low", "Medium", "High"]
    rows = [r for r in rows if order.index(r["risk"]) >= order.index(args.min_risk)]
    if args.format == "json":
        print(json.dumps({"system": model["system"], "threats": rows}, indent=2))
    elif args.format == "csv":
        sys.stdout.write(to_csv(rows))
    else:
        sys.stdout.write(to_markdown(model, rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
