#!/usr/bin/env python3
"""Create and maintain a Markdown incident record with a phase checklist and timeline.

Commands:
  new    create incident-<UTC timestamp>-<slug>.md from a playbook type
  add    append a UTC-timestamped entry to the Timeline section
  check  report checklist progress per phase (exit 1 while items are open)

Types: leaked-secret, compromised-account, malicious-dependency, other.
Only writes the record file you name or create; never contacts any service.
Do not paste secret values into the record: describe them (for example "AWS key AKIA...XYZ1").

Exit codes: 0 = ok (check: all items done), 1 = check found open items, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PHASES = ["Triage", "Contain", "Eradicate", "Recover", "Learn"]
CHECKLISTS = {
    "leaked-secret": {
        "Triage": [
            "Identify the secret type, owner and scope (what it can access)",
            "Find where it leaked (repo, commit, log, ticket, chat) and when it was first exposed",
            "Decide severity: public exposure or production scope = SEV1",
        ],
        "Contain": [
            "Revoke or rotate the secret at the provider (do not wait for the history rewrite)",
            "Deploy the new secret to every consumer and confirm they work",
            "Disable the old secret and confirm it is rejected",
        ],
        "Eradicate": [
            "Review provider audit logs for use of the old secret since first exposure",
            "Remove the secret from code; load it from a secret store or environment",
            "Purge it from git history / logs / artifacts if needed and ask collaborators to re-clone",
        ],
        "Recover": [
            "Add secret scanning (pre-commit + CI) so it cannot happen again",
            "Confirm no unexpected resources, charges or data access remain",
        ],
        "Learn": [
            "Write a blameless post-incident review with timeline and root cause",
            "Track follow-up actions with owners and due dates",
        ],
    },
    "compromised-account": {
        "Triage": [
            "Identify the account, its privileges and the first suspicious activity",
            "Preserve evidence: export audit/sign-in logs before they roll over",
            "Decide severity: admin or production access = SEV1",
        ],
        "Contain": [
            "Reset the password and revoke all sessions and refresh tokens",
            "Revoke API keys, OAuth grants, app passwords and SSH keys created by the account",
            "Enforce MFA (phishing-resistant if possible) before re-enabling",
        ],
        "Eradicate": [
            "Remove attacker persistence: new users, keys, mail forwarding rules, webhooks, deploy keys",
            "Review changes made during the window (code, config, permissions, payouts)",
            "Check other accounts that share the password or device",
        ],
        "Recover": [
            "Restore changed data/config from known-good state",
            "Monitor the account and related systems closely for 30 days",
        ],
        "Learn": [
            "Write a blameless post-incident review with timeline and root cause",
            "Track follow-up actions with owners and due dates",
        ],
    },
    "malicious-dependency": {
        "Triage": [
            "Identify the package, malicious versions and which projects/lockfiles include it",
            "Find every place it ran: developer machines, CI runners, build servers, production",
            "Decide severity: ran in CI with secrets or in production = SEV1",
        ],
        "Contain": [
            "Pin to a known-good version or remove the package; block the bad version in CI",
            "Rotate every secret the install/build environment could read "
            "(CI tokens, cloud keys, npm/PyPI tokens)",
            "Isolate or rebuild affected machines and runners",
        ],
        "Eradicate": [
            "Check for persistence the package may have installed (startup scripts, cron, SSH keys)",
            "Rebuild and redeploy artifacts built while the bad version was present",
        ],
        "Recover": [
            "Enable lockfile-only installs (npm ci, pip --require-hashes) and dependency review",
            "Watch provider audit logs for use of rotated credentials",
        ],
        "Learn": [
            "Write a blameless post-incident review with timeline and root cause",
            "Track follow-up actions with owners and due dates",
        ],
    },
    "other": {
        "Triage": ["Describe what happened, what is affected and the current impact", "Assign roles"],
        "Contain": ["Stop further damage with the smallest safe change"],
        "Eradicate": ["Remove the root cause and any persistence"],
        "Recover": ["Restore normal service and monitor"],
        "Learn": ["Write a blameless post-incident review", "Track follow-up actions"],
    },
}


def utc_now(override: str | None = None) -> datetime:
    if override:
        dt = datetime.fromisoformat(override.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slugify(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:40] or "incident"


def render(kind: str, title: str, severity: str, now: datetime) -> str:
    lines = [
        f"# Incident: {title}",
        "",
        f"- Type: {kind}",
        f"- Severity: {severity}",
        "- Status: open",
        f"- Opened: {iso(now)}",
        "- Incident lead: TBD",
        "- Communications: TBD",
        "- Playbook: references/playbooks.md",
        "",
        "> Never paste secret values, passwords or personal data into this file.",
        "",
        "## Summary",
        "",
        "What happened, what is affected, current impact. Update as facts change.",
        "",
    ]
    for phase in PHASES:
        lines.append(f"## {phase}")
        lines.append("")
        lines += [f"- [ ] {item}" for item in CHECKLISTS[kind][phase]]
        lines.append("")
    lines += ["## Timeline", "", f"- {iso(now)} incident record created", ""]
    return "\n".join(lines)


def add_entry(text: str, message: str, now: datetime) -> str:
    entry = f"- {iso(now)} {message.strip()}"
    m = re.search(r"^## Timeline\s*$", text, re.M)
    if not m:
        return text.rstrip("\n") + f"\n\n## Timeline\n\n{entry}\n"
    nxt = re.search(r"^## ", text[m.end() :], re.M)
    end = m.end() + nxt.start() if nxt else len(text)
    section = text[m.end() : end].rstrip("\n")
    return text[: m.end()] + section + "\n" + entry + "\n" + ("\n" + text[end:] if nxt else "")


def progress(text: str) -> dict:
    result: dict = {}
    current = None
    for line in text.splitlines():
        h = re.match(r"^## (\w+)", line)
        if h:
            current = h.group(1) if h.group(1) in PHASES else None
            if current:
                result[current] = {"done": 0, "open": []}
            continue
        if current:
            m = re.match(r"^\s*- \[( |x|X)\] (.+)$", line)
            if m:
                if m.group(1) == " ":
                    result[current]["open"].append(m.group(2).strip())
                else:
                    result[current]["done"] += 1
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Create and maintain a Markdown incident record.")
    sub = p.add_subparsers(dest="command", required=True)
    n = sub.add_parser("new", help="create a new incident record")
    n.add_argument("--type", choices=sorted(CHECKLISTS), required=True)
    n.add_argument("--title", required=True)
    n.add_argument("--severity", default="TBD", help="e.g. SEV1, SEV2, SEV3")
    n.add_argument("--out", type=Path, default=Path("."), help="directory for the record (default .)")
    n.add_argument("--now", help="override the current UTC time (ISO 8601), for tests")
    a = sub.add_parser("add", help="append a timestamped timeline entry")
    a.add_argument("file", type=Path)
    a.add_argument("message")
    a.add_argument("--now", help="override the current UTC time (ISO 8601)")
    c = sub.add_parser("check", help="show checklist progress; exit 1 while items are open")
    c.add_argument("file", type=Path)
    c.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)

    try:
        if args.command == "new":
            now = utc_now(args.now)
            args.out.mkdir(parents=True, exist_ok=True)
            path = args.out / f"incident-{now.strftime('%Y%m%d-%H%M')}-{slugify(args.title)}.md"
            if path.exists():
                print(f"error: {path} already exists", file=sys.stderr)
                return 2
            path.write_text(render(args.type, args.title, args.severity, now), encoding="utf-8")
            print(path)
            return 0
        if args.command == "add":
            text = args.file.read_text(encoding="utf-8")
            args.file.write_text(add_entry(text, args.message, utc_now(args.now)), encoding="utf-8")
            print(f"added to {args.file}")
            return 0
        prog = progress(args.file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    open_items = sum(len(v["open"]) for v in prog.values())
    if args.json:
        print(json.dumps({"open": open_items, "phases": prog}, indent=2))
    else:
        for phase, v in prog.items():
            total = v["done"] + len(v["open"])
            print(f"{phase:10} {v['done']}/{total} done")
            for item in v["open"]:
                print(f"  [ ] {item}")
        print(f"{open_items} open item(s)")
    return 1 if open_items else 0


if __name__ == "__main__":
    sys.exit(main())
