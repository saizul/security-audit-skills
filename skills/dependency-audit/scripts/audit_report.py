#!/usr/bin/env python3
"""Turn npm audit, pip-audit and composer audit JSON into one prioritized fix plan.

Supported inputs (format is detected automatically):
  npm audit --json          (npm 7+ "auditReportVersion": 2, and legacy npm 6 "advisories")
  pip-audit -f json         (object with "dependencies", or the older top-level list)
  composer audit --format=json

Priorities:
  P1 fix now      critical/high with a fix available
  P2 this sprint  critical/high without a fix (mitigate or replace), medium with a fix,
                  or unknown severity (pip-audit reports none: look it up and re-rank)
  P3 track        everything else (low, or medium without a fix)

Read-only: the script never runs the package managers. Exit codes: 0 = nothing at or
above --fail-on, 1 = findings at or above --fail-on, 2 = unreadable or unknown input.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEV_ORDER = ["unknown", "low", "medium", "high", "critical"]
SEV_ALIASES = {"moderate": "medium", "info": "low", "none": "low", "": "unknown"}


@dataclass
class Vuln:
    ecosystem: str
    package: str
    severity: str
    ids: list[str] = field(default_factory=list)
    title: str = ""
    url: str = ""
    installed: str = ""
    affected: str = ""
    fix: str | None = None  # version, "available", or None
    breaking_fix: bool = False
    direct: bool | None = None
    via: list[str] = field(default_factory=list)
    priority: str = ""


def norm_sev(value) -> str:
    s = str(value or "").strip().lower()
    s = SEV_ALIASES.get(s, s)
    return s if s in SEV_ORDER else "unknown"


def detect(data) -> str:
    if isinstance(data, list):
        if not data or (isinstance(data[0], dict) and "vulns" in data[0]):
            return "pip-audit"
    if isinstance(data, dict):
        if "auditReportVersion" in data or (
            "vulnerabilities" in data and isinstance(data["vulnerabilities"], dict)
        ):
            return "npm"
        if "dependencies" in data and isinstance(data["dependencies"], list):
            return "pip-audit"
        adv = data.get("advisories")
        if isinstance(adv, dict) and adv:
            first = next(iter(adv.values()))
            if isinstance(first, dict) and "module_name" in first:
                return "npm-legacy"
            return "composer"
        if "advisories" in data or "abandoned" in data:
            return "composer"
    raise ValueError("unrecognised audit JSON (expected npm audit, pip-audit or composer audit output)")


def parse_npm(data: dict) -> list[Vuln]:
    out = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        ids, titles, urls, via_pkgs = [], [], [], []
        sev = norm_sev(v.get("severity"))
        for item in v.get("via") or []:
            if isinstance(item, dict):
                src = item.get("source")
                url = item.get("url") or ""
                ghsa = url.rsplit("/", 1)[-1] if "GHSA-" in url else ""
                ids.append(ghsa or (f"npm:{src}" if src is not None else ""))
                if item.get("title"):
                    titles.append(item["title"])
                if url:
                    urls.append(url)
                if norm_sev(item.get("severity")) not in ("unknown",) and SEV_ORDER.index(
                    norm_sev(item.get("severity"))
                ) > SEV_ORDER.index(sev):
                    sev = norm_sev(item.get("severity"))
            else:
                via_pkgs.append(str(item))
        fa = v.get("fixAvailable")
        fix, breaking = None, False
        if fa is True:
            fix = "available"
        elif isinstance(fa, dict):
            fix = f"{fa.get('name', name)}@{fa.get('version', '?')}"
            breaking = bool(fa.get("isSemVerMajor"))
        title = "; ".join(dict.fromkeys(titles)) or (f"via {', '.join(via_pkgs)}" if via_pkgs else "")
        out.append(
            Vuln(
                ecosystem="npm",
                package=name,
                severity=sev,
                ids=[i for i in dict.fromkeys(ids) if i],
                title=title,
                url=urls[0] if urls else "",
                affected=str(v.get("range") or ""),
                fix=fix,
                breaking_fix=breaking,
                direct=v.get("isDirect"),
                via=via_pkgs,
            )
        )
    return out


def parse_npm_legacy(data: dict) -> list[Vuln]:
    out = []
    for adv in (data.get("advisories") or {}).values():
        patched = str(adv.get("patched_versions") or "")
        findings = adv.get("findings") or [{}]
        versions = sorted({f.get("version", "") for f in findings if f.get("version")})
        out.append(
            Vuln(
                ecosystem="npm",
                package=adv.get("module_name", "?"),
                severity=norm_sev(adv.get("severity")),
                ids=[str(c) for c in adv.get("cves") or []] or [f"npm:{adv.get('id', '?')}"],
                title=adv.get("title", ""),
                url=adv.get("url", ""),
                installed=", ".join(versions),
                affected=str(adv.get("vulnerable_versions") or ""),
                fix=f"{adv.get('module_name', '?')}@{patched}" if patched and patched != "<0.0.0" else None,
            )
        )
    return out


def parse_pip(data) -> list[Vuln]:
    deps = data if isinstance(data, list) else data.get("dependencies") or []
    out = []
    for dep in deps:
        for v in dep.get("vulns") or []:
            fixes = v.get("fix_versions") or []
            ids = [v.get("id", "")] + list(v.get("aliases") or [])
            desc = (v.get("description") or "").strip().splitlines()
            out.append(
                Vuln(
                    ecosystem="pypi",
                    package=dep.get("name", "?"),
                    severity=norm_sev(v.get("severity")),
                    ids=[i for i in dict.fromkeys(ids) if i],
                    title=desc[0][:160] if desc else "",
                    url=f"https://osv.dev/vulnerability/{v.get('id')}" if v.get("id") else "",
                    installed=str(dep.get("version", "")),
                    fix=fixes[0] if fixes else None,
                )
            )
    return out


def parse_composer(data: dict) -> list[Vuln]:
    out = []
    adv = data.get("advisories") or {}
    if isinstance(adv, list):  # composer prints [] when there are none
        adv = {}
    for pkg, items in adv.items():
        if isinstance(items, dict):  # some versions key advisories by index
            items = list(items.values())
        for a in items:
            ids = [a.get("advisoryId", ""), a.get("cve") or ""]
            out.append(
                Vuln(
                    ecosystem="composer",
                    package=a.get("packageName", pkg),
                    severity=norm_sev(a.get("severity")),
                    ids=[i for i in ids if i],
                    title=a.get("title", ""),
                    url=a.get("link", ""),
                    affected=str(a.get("affectedVersions", "")),
                    fix="available",  # composer audit does not report the fixed version
                )
            )
    for pkg, replacement in (data.get("abandoned") or {}).items():
        out.append(
            Vuln(
                ecosystem="composer",
                package=pkg,
                severity="low",
                ids=["abandoned"],
                title="package is abandoned"
                + (f"; use {replacement}" if isinstance(replacement, str) and replacement else ""),
                fix=replacement if isinstance(replacement, str) and replacement else None,
            )
        )
    return out


PARSERS = {
    "npm": parse_npm,
    "npm-legacy": parse_npm_legacy,
    "pip-audit": parse_pip,
    "composer": parse_composer,
}


def prioritize(v: Vuln) -> str:
    high = v.severity in ("critical", "high")
    if high and v.fix:
        return "P1"
    if high or v.severity == "unknown" or (v.fix and v.severity == "medium"):
        return "P2"
    return "P3"


def fix_command(v: Vuln) -> str:
    if v.ecosystem == "npm":
        if v.fix and v.fix != "available":
            note = "   # semver-major upgrade: read the changelog and test" if v.breaking_fix else ""
            return f"npm install {shlex.quote(v.fix)}{note}"
        if v.fix:
            return "npm audit fix"
        return "no fix yet: check for an override (npm overrides) or replace the dependency"
    if v.ecosystem == "pypi":
        if v.fix:
            return f"pip install {shlex.quote(v.package + '>=' + v.fix)}  (then update requirements/lock)"
        return "no fixed release: pin away from affected versions, mitigate or replace"
    if v.ecosystem == "composer":
        if "abandoned" in v.ids:
            return f"replace with {v.fix}" if v.fix else "find a maintained replacement"
        return f"composer update {shlex.quote(v.package)} --with-all-dependencies"
    return ""


def analyse(docs: list) -> list[Vuln]:
    vulns: list[Vuln] = []
    for data in docs:
        vulns.extend(PARSERS[detect(data)](data))
    for v in vulns:
        v.priority = prioritize(v)
    vulns.sort(
        key=lambda v: (v.priority, -SEV_ORDER.index(v.severity), not bool(v.direct), v.ecosystem, v.package)
    )
    return vulns


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Prioritize npm audit / pip-audit / composer audit JSON into a fix plan.",
        epilog="Example: npm audit --json > npm.json; pip-audit -f json > pip.json; "
        "audit_report.py npm.json pip.json",
    )
    p.add_argument("files", nargs="+", help="audit JSON files, or - for stdin")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "any", "none"],
        default="high",
        help="exit 1 if a finding has at least this severity (default: high)",
    )
    args = p.parse_args(argv)

    docs = []
    for f in args.files:
        try:
            text = sys.stdin.read() if f == "-" else Path(f).read_text(encoding="utf-8")
            data = json.loads(text)
            detect(data)
            docs.append(data)
        except (OSError, ValueError) as exc:
            print(f"error: {f}: {exc}", file=sys.stderr)
            return 2
    vulns = analyse(docs)

    if args.json:
        print(json.dumps({"count": len(vulns), "findings": [asdict(v) for v in vulns]}, indent=2))
    else:
        by_p = {k: [v for v in vulns if v.priority == k] for k in ("P1", "P2", "P3")}
        print(
            f"dependency audit: {len(vulns)} finding(s) - "
            f"P1 {len(by_p['P1'])}, P2 {len(by_p['P2'])}, P3 {len(by_p['P3'])}"
        )
        labels = {"P1": "P1 fix now", "P2": "P2 this sprint", "P3": "P3 track"}
        for key, items in by_p.items():
            if not items:
                continue
            print(f"\n== {labels[key]} ==")
            for v in items:
                direct = {True: "direct", False: "transitive", None: ""}[v.direct]
                ver = f" {v.installed}" if v.installed else (f" ({v.affected})" if v.affected else "")
                print(f"- [{v.severity}] {v.ecosystem}:{v.package}{ver} {direct}".rstrip())
                if v.title:
                    print(f"    {v.title}")
                if v.ids:
                    print(f"    ids: {', '.join(v.ids[:4])}")
                print(f"    fix: {fix_command(v)}")
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if vulns else 0
    threshold = SEV_ORDER.index(args.fail_on)
    return 1 if any(SEV_ORDER.index(v.severity) >= threshold for v in vulns) else 0


if __name__ == "__main__":
    sys.exit(main())
