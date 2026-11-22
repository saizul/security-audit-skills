#!/usr/bin/env python3
"""Scan a directory or files for hardcoded secrets. Read-only; never prints a full secret.

Detects provider tokens (AWS, GitHub, GitLab, Slack, Stripe, Google, npm, SendGrid,
OpenAI/Anthropic-style keys), private key blocks, JWTs, credentials in URLs, and
high-entropy values assigned to secret-like names (password, token, api_key, ...).
Also flags sensitive files (.env, id_rsa, *.pem, terraform.tfstate, ...).

Matches are shown redacted: the first 4 characters, the length and a fingerprint.
Lines containing "secrets-scan:allow" or "gitleaks:allow" are skipped unless
--no-inline-allow is given. Use --baseline to ignore known, accepted findings.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = error.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high"]
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".terraform",
}
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".jar",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp4",
    ".mp3",
    ".lock",
    ".min.js",
    ".map",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock"}
ALLOW_MARKERS = ("secrets-scan:allow", "gitleaks:allow")
# Published documentation examples (AWS docs). Skipped unless --include-examples.
KNOWN_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
PLACEHOLDER_RE = re.compile(
    r"^(\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{.*\}\}|\{[A-Za-z_][\w.]*\}|<[^>]+>|%\(?[A-Za-z_]+\)?s?|x{4,}|\*{3,}|\.{3,})$"
    r"|(change.?me|example|placeholder|dummy|sample|your[_-]|redacted|fake|not.?a.?real|test[_-]?only)",
    re.I,
)
CODE_REF_RE = re.compile(
    r"(os\.environ|os\.getenv|getenv\(|process\.env|ENV\[|env\(|config\(|settings\.|\$_ENV|"
    r"System\.getenv|secrets\.|vault:|ssm:|arn:aws)",
    re.I,
)

# (rule id, severity, regex, group holding the secret, needs entropy check)
RULES = [
    ("aws-access-key-id", "high", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", 1, False),
    (
        "aws-secret-access-key",
        "high",
        r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        1,
        True,
    ),
    ("github-token", "high", r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b", 1, False),
    ("github-fine-grained-pat", "high", r"\b(github_pat_[A-Za-z0-9_]{60,255})\b", 1, False),
    ("gitlab-token", "high", r"\b(glpat-[A-Za-z0-9_-]{20,})\b", 1, False),
    ("slack-token", "high", r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b", 1, False),
    (
        "slack-webhook",
        "medium",
        r"(https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+)",
        1,
        False,
    ),
    ("stripe-live-key", "high", r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b", 1, False),
    ("stripe-test-key", "low", r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b", 1, False),
    ("google-api-key", "high", r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])", 1, False),
    ("npm-token", "high", r"\b(npm_[A-Za-z0-9]{36})\b", 1, False),
    ("sendgrid-api-key", "high", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])", 1, False),
    ("anthropic-api-key", "high", r"\b(sk-ant-[A-Za-z0-9_-]{20,})", 1, False),
    ("openai-api-key", "high", r"(?<![A-Za-z0-9_-])(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,})", 1, True),
    (
        "private-key",
        "high",
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        1,
        False,
    ),
    (
        "jwt",
        "medium",
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        1,
        False,
    ),
    (
        "url-credentials",
        "medium",
        r"\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@'\"]{1,64}:([^/\s:@'\"]{3,128})@[A-Za-z0-9.-]+",
        1,
        False,
    ),
    (
        "generic-secret",
        "medium",
        r"(?i)\b[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
        r"auth[_-]?key|client[_-]?secret|private[_-]?key|credentials?)[A-Za-z0-9_.-]*['\"]?\s*(?::=|=>|[:=])\s*"
        r"['\"]?([^\s'\"`,;)}\]]{8,200})",
        1,
        True,
    ),
]
COMPILED = [(rid, sev, re.compile(rx), grp, ent) for rid, sev, rx, grp, ent in RULES]

SENSITIVE_FILES = [
    (".env", "medium", "dotenv file with real values"),
    (".env.*", "medium", "dotenv file with real values"),
    ("id_rsa", "high", "SSH private key"),
    ("id_dsa", "high", "SSH private key"),
    ("id_ecdsa", "high", "SSH private key"),
    ("id_ed25519", "high", "SSH private key"),
    ("*.pem", "medium", "PEM file (may hold a private key)"),
    ("*.key", "medium", "key file"),
    ("*.p12", "high", "PKCS#12 keystore"),
    ("*.pfx", "high", "PKCS#12 keystore"),
    ("*.jks", "medium", "Java keystore"),
    ("*.keystore", "medium", "keystore"),
    ("terraform.tfstate", "high", "Terraform state (contains resource secrets)"),
    ("terraform.tfstate.backup", "high", "Terraform state (contains resource secrets)"),
    ("credentials.json", "medium", "credentials file"),
    ("service-account*.json", "medium", "cloud service account key"),
    (".htpasswd", "medium", "password hashes"),
    (".pgpass", "high", "PostgreSQL password file"),
    (".netrc", "high", "netrc credentials"),
    ("wp-config.php", "low", "WordPress config (DB password, salts) - make sure it is not committed"),
]
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    redacted: str
    length: int
    fingerprint: str
    entropy: float | None = None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep + 4:
        return value[:2] + "*" * 6
    return value[:keep] + "*" * 8


def fingerprint(rule: str, value: str) -> str:
    return hashlib.sha256(f"{rule}:{value}".encode()).hexdigest()[:16]


def looks_like_placeholder(value: str) -> bool:
    v = value.strip("'\"")
    if PLACEHOLDER_RE.search(v):
        return True
    if len(set(v)) <= 3:
        return True
    if v.lower() in {
        "true",
        "false",
        "null",
        "none",
        "undefined",
        "required",
        "optional",
        "password",
        "passwd",
        "secret",
        "token",
        "pass",
        "pwd",
    }:
        return True
    return False


CODE_VALUE_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


def looks_like_code(value: str) -> bool:
    """Variable references, attribute access and calls are not literal secrets."""
    if value.startswith(("$", "@", "&", "!", "%")) or "(" in value or "[" in value:
        return True
    return bool(CODE_VALUE_RE.match(value))


def scan_text(
    text: str,
    path: str = "-",
    min_entropy: float = 3.5,
    inline_allow: bool = True,
    include_examples: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if inline_allow and any(m in line for m in ALLOW_MARKERS):
            continue
        if len(line) > 4000:
            line = line[:4000]
        seen_spans: list[tuple[int, int]] = []
        for rid, sev, rx, grp, needs_entropy in COMPILED:
            for m in rx.finditer(line):
                value = m.group(grp)
                start, end = m.span(grp)
                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue
                if not include_examples and value in KNOWN_EXAMPLES:
                    continue
                ent = None
                if rid in ("generic-secret", "url-credentials"):
                    if looks_like_placeholder(value) or CODE_REF_RE.search(value):
                        continue
                    if rid == "generic-secret" and looks_like_code(value):
                        continue
                if needs_entropy:
                    ent = round(shannon_entropy(value), 2)
                    if ent < min_entropy:
                        continue
                seen_spans.append((start, end))
                findings.append(
                    Finding(
                        path=path,
                        line=lineno,
                        rule=rid,
                        severity=sev,
                        redacted=value if rid == "private-key" else redact(value),
                        length=len(value),
                        fingerprint=fingerprint(rid, value),
                        entropy=ent,
                    )
                )
    return findings


def sensitive_file_finding(path: Path, shown: str) -> Finding | None:
    name = path.name
    if name.endswith(SAFE_ENV_SUFFIXES):
        return None
    for pattern, sev, desc in SENSITIVE_FILES:
        if fnmatch.fnmatch(name, pattern):
            return Finding(
                path=shown,
                line=0,
                rule="sensitive-file",
                severity=sev,
                redacted=desc,
                length=0,
                fingerprint=fingerprint("sensitive-file", shown),
            )
    return None


def is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(8192)
    except OSError:
        return True


def iter_files(paths: list[Path], excludes: list[str]):
    for base in paths:
        if base.is_file():
            yield base, base
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                rel = p.relative_to(base).as_posix()
                if any(fnmatch.fnmatch(rel, ex) or fnmatch.fnmatch(fn, ex) for ex in excludes):
                    continue
                yield p, base


def scan_paths(
    paths: list[Path],
    excludes: list[str] | None = None,
    max_bytes: int = 1_000_000,
    **kwargs,
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    count = 0
    for p, base in iter_files(paths, excludes or []):
        shown = p.as_posix() if base == p else (Path(base.name) / p.relative_to(base)).as_posix()
        sf = sensitive_file_finding(p, shown)
        if sf:
            findings.append(sf)
        lower = p.name.lower()
        if p.name in SKIP_FILES or any(lower.endswith(s) for s in SKIP_SUFFIXES):
            continue
        try:
            if p.stat().st_size > max_bytes or is_binary(p):
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        findings.extend(scan_text(text, shown, **kwargs))
    return findings, count


def load_baseline(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("fingerprints", [])
    return {str(x) for x in data}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Scan files for hardcoded secrets (read-only, output is redacted).",
        epilog="Example: secrets_scan.py . --exclude 'tests/fixtures/*' --json",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths")
    p.add_argument("--min-entropy", type=float, default=3.5, help="entropy threshold for generic values")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="low", help="exit 1 at this severity")
    p.add_argument("--baseline", type=Path, help="JSON list of fingerprints to ignore")
    p.add_argument("--write-baseline", type=Path, help="write current fingerprints to this file and exit 0")
    p.add_argument("--no-inline-allow", action="store_true", help="ignore secrets-scan:allow markers")
    p.add_argument("--include-examples", action="store_true", help="report published documentation keys")
    p.add_argument("--max-bytes", type=int, default=1_000_000, help="skip files larger than this")
    args = p.parse_args(argv)

    paths = [Path(x) for x in args.paths]
    for x in paths:
        if not x.exists():
            print(f"error: {x} does not exist", file=sys.stderr)
            return 2
    findings, scanned = scan_paths(
        paths,
        args.exclude,
        args.max_bytes,
        min_entropy=args.min_entropy,
        inline_allow=not args.no_inline_allow,
        include_examples=args.include_examples,
    )
    if args.write_baseline:
        fps = sorted({f.fingerprint for f in findings})
        args.write_baseline.write_text(json.dumps({"fingerprints": fps}, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {len(fps)} fingerprint(s) to {args.write_baseline}")
        return 0
    if args.baseline:
        try:
            ignore = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 2
        findings = [f for f in findings if f.fingerprint not in ignore]

    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.path, f.line))
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    if args.json:
        print(
            json.dumps(
                {"files_scanned": scanned, "counts": counts, "findings": [asdict(f) for f in findings]},
                indent=2,
            )
        )
    else:
        print(
            f"secrets scan: {scanned} files, "
            + ", ".join(f"{n} {s}" for s, n in counts.items())
            + " (values redacted)"
        )
        for f in findings:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            extra = f" entropy={f.entropy}" if f.entropy is not None else ""
            detail = f.redacted if f.rule == "sensitive-file" else f"{f.redacted} (len {f.length})"
            print(f"{f.severity.upper():6} {loc}  {f.rule}  {detail}  fp={f.fingerprint}{extra}")
    if args.fail_on == "none":
        return 0
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
