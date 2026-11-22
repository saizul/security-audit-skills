#!/usr/bin/env python3
"""Lint Dockerfiles / Containerfiles for security problems. Read-only, offline.

Checks (per final stage unless noted):
  DF001 base image unpinned (no tag or :latest)            medium
  DF002 container runs as root (no USER, or USER root/0)   medium
  DF003 secret in ENV/ARG (value never printed)            high / medium
  DF004 ADD from a URL (no integrity check)                medium; ADD of plain files  low
  DF005 remote script piped to a shell (curl | sh)         medium
  DF006 secret files copied into the image (.env, keys)    high
  DF007 TLS verification disabled (curl -k, pip --trusted-host, ...)  medium
  DF008 chmod 777 / world-writable                         medium; sudo in RUN  low
  DF009 EXPOSE 22 (sshd in a container)                    low
  DF010 COPY . with no .dockerignore next to the Dockerfile low
  DF011 RUN --security=insecure                            medium
  DF012 no HEALTHCHECK                                     info

Paths may be Dockerfiles or directories (searched for Dockerfile, *.Dockerfile,
Dockerfile.*, Containerfile). Exit codes: 0 = nothing at or above --fail-on,
1 = findings, 2 = error.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high"]
SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH|DSN|"
    r"CONNECTION_?STRING|NPM_?TOKEN|GITHUB_?TOKEN|PAT)$|^(AWS_SECRET|DATABASE_URL)",
    re.I,
)
NOT_SECRET_NAME_RE = re.compile(r"(_FILE|_PATH|_DIR|_URL_?PATH|_LENGTH|_TTL|_HEADER|_NAME|_USER)$", re.I)
SECRET_FILE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials*",
    "*.p12",
    "*.pfx",
    ".aws",
    ".aws/*",
    ".ssh",
    ".ssh/*",
    ".docker/config.json",
    "service-account*.json",
]
SAFE_FILE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".pub")
ARCHIVE_RE = re.compile(r"\.(tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar\.zst)$", re.I)
TLS_OFF_RE = re.compile(
    r"(curl\b[^|;&]*\s(-k|--insecure)\b|wget\b[^|;&]*--no-check-certificate|--trusted-host\b|"
    r"strict-ssl\s+false|sslverify\s*=?\s*false|http\.sslVerify\s+false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|"
    r"PYTHONHTTPSVERIFY\s*=\s*0|--index-url\s+http://|--extra-index-url\s+http://|"
    r"GIT_SSL_NO_VERIFY\s*=\s*(1|true))",
    re.I,
)
PIPE_SH_RE = re.compile(r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|ash|dash|python3?|perl)\b")
DF_NAMES = ("Dockerfile", "Containerfile", "*.Dockerfile", "*.dockerfile", "Dockerfile.*", "Containerfile.*")


@dataclass
class Instruction:
    line: int
    cmd: str
    args: str
    flags: list


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    fix: str


def parse(text: str) -> list[Instruction]:
    escape = "\\"
    lines = text.splitlines()
    for raw in lines[:5]:
        m = re.match(r"^\s*#\s*escape\s*=\s*(\S)", raw, re.I)
        if m:
            escape = m.group(1)
    out: list[Instruction] = []
    buf, start = "", 0
    for i, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # comment lines inside a continuation are ignored by Docker
        if not buf:
            start = i
        if stripped.endswith(escape):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        m = re.match(r"^(\w+)\s*(.*)$", buf, re.S)
        if m:
            args = m.group(2).strip()
            flags = []
            while True:
                fm = re.match(r"^--(\S+)\s*", args)
                if not fm:
                    break
                flags.append(fm.group(1))
                args = args[fm.end() :]
            out.append(Instruction(start, m.group(1).upper(), args, flags))
        buf = ""
    return out


def split_stages(instrs: list[Instruction]) -> tuple[list[Instruction], list[list[Instruction]]]:
    """Return (global instructions before the first FROM, stages each starting with FROM)."""
    preamble: list[Instruction] = []
    stages: list[list[Instruction]] = []
    for ins in instrs:
        if ins.cmd == "FROM":
            stages.append([])
        (stages[-1] if stages else preamble).append(ins)
    return preamble, stages


def image_problem(image: str, aliases: set[str]) -> str | None:
    if image.lower() == "scratch" or image in aliases:
        return None
    if "$" in image:
        return "variable"
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    if last.rsplit(":", 1)[1] == "latest":
        return "latest"
    return None


def kv_pairs(args: str) -> list[tuple[str, str | None]]:
    """Parse ENV/ARG arguments into (name, value or None)."""
    try:
        tokens = shlex.split(args, posix=True)
    except ValueError:
        tokens = args.split()
    if not tokens:
        return []
    if "=" not in tokens[0] and len(tokens) >= 2:  # legacy: ENV NAME value with spaces
        return [(tokens[0], " ".join(tokens[1:]))]
    pairs: list[tuple[str, str | None]] = []
    for t in tokens:
        name, sep, value = t.partition("=")
        pairs.append((name, value if sep else None))
    return pairs


def is_secret_file(src: str) -> bool:
    src = src.rstrip("/")
    name = src.rsplit("/", 1)[-1]
    if name.endswith(SAFE_FILE_SUFFIXES):
        return False
    return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(src, p) for p in SECRET_FILE_PATTERNS)


def copy_sources(args: str) -> list[str]:
    args = args.strip()
    if args.startswith("["):
        try:
            parts = json.loads(args)
        except ValueError:
            parts = []
    else:
        try:
            parts = shlex.split(args)
        except ValueError:
            parts = args.split()
    return [str(p) for p in parts[:-1]] if len(parts) >= 2 else []


def lint(text: str, path: str = "Dockerfile", context_dir: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    instrs = parse(text)

    def add(ins_line, rule, sev, msg, fix):
        findings.append(Finding(path, ins_line, rule, sev, msg, fix))

    if not any(i.cmd == "FROM" for i in instrs):
        add(0, "DF000", "info", "no FROM instruction found", "check that this is a Dockerfile")
        return findings
    preamble, stages = split_stages(instrs)
    aliases: set[str] = set()
    for idx, stage in enumerate(stages):
        final = idx == len(stages) - 1
        frm = stage[0]
        parts = frm.args.split()
        image = parts[0] if parts else ""
        problem = image_problem(image, aliases)
        if len(parts) >= 3 and parts[1].upper() == "AS":
            aliases.add(parts[2])
        if problem in ("untagged", "latest"):
            add(
                frm.line,
                "DF001",
                "medium",
                f"base image '{image}' is {'not tagged' if problem == 'untagged' else ':latest'}",
                "pin a version tag and ideally a digest: FROM image:1.2.3@sha256:...",
            )
        elif problem == "variable":
            add(
                frm.line,
                "DF001",
                "info",
                f"base image comes from a build arg ({image})",
                "give the ARG a pinned default",
            )

        for ins in preamble + stage if idx == 0 else stage:
            if ins.cmd in ("ENV", "ARG"):
                for name, value in kv_pairs(ins.args):
                    if not SECRET_NAME_RE.search(name) or NOT_SECRET_NAME_RE.search(name):
                        continue
                    if ins.cmd == "ENV" and value:
                        literal = not re.fullmatch(r"\$\{?\w+\}?", value)
                        add(
                            ins.line,
                            "DF003",
                            "high" if literal else "medium",
                            f"ENV {name} bakes a secret into the image"
                            + ("" if literal else " (from a build arg; still stored in the image)"),
                            "pass it at runtime (docker run -e / compose secrets) or use "
                            "RUN --mount=type=secret,id=...",
                        )
                    elif ins.cmd == "ARG":
                        add(
                            ins.line,
                            "DF003",
                            "high" if value else "medium",
                            f"ARG {name} {'has a default secret value' if value else 'passes a secret'}; "
                            "build args are visible in image history",
                            "use BuildKit secrets: RUN --mount=type=secret,id=" + name.lower(),
                        )
            elif ins.cmd == "ADD":
                srcs = copy_sources(ins.args)
                if any(re.match(r"^(https?|git)://|^git@", s) for s in srcs):
                    has_checksum = any(f.startswith("checksum=") for f in ins.flags)
                    if not has_checksum:
                        add(
                            ins.line,
                            "DF004",
                            "medium",
                            "ADD downloads from a URL without an integrity check",
                            "ADD --checksum=sha256:... URL, or RUN curl -fsSL ... && sha256sum -c",
                        )
                elif srcs and not all(ARCHIVE_RE.search(s) for s in srcs):
                    add(
                        ins.line,
                        "DF004",
                        "low",
                        "ADD used for plain files",
                        "use COPY (ADD auto-extracts archives)",
                    )
                if any(is_secret_file(s) for s in srcs):
                    add(
                        ins.line,
                        "DF006",
                        "high",
                        "secret file added to the image",
                        "mount it at runtime instead",
                    )
            elif ins.cmd == "COPY":
                srcs = copy_sources(ins.args)
                if any(is_secret_file(s) for s in srcs):
                    add(
                        ins.line,
                        "DF006",
                        "high",
                        "secret file copied into the image: "
                        + ", ".join(s for s in srcs if is_secret_file(s)),
                        "use RUN --mount=type=secret or runtime secrets; add the file to .dockerignore",
                    )
                if (
                    any(s in (".", "./") for s in srcs)
                    and not any(f.startswith("from=") for f in ins.flags)
                    and context_dir is not None
                    and not (context_dir / ".dockerignore").exists()
                ):
                    add(
                        ins.line,
                        "DF010",
                        "low",
                        "COPY . without a .dockerignore may ship .git, .env and local secrets",
                        "add .dockerignore with .git, .env*, *.pem, node_modules, ...",
                    )
            elif ins.cmd == "RUN":
                if PIPE_SH_RE.search(ins.args):
                    add(
                        ins.line,
                        "DF005",
                        "medium",
                        "remote script piped straight into an interpreter",
                        "download, verify a checksum or signature, then run it",
                    )
                if TLS_OFF_RE.search(ins.args):
                    add(
                        ins.line,
                        "DF007",
                        "medium",
                        "TLS certificate verification is disabled",
                        "remove the flag; add the CA instead",
                    )
                if re.search(r"\bchmod\s+(-R\s+)?(0?777|a\+w|o\+w)\b", ins.args):
                    add(
                        ins.line,
                        "DF008",
                        "medium",
                        "world-writable permissions",
                        "grant only what the app user needs",
                    )
                if re.search(r"(^|[;&|]\s*)sudo\b", ins.args):
                    add(
                        ins.line,
                        "DF008",
                        "low",
                        "sudo in RUN (builds already run as root)",
                        "drop sudo; switch USER explicitly",
                    )
                if any(f.startswith("security=insecure") for f in ins.flags):
                    add(ins.line, "DF011", "medium", "RUN --security=insecure", "remove it")
                if re.search(r"(?i)(password|secret|token|api_?key)\s*=\s*['\"]?[^\s'\"$]{6,}", ins.args):
                    add(
                        ins.line,
                        "DF003",
                        "high",
                        "RUN contains a literal credential (stored in the layer and history)",
                        "use RUN --mount=type=secret",
                    )
            elif ins.cmd == "EXPOSE" and final:
                ports = {p.split("/")[0] for p in ins.args.split()}
                if "22" in ports:
                    add(
                        ins.line,
                        "DF009",
                        "low",
                        "EXPOSE 22: SSH server inside a container",
                        "use docker exec / kubectl exec",
                    )

        if final:
            users = [i for i in stage if i.cmd == "USER"]
            if not users:
                add(
                    frm.line,
                    "DF002",
                    "medium",
                    "final stage has no USER, so the container runs as root",
                    "create an unprivileged user and add USER app (or a numeric UID such as 10001)",
                )
            else:
                last = users[-1].args.split(":")[0].strip()
                if last in ("root", "0"):
                    add(
                        users[-1].line,
                        "DF002",
                        "medium",
                        "final USER is root",
                        "switch to an unprivileged USER",
                    )
            if not any(i.cmd == "HEALTHCHECK" for i in stage):
                add(
                    frm.line,
                    "DF012",
                    "info",
                    "no HEALTHCHECK",
                    "add HEALTHCHECK CMD ... (or define it in compose/k8s)",
                )
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.line))
    return findings


def find_dockerfiles(base: Path) -> list[Path]:
    if base.is_file():
        return [base]
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "node_modules", "vendor", ".venv"})
        for fn in sorted(filenames):
            if any(fnmatch.fnmatch(fn, pat) for pat in DF_NAMES) and not fn.endswith(".dockerignore"):
                out.append(Path(dirpath) / fn)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Lint Dockerfiles for security problems (root user, unpinned images, secrets, ADD URLs).",
        epilog="Example: dockerfile_lint.py . --json",
    )
    p.add_argument("paths", nargs="*", default=["."], help="Dockerfiles or directories (default: .)")
    p.add_argument("--context", type=Path, help="build context dir for the .dockerignore check")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="medium")
    p.add_argument("--json", action="store_true", help="print JSON")
    args = p.parse_args(argv)
    files: list[Path] = []
    for x in args.paths:
        path = Path(x)
        if not path.exists():
            print(f"error: {x} does not exist", file=sys.stderr)
            return 2
        files += find_dockerfiles(path)
    if not files:
        print("error: no Dockerfile found", file=sys.stderr)
        return 2
    findings: list[Finding] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        findings += lint(text, f.as_posix(), args.context or f.parent)
    if args.json:
        print(
            json.dumps(
                {"files": [f.as_posix() for f in files], "findings": [asdict(x) for x in findings]}, indent=2
            )
        )
    else:
        counts = {s: sum(1 for x in findings if x.severity == s) for s in reversed(SEVERITIES)}
        print(f"dockerfile lint: {len(files)} file(s), " + ", ".join(f"{n} {s}" for s, n in counts.items()))
        for x in findings:
            print(f"{x.severity.upper():6} {x.path}:{x.line}  {x.rule} {x.message}\n       fix: {x.fix}")
    if args.fail_on == "none":
        return 0
    t = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(x.severity) >= t for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
