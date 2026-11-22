#!/usr/bin/env python3
"""Find code locations that deserve an input-validation review (read-only).

Flags dangerous sinks in Python, JavaScript/TypeScript, PHP, Go, Java/Kotlin and Ruby:
SQL built from strings, shell commands, eval, unsafe deserialization, raw HTML output
(XSS), file paths and outbound URLs built from request data (path traversal, SSRF),
open redirects and XML external entities.

These are review points, not proven vulnerabilities: a human (or the agent) must trace
whether untrusted input reaches each sink. Each finding names the safe pattern to use
(see references/safe-patterns.md).

Suppress a reviewed line with a comment containing "review:ok".
Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high"]
LANG_EXT = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"},
    "php": {".php", ".phtml"},
    "go": {".go"},
    "java": {".java", ".kt"},
    "ruby": {".rb", ".erb"},
    "template": {".html", ".jinja", ".jinja2", ".j2", ".twig", ".njk", ".hbs"},
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "coverage",
    "site-packages",
}
SUPPRESS = "review:ok"

PY_REQ = r"request\.(?:args|form|values|json|GET|POST|data|query_params|files|cookies|headers)"
JS_REQ = r"req\.(?:query|body|params|headers|cookies)"
PHP_REQ = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"
GO_REQ = r"r\.(?:URL|Form|FormValue|PostForm|Header)"
JAVA_REQ = r"request\.getParameter"
RB_REQ = r"params\["

# (id, language, category, severity, regex, safe pattern hint)
RULES = [
    # Python
    (
        "py-sql-fstring",
        "python",
        "sql-injection",
        "high",
        r"\.(?:execute|executemany|raw|extra)\(\s*f[\"']",
        "parameterized query: cur.execute(sql, params)",
    ),
    (
        "py-sql-format",
        "python",
        "sql-injection",
        "high",
        r"\.(?:execute|executemany|raw)\([^)]*(?:[\"']\s*%\s*[\w(]|\.format\(|[\"']\s*\+\s*\w)",
        "parameterized query: cur.execute(sql, params)",
    ),
    (
        "py-sqlalchemy-text-fstring",
        "python",
        "sql-injection",
        "high",
        r"\btext\(\s*f[\"']",
        "text('... :name').bindparams(name=value)",
    ),
    (
        "py-shell-true",
        "python",
        "command-injection",
        "high",
        r"subprocess\.\w+\([^)]*shell\s*=\s*True",
        "subprocess.run([cmd, arg], shell=False)",
    ),
    (
        "py-os-system",
        "python",
        "command-injection",
        "medium",
        r"\bos\.(?:system|popen)\(",
        "subprocess.run([...]) with an argument list",
    ),
    (
        "py-eval",
        "python",
        "code-injection",
        "high",
        r"(?<![\w.])(?:eval|exec)\(\s*(?![\"'])",
        "ast.literal_eval for literals, or a dispatch table",
    ),
    (
        "py-pickle",
        "python",
        "deserialization",
        "high",
        r"\b(?:pickle|cPickle|dill|marshal|shelve)\.loads?\(|\bjsonpickle\.decode\(",
        "json for untrusted data; sign blobs (hmac) if you must unpickle your own",
    ),
    (
        "py-yaml-load",
        "python",
        "deserialization",
        "high",
        r"\byaml\.(?:load|load_all)\((?![^)]*(?:SafeLoader|CSafeLoader))",
        "yaml.safe_load",
    ),
    (
        "py-mark-safe",
        "python",
        "xss",
        "medium",
        r"\b(?:mark_safe|Markup|SafeString)\(",
        "let the template engine escape; sanitize HTML with an allow-list",
    ),
    (
        "py-open-request",
        "python",
        "path-traversal",
        "high",
        rf"\b(?:open|send_file|send_from_directory|FileResponse)\([^)]*{PY_REQ}",
        "resolve the path and check it stays under a base dir (Path.resolve().is_relative_to)",
    ),
    (
        "py-requests-var",
        "python",
        "ssrf",
        "low",
        r"\b(?:requests|httpx)\.(?:get|post|put|delete|head|request)\(\s*(?![\"'])",
        "allow-list hosts, block private/link-local IPs after DNS resolution",
    ),
    (
        "py-urlopen-var",
        "python",
        "ssrf",
        "low",
        r"\burlopen\(\s*(?![\"'])",
        "allow-list hosts, block private/link-local IPs after DNS resolution",
    ),
    (
        "py-redirect-request",
        "python",
        "open-redirect",
        "medium",
        rf"\bredirect\(\s*{PY_REQ}",
        "redirect only to relative paths or an allow-list (url_has_allowed_host_and_scheme)",
    ),
    (
        "py-xml",
        "python",
        "xxe",
        "low",
        r"\b(?:xml\.dom\.minidom\.parse|xml\.sax\.parse|lxml\.etree\.(?:parse|fromstring|XML))\(",
        "defusedxml, or lxml with resolve_entities=False, no_network=True",
    ),
    # JavaScript / TypeScript
    (
        "js-innerhtml",
        "javascript",
        "xss",
        "medium",
        r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)|\binsertAdjacentHTML\(|\bdocument\.write(?:ln)?\(",
        "textContent / createElement; sanitize with DOMPurify if HTML is required",
    ),
    (
        "js-dangerously-set",
        "javascript",
        "xss",
        "medium",
        r"dangerouslySetInnerHTML|\bv-html\s*=|\{@html\s",
        "render text; sanitize with DOMPurify if HTML is required",
    ),
    (
        "js-eval",
        "javascript",
        "code-injection",
        "high",
        r"(?<![\w.])eval\(\s*(?![\"'`]\s*\))|\bnew\s+Function\(|\bset(?:Timeout|Interval)\(\s*[\"'`]",
        "JSON.parse for data; pass functions, not strings",
    ),
    (
        "js-exec",
        "javascript",
        "command-injection",
        "high",
        r"\b(?:exec|execSync)\(\s*(?:`[^`]*\$\{|[^)]*[\"'`]\s*\+)",
        "execFile/spawn with an argument array and shell: false",
    ),
    (
        "js-spawn-shell",
        "javascript",
        "command-injection",
        "high",
        r"\b(?:spawn|spawnSync|execFile)\([^)]*shell\s*:\s*true",
        "spawn with an argument array and shell: false",
    ),
    (
        "js-sql-template",
        "javascript",
        "sql-injection",
        "high",
        r"\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\(\s*`[^`]*\$\{",
        "placeholders: db.query('... WHERE id = $1', [id]) or tagged templates (sql``, Prisma $queryRaw``)",
    ),
    (
        "js-sql-concat",
        "javascript",
        "sql-injection",
        "high",
        r"\.(?:query|execute|raw)\(\s*[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+",
        "placeholders: db.query('... WHERE id = ?', [id])",
    ),
    (
        "js-fs-request",
        "javascript",
        "path-traversal",
        "high",
        rf"\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|sendFile|download|unlink)\([^)]*{JS_REQ}",
        "path.resolve(base, name) and check it startsWith(base + path.sep); sendFile with root option",
    ),
    (
        "js-fetch-request",
        "javascript",
        "ssrf",
        "medium",
        rf"\b(?:fetch|axios(?:\.\w+)?|got|request|http\.get|https\.get)\(\s*(?:{JS_REQ}|`[^`]*\$\{{\s*{JS_REQ})",
        "allow-list hosts, block private/link-local IPs after DNS resolution",
    ),
    (
        "js-redirect-request",
        "javascript",
        "open-redirect",
        "medium",
        rf"\bres\.redirect\(\s*(?:\d+\s*,\s*)?{JS_REQ}",
        "redirect only to relative paths or an allow-list",
    ),
    (
        "js-unserialize",
        "javascript",
        "deserialization",
        "high",
        r"require\([\"']node-serialize[\"']\)|\bunserialize\(",
        "JSON.parse with schema validation",
    ),
    # PHP
    (
        "php-sql-request",
        "php",
        "sql-injection",
        "high",
        rf"\b(?:mysqli_query|mysql_query|pg_query|->query|->exec|->prepare)\([^;]*{PHP_REQ}",
        "prepared statements: $pdo->prepare('... = ?')->execute([$v])",
    ),
    (
        "php-sql-interp",
        "php",
        "sql-injection",
        "high",
        r"\b(?:mysqli_query|pg_query|->query|->exec)\([^;]*[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*(?:\$\w|[\"']\s*\.\s*\$)",
        "prepared statements with bound parameters; $wpdb->prepare in WordPress",
    ),
    (
        "php-shell",
        "php",
        "command-injection",
        "high",
        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$|`[^`]*\$\w+[^`]*`",
        "avoid the shell; if unavoidable escapeshellarg() every argument",
    ),
    (
        "php-eval",
        "php",
        "code-injection",
        "high",
        r"\beval\s*\(|\bcreate_function\s*\(|\bassert\s*\(\s*\$|preg_replace\s*\(\s*[\"'].*/[a-z]*e[a-z]*[\"']",
        "remove dynamic code; use a dispatch table",
    ),
    (
        "php-include-var",
        "php",
        "path-traversal",
        "high",
        r"\b(?:include|include_once|require|require_once)\s*\(?\s*[^;]*\$",
        "include from a fixed allow-list: $pages = ['home' => 'home.php']",
    ),
    (
        "php-unserialize",
        "php",
        "deserialization",
        "high",
        r"\bunserialize\s*\(",
        "json_decode; or unserialize($x, ['allowed_classes' => false]) for trusted data",
    ),
    (
        "php-echo-request",
        "php",
        "xss",
        "high",
        rf"(?:\becho|\bprint|<\?=)\s*[^;]*{PHP_REQ}",
        "htmlspecialchars($v, ENT_QUOTES, 'UTF-8') / esc_html()",
    ),
    (
        "php-file-request",
        "php",
        "path-traversal",
        "high",
        rf"\b(?:file_get_contents|fopen|readfile|file|unlink|move_uploaded_file)\s*\([^;]*{PHP_REQ}",
        "basename() + realpath() under a base dir; never pass request data to file functions",
    ),
    (
        "php-curl-request",
        "php",
        "ssrf",
        "medium",
        rf"CURLOPT_URL\s*,\s*[^;]*{PHP_REQ}",
        "allow-list hosts, block private IPs, disable redirects",
    ),
    (
        "php-redirect-request",
        "php",
        "open-redirect",
        "medium",
        rf"header\s*\(\s*[\"']Location:[^;]*{PHP_REQ}",
        "redirect to relative paths or wp_safe_redirect / an allow-list",
    ),
    (
        "php-xxe",
        "php",
        "xxe",
        "medium",
        r"LIBXML_NOENT|libxml_disable_entity_loader\s*\(\s*false",
        "do not enable entity substitution",
    ),
    # Go
    (
        "go-sql-sprintf",
        "go",
        "sql-injection",
        "high",
        r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\([^)]*fmt\.Sprintf",
        'db.Query("... WHERE id = $1", id)',
    ),
    (
        "go-sql-concat",
        "go",
        "sql-injection",
        "high",
        r"\.(?:Query|QueryRow|Exec)\(\s*\"[^\"]*\"\s*\+",
        'db.Query("... WHERE id = $1", id)',
    ),
    (
        "go-shell",
        "go",
        "command-injection",
        "high",
        r"exec\.Command(?:Context)?\([^)]*\"(?:sh|bash|cmd|/bin/sh|/bin/bash)\"\s*,\s*\"(?:-c|/c)\"",
        "exec.Command(binary, args...) without a shell",
    ),
    (
        "go-template-html",
        "go",
        "xss",
        "medium",
        r"\btemplate\.(?:HTML|JS|URL|HTMLAttr)\(",
        "let html/template escape; never wrap untrusted input",
    ),
    ("go-text-template", "go", "xss", "low", r"\"text/template\"", "use html/template for HTML output"),
    (
        "go-path-request",
        "go",
        "path-traversal",
        "medium",
        rf"\b(?:os\.Open|os\.ReadFile|http\.ServeFile|filepath\.Join)\([^)]*{GO_REQ}",
        "filepath.Clean + check prefix, or os.Root / http.FS with a fixed root",
    ),
    (
        "go-http-request",
        "go",
        "ssrf",
        "medium",
        rf"\bhttp\.(?:Get|Post|Head)\([^)]*{GO_REQ}",
        "allow-list hosts; custom Dialer that blocks private IPs",
    ),
    # Java / Kotlin
    (
        "java-sql-concat",
        "java",
        "sql-injection",
        "high",
        r"\.(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement)\(\s*\"[^\"]*\"\s*\+",
        "PreparedStatement with ? placeholders / JPA named parameters",
    ),
    (
        "java-runtime-exec",
        "java",
        "command-injection",
        "medium",
        r"Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\([^)]*\"(?:sh|bash|cmd)\"",
        "ProcessBuilder with a fixed binary and separate arguments, no shell",
    ),
    (
        "java-deserialization",
        "java",
        "deserialization",
        "high",
        r"new\s+ObjectInputStream\(|\bXMLDecoder\(|enableDefaultTyping\(|activateDefaultTyping\(",
        "JSON with explicit types; ObjectInputFilter allow-list if Java serialization is unavoidable",
    ),
    (
        "java-xxe",
        "java",
        "xxe",
        "low",
        r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(",
        'disable DTDs: setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
    ),
    (
        "java-file-request",
        "java",
        "path-traversal",
        "high",
        rf"new\s+File(?:InputStream)?\([^)]*{JAVA_REQ}|Paths\.get\([^)]*{JAVA_REQ}",
        "normalize() and check startsWith(baseDir)",
    ),
    # Ruby
    (
        "rb-sql-interp",
        "ruby",
        "sql-injection",
        "high",
        r"\.(?:where|find_by_sql|order|group|having|joins|pluck|select|exec_query|execute)\(\s*\"[^\"]*#\{",
        "where(id: x) or where('id = ?', x); sanitize_sql_for_order",
    ),
    (
        "rb-shell",
        "ruby",
        "command-injection",
        "high",
        r"\b(?:system|exec|spawn|IO\.popen|Open3\.\w+)\(\s*\"[^\"]*#\{|`[^`]*#\{|%x\{[^}]*#\{",
        "system(cmd, arg1, arg2) with separate arguments",
    ),
    (
        "rb-html-safe",
        "ruby",
        "xss",
        "medium",
        r"\.html_safe\b|\braw\(|<%==",
        "let ERB escape; sanitize() with an allow-list",
    ),
    (
        "rb-marshal",
        "ruby",
        "deserialization",
        "high",
        r"\bMarshal\.load\(|\bYAML\.unsafe_load\(|\bOj\.load\(",
        "JSON.parse / YAML.safe_load",
    ),
    (
        "rb-dynamic-dispatch",
        "ruby",
        "code-injection",
        "high",
        rf"\.(?:send|public_send|constantize|safe_constantize)\(\s*{RB_REQ}|\beval\(",
        "map allowed values explicitly: ALLOWED.fetch(params[:x])",
    ),
    (
        "rb-redirect-params",
        "ruby",
        "open-redirect",
        "medium",
        rf"\bredirect_to\s*\(?\s*{RB_REQ}",
        "redirect_to with allow_other_host: false (Rails 7) or an allow-list",
    ),
    # Templates
    (
        "tpl-safe-filter",
        "template",
        "xss",
        "medium",
        r"\|\s*safe\b|\{%\s*autoescape\s+(?:false|off)|\{\{\{[^}]+\}\}\}|\|\s*raw\b|\{!!",
        "keep auto-escaping on; sanitize HTML with an allow-list before marking it safe",
    ),
]
COMPILED = [(rid, lang, cat, sev, re.compile(rx), hint) for rid, lang, cat, sev, rx, hint in RULES]
COMMENT_RE = re.compile(r"^\s*(?:#|//|\*|/\*|<!--)")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    category: str
    severity: str
    code: str
    safe_pattern: str


def language_of(path: Path) -> str | None:
    ext = path.suffix.lower()
    for lang, exts in LANG_EXT.items():
        if ext in exts:
            return lang
    return None


def scan_text(text: str, lang: str, path: str = "-") -> list[Finding]:
    out: list[Finding] = []
    rules = [r for r in COMPILED if r[1] == lang]
    if lang in {"php", "javascript"}:
        # .vue/.svelte/.php files also contain template syntax
        rules += [r for r in COMPILED if r[1] == "template"]
    for lineno, line in enumerate(text.splitlines(), 1):
        if SUPPRESS in line or COMMENT_RE.match(line) or len(line) > 2000:
            continue
        hit_rules = set()
        for rid, _lang, cat, sev, rx, hint in rules:
            if cat in hit_rules:  # one finding per category per line
                continue
            if rx.search(line):
                hit_rules.add(cat)
                code = line.strip()
                out.append(
                    Finding(
                        path, lineno, rid, cat, sev, code[:160] + ("..." if len(code) > 160 else ""), hint
                    )
                )
    return out


def iter_files(paths: list[Path]):
    for base in paths:
        if base.is_file():
            yield base
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                if fn.endswith((".min.js", ".bundle.js")):
                    continue
                yield Path(dirpath) / fn


def scan_paths(paths: list[Path], languages: set[str] | None = None) -> tuple[list[Finding], int]:
    findings, count = [], 0
    for p in iter_files(paths):
        lang = language_of(p)
        if not lang or (languages and lang not in languages):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count += 1
        findings.extend(scan_text(text, lang, p.as_posix()))
    return findings, count


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="List injection/XSS/SSRF/path-traversal review points in source code.",
        epilog="Example: risky_patterns.py src/ --category sql-injection --json",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    p.add_argument("--lang", action="append", choices=sorted(LANG_EXT), help="limit to a language")
    p.add_argument("--category", action="append", help="limit to a category (e.g. xss, ssrf)")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    args = p.parse_args(argv)
    if args.list_rules:
        for rid, lang, cat, sev, _rx, hint in RULES:
            print(f"{rid:28} {lang:10} {cat:18} {sev:6} {hint}")
        return 0
    paths = [Path(x) for x in args.paths]
    for x in paths:
        if not x.exists():
            print(f"error: {x} does not exist", file=sys.stderr)
            return 2
    findings, scanned = scan_paths(paths, set(args.lang) if args.lang else None)
    if args.category:
        findings = [f for f in findings if f.category in set(args.category)]
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.category, f.path, f.line))
    if args.json:
        print(json.dumps({"files_scanned": scanned, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        cats: dict[str, int] = {}
        for f in findings:
            cats[f.category] = cats.get(f.category, 0) + 1
        summary = ", ".join(f"{k} {v}" for k, v in sorted(cats.items())) or "none"
        print(f"review points: {len(findings)} in {scanned} files ({summary})")
        for f in findings:
            print(f"{f.severity.upper():6} {f.path}:{f.line}  [{f.category}] {f.rule}\n       {f.code}")
            print(f"       safe: {f.safe_pattern}")
    if args.fail_on == "none":
        return 0
    t = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= t for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
