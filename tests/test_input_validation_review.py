import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "input-validation-review"
SCRIPT = "risky_patterns.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL


def by_file():
    findings, _ = mod.scan_paths([F / "risky"])
    out = {}
    for f in findings:
        out.setdefault(f.path.rsplit("/", 1)[-1], set()).add(f.rule)
    return out


def test_every_language_fixture_is_covered():
    found = by_file()
    assert {
        "py-sql-fstring",
        "py-sql-format",
        "py-shell-true",
        "py-os-system",
        "py-eval",
        "py-pickle",
        "py-yaml-load",
        "py-open-request",
        "py-requests-var",
        "py-redirect-request",
    } <= found["app.py"]
    assert {
        "js-sql-template",
        "js-exec",
        "js-fs-request",
        "js-fetch-request",
        "js-redirect-request",
        "js-innerhtml",
        "js-dangerously-set",
        "js-eval",
    } <= found["app.js"]
    assert {
        "php-sql-request",
        "php-echo-request",
        "php-shell",
        "php-include-var",
        "php-unserialize",
        "php-file-request",
        "php-redirect-request",
    } <= found["index.php"]
    assert {"go-sql-sprintf", "go-shell", "go-http-request"} <= found["main.go"]
    assert {"java-sql-concat", "java-deserialization", "java-runtime-exec"} <= found["UserDao.java"]
    assert {"rb-sql-interp", "rb-shell", "rb-redirect-params"} <= found["users_controller.rb"]
    assert found["page.html"] == {"tpl-safe-filter"}


def test_safe_fixtures_are_clean():
    findings, scanned = mod.scan_paths([F / "safe"])
    assert scanned == 3
    assert findings == []


def test_suppression_and_comments():
    text = 'cur.execute(f"SELECT {x}")  # review:ok constant\n# eval(x)\n// el.innerHTML = x\n'
    assert mod.scan_text(text, "python") == []
    assert mod.scan_text("// el.innerHTML = x", "javascript") == []
    assert len(mod.scan_text("el.innerHTML = x", "javascript")) == 1


def test_one_finding_per_category_per_line():
    findings = mod.scan_text('cur.execute(f"SELECT * FROM t WHERE a = {a}" + b)', "python")
    assert [f.category for f in findings] == ["sql-injection"]


@pytest.mark.parametrize(
    "line,lang,rule",
    [
        ("yaml.load(data, Loader=yaml.SafeLoader)", "python", None),
        ("yaml.load(data)", "python", "py-yaml-load"),
        ('requests.get("https://api.example.com")', "python", None),
        ("requests.get(url)", "python", "py-requests-var"),
        ("subprocess.run(['ls', path])", "python", None),
        ("el.innerHTML === x", "javascript", None),
        ("el.textContent = x", "javascript", None),
        ("db.query('SELECT 1 WHERE id = $1', [id])", "javascript", None),
        ("<?= htmlspecialchars($name) ?>", "php", None),
        ("<?= $_GET['q'] ?>", "php", "php-echo-request"),
        ('db.Query("SELECT 1 WHERE id = $1", id)', "go", None),
        ("User.where(name: params[:name])", "ruby", None),
        ('<div v-html="comment"></div>', "javascript", "js-dangerously-set"),
    ],
)
def test_rules(line, lang, rule):
    rules = {f.rule for f in mod.scan_text(line, lang)}
    assert rules == ({rule} if rule else set())


def test_language_detection():
    assert mod.language_of(F / "x.tsx") == "javascript"
    assert mod.language_of(F / "x.kt") == "java"
    assert mod.language_of(F / "x.txt") is None


def test_cli(tmp_path):
    r = run_script(SKILL, SCRIPT, str(F / "risky"))
    assert r.returncode == 1 and "safe:" in r.stdout
    j = run_script(SKILL, SCRIPT, str(F / "risky"), "--json", "--lang", "go")
    data = json.loads(j.stdout)
    assert data["files_scanned"] == 1 and all(f["path"].endswith(".go") for f in data["findings"])
    c = run_script(SKILL, SCRIPT, str(F / "risky"), "--json", "--category", "xss", "--fail-on", "none")
    assert c.returncode == 0 and {f["category"] for f in json.loads(c.stdout)["findings"]} == {"xss"}
    assert run_script(SKILL, SCRIPT, str(F / "safe")).returncode == 0
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing")).returncode == 2
    lr = run_script(SKILL, SCRIPT, "--list-rules")
    assert lr.returncode == 0 and "py-pickle" in lr.stdout
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
