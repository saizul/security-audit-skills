import json
from pathlib import Path

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "dependency-audit"
SCRIPT = "audit_report.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL


def load(name):
    return json.loads((F / name).read_text())


@pytest.mark.parametrize(
    "name,fmt",
    [
        ("npm-v2.json", "npm"),
        ("npm-v1.json", "npm-legacy"),
        ("pip-audit.json", "pip-audit"),
        ("pip-audit-list.json", "pip-audit"),
        ("composer.json", "composer"),
        ("composer-empty.json", "composer"),
    ],
)
def test_detect(name, fmt):
    assert mod.detect(load(name)) == fmt


def test_detect_unknown():
    with pytest.raises(ValueError):
        mod.detect(load("unknown.json"))


def test_npm_v2():
    vulns = {v.package: v for v in mod.analyse([load("npm-v2.json")])}
    parser = vulns["example-parser"]
    assert parser.severity == "critical" and parser.direct is True
    assert parser.fix == "example-parser@2.1.0" and parser.priority == "P1"
    assert parser.ids == ["GHSA-test-0000-0001"]
    cli = vulns["example-cli"]
    assert cli.via == ["example-parser"] and cli.fix == "available" and cli.priority == "P1"
    assert vulns["example-template"].breaking_fix is True
    assert "semver-major" in mod.fix_command(vulns["example-template"])
    assert vulns["example-regex"].severity == "medium" and vulns["example-regex"].priority == "P3"
    assert vulns["example-log"].priority == "P2"  # high, no fix
    assert "override" in mod.fix_command(vulns["example-log"])


def test_npm_legacy():
    vulns = {v.package: v for v in mod.analyse([load("npm-v1.json")])}
    legacy = vulns["example-legacy"]
    assert legacy.installed == "2.9.0" and legacy.ids == ["CVE-0000-00010"]
    assert legacy.priority == "P1"
    assert mod.fix_command(legacy) == "npm install 'example-legacy@>=3.0.1'"
    assert vulns["example-old"].fix is None and vulns["example-old"].priority == "P3"


def test_pip_audit_both_shapes():
    vulns = mod.analyse([load("pip-audit.json")])
    names = [v.package for v in vulns]
    assert names.count("example-web") == 1 and "example-ok" not in names and "local-pkg" not in names
    web = next(v for v in vulns if v.package == "example-web")
    assert web.fix == "2.0.3" and web.severity == "unknown" and web.priority == "P2"
    assert web.title == "Open redirect in example-web when ..."
    assert "CVE-0000-00001" in web.ids
    assert mod.fix_command(web).startswith("pip install 'example-web>=2.0.3'")
    assert len(mod.analyse([load("pip-audit-list.json")])) == 1


def test_composer():
    vulns = {v.package: v for v in mod.analyse([load("composer.json")])}
    assert vulns["example/http"].priority == "P1"
    assert vulns["example/http"].ids == ["PKSA-test-0001", "CVE-0000-00020"]
    assert vulns["example/markdown"].priority == "P2"
    assert "--with-all-dependencies" in mod.fix_command(vulns["example/http"])
    assert mod.fix_command(vulns["example/old-mailer"]) == "replace with example/mailer"
    assert vulns["example/unmaintained"].fix is None
    assert mod.analyse([load("composer-empty.json")]) == []


def test_sorted_by_priority_then_severity():
    vulns = mod.analyse([load(n) for n in ("npm-v2.json", "pip-audit.json", "composer.json")])
    prios = [v.priority for v in vulns]
    assert prios == sorted(prios)
    assert vulns[0].severity == "critical" and vulns[0].direct is True


def test_cli(tmp_path):
    files = [str(F / n) for n in ("npm-v2.json", "pip-audit.json", "composer.json")]
    r = run_script(SKILL, SCRIPT, *files)
    assert r.returncode == 1
    assert "== P1 fix now ==" in r.stdout and "npm install example-parser@2.1.0" in r.stdout
    j = run_script(SKILL, SCRIPT, *files, "--json")
    assert json.loads(j.stdout)["count"] == len(mod.analyse([json.loads(Path(f).read_text()) for f in files]))
    assert run_script(SKILL, SCRIPT, str(F / "pip-audit.json")).returncode == 0  # unknown < high
    assert run_script(SKILL, SCRIPT, str(F / "pip-audit.json"), "--fail-on", "any").returncode == 1
    assert run_script(SKILL, SCRIPT, str(F / "npm-v2.json"), "--fail-on", "none").returncode == 0
    assert run_script(SKILL, SCRIPT, str(F / "composer-empty.json"), "--fail-on", "any").returncode == 0
    assert run_script(SKILL, SCRIPT, "-", stdin=(F / "npm-v1.json").read_text()).returncode == 1
    assert run_script(SKILL, SCRIPT, str(F / "unknown.json")).returncode == 2
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing.json")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
