import json

import pytest

from conftest import load_script, run_script

SKILL = "incident-response-playbook"
SCRIPT = "incident_log.py"
mod = load_script(SKILL, SCRIPT)
NOW = "2026-11-22T10:15:00Z"


@pytest.mark.parametrize("kind", sorted(mod.CHECKLISTS))
def test_every_type_has_all_phases(kind):
    assert list(mod.CHECKLISTS[kind]) == mod.PHASES
    text = mod.render(kind, "Test", "SEV2", mod.utc_now(NOW))
    prog = mod.progress(text)
    assert list(prog) == mod.PHASES
    assert all(v["done"] == 0 and v["open"] for v in prog.values())


def test_render_and_timeline():
    text = mod.render("leaked-secret", "AWS key in public repo", "SEV1", mod.utc_now(NOW))
    assert text.startswith("# Incident: AWS key in public repo")
    assert "- Severity: SEV1" in text and "- Opened: 2026-11-22T10:15:00Z" in text
    text = mod.add_entry(text, "key deactivated", mod.utc_now("2026-11-22T10:20:00Z"))
    assert text.rstrip().endswith("- 2026-11-22T10:20:00Z key deactivated")


def test_add_entry_before_following_section():
    text = "# X\n\n## Timeline\n\n- a\n\n## Notes\n\nn\n"
    out = mod.add_entry(text, "b", mod.utc_now(NOW))
    assert out.index("- 2026-11-22T10:15:00Z b") < out.index("## Notes")
    assert mod.add_entry("# X\n", "c", mod.utc_now(NOW)).endswith("## Timeline\n\n- 2026-11-22T10:15:00Z c\n")


def test_slugify():
    assert mod.slugify("Leaked GitHub token (CI)!") == "leaked-github-token-ci"
    assert mod.slugify("!!!") == "incident"


def test_cli_lifecycle(tmp_path):
    r = run_script(
        SKILL,
        SCRIPT,
        "new",
        "--type",
        "compromised-account",
        "--title",
        "Admin login from new country",
        "--severity",
        "SEV2",
        "--out",
        str(tmp_path),
        "--now",
        NOW,
    )
    assert r.returncode == 0
    path = tmp_path / "incident-20261122-1015-admin-login-from-new-country.md"
    assert r.stdout.strip() == str(path) and path.exists()
    again = run_script(
        SKILL,
        SCRIPT,
        "new",
        "--type",
        "other",
        "--title",
        "Admin login from new country",
        "--out",
        str(tmp_path),
        "--now",
        NOW,
    )
    assert again.returncode == 2  # never overwrites
    assert run_script(SKILL, SCRIPT, "add", str(path), "sessions revoked", "--now", NOW).returncode == 0
    assert "sessions revoked" in path.read_text()
    c = run_script(SKILL, SCRIPT, "check", str(path), "--json")
    assert c.returncode == 1 and json.loads(c.stdout)["open"] > 0
    path.write_text(path.read_text().replace("- [ ]", "- [x]"))
    done = run_script(SKILL, SCRIPT, "check", str(path))
    assert done.returncode == 0 and "0 open item(s)" in done.stdout
    assert run_script(SKILL, SCRIPT, "check", str(tmp_path / "missing.md")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
