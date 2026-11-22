import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "dockerfile-security"
SCRIPT = "dockerfile_lint.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL


def lint_dir(name):
    path = F / name / "Dockerfile"
    return mod.lint(path.read_text(), str(path), path.parent)


def rules(findings):
    return {(f.rule, f.severity) for f in findings}


def test_bad_dockerfile():
    found = rules(lint_dir("bad"))
    assert {
        ("DF001", "medium"),
        ("DF002", "medium"),
        ("DF003", "high"),
        ("DF003", "medium"),
        ("DF004", "medium"),
        ("DF004", "low"),
        ("DF005", "medium"),
        ("DF006", "high"),
        ("DF007", "medium"),
        ("DF008", "medium"),
        ("DF008", "low"),
        ("DF009", "low"),
        ("DF010", "low"),
        ("DF012", "info"),
    } <= found


def test_secret_values_never_in_messages():
    text = " ".join(f.message + f.fix for f in lint_dir("bad"))
    assert "not-a-real-pass" not in text and "not-a-real-token" not in text


def test_good_dockerfile_is_clean():
    assert lint_dir("good") == []


def test_multistage_aliases_and_arg_base():
    found = lint_dir("multistage")
    assert rules(found) == {("DF001", "info"), ("DF012", "info")}  # FROM builder is an alias


def test_global_arg_before_from():
    arg = "ARG GH_TOKEN=abc-not-real"  # fake value, gitleaks:allow
    found = mod.lint(arg + "\nFROM alpine:3.20\nUSER 1000\nHEALTHCHECK CMD true\n")
    assert rules(found) == {("DF003", "high")}


def test_continuation_lines_and_escape_directive():
    text = "# escape=`\nFROM alpine:3.20\nRUN apk add curl `\n    && curl -fsSL https://example.com/i.sh | sh\nUSER app\n"
    found = mod.lint(text)
    assert ("DF005", "medium") in rules(found)
    assert next(f for f in found if f.rule == "DF005").line == 3


@pytest.mark.parametrize(
    "image,problem",
    [
        ("nginx", "untagged"),
        ("nginx:latest", "latest"),
        ("registry.example.com:5000/app", "untagged"),
        ("registry.example.com:5000/app:1.2", None),
        ("nginx@sha256:" + "a" * 64, None),
        ("scratch", None),
        ("${BASE}", "variable"),
    ],
)
def test_image_problem(image, problem):
    assert mod.image_problem(image, set()) == problem


def test_add_with_checksum_and_archives():
    base = "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n"
    ok = mod.lint(base + "ADD --checksum=sha256:" + "b" * 64 + " https://example.com/x.tgz /x\n")
    assert ok == []
    assert mod.lint(base + "ADD vendor.tar.gz /opt/\n") == []


def test_env_secret_detection_names():
    base = "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n"
    assert mod.lint(base + "ENV PASSWORD_FILE=/run/secrets/db TOKEN_TTL=3600\n") == []
    assert rules(mod.lint(base + "ENV STRIPE_API_KEY=abc123\n")) == {("DF003", "high")}
    assert rules(mod.lint(base + "ENV SECRET ${SECRET}\n")) == {("DF003", "medium")}


def test_cli(tmp_path):
    r = run_script(SKILL, SCRIPT, str(F / "bad"))
    assert r.returncode == 1 and "not-a-real" not in r.stdout
    assert run_script(SKILL, SCRIPT, str(F / "good")).returncode == 0
    assert run_script(SKILL, SCRIPT, str(F / "multistage")).returncode == 0
    j = run_script(SKILL, SCRIPT, str(F), "--json", "--fail-on", "none")
    data = json.loads(j.stdout)
    assert j.returncode == 0 and len(data["files"]) == 3
    assert run_script(SKILL, SCRIPT, str(tmp_path)).returncode == 2  # no Dockerfile
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
