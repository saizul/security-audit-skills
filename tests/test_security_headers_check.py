import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "security-headers-check"
SCRIPT = "headers_grade.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL


def grade_text(text, https=True):
    (resp,) = mod.parse_raw(text)[-1:]
    return mod.evaluate(resp, https)


def keys(result):
    return {(f["header"], f["severity"]) for f in result["findings"]}


def test_bad_headers():
    res = grade_text((F / "curl-bad.txt").read_text())
    assert res["grade"] == "F"
    assert {
        ("strict-transport-security", "high"),
        ("access-control-allow-origin", "high"),
        ("content-security-policy", "medium"),
        ("x-frame-options", "medium"),
        ("x-content-type-options", "low"),
        ("server", "low"),
        ("x-powered-by", "low"),
        ("x-xss-protection", "info"),
    } <= keys(res)


def test_good_headers_score_100():
    res = grade_text((F / "curl-good.txt").read_text())
    assert (res["score"], res["grade"], res["findings"]) == (100, "A", [])


def test_redirect_chain_grades_last_response():
    responses = mod.parse_raw((F / "curl-redirect.txt").read_text())
    assert [r["status"] for r in responses] == [301, 200]
    res = mod.evaluate(responses[-1], True)
    msgs = " ".join(f["message"] for f in res["findings"])
    assert "'unsafe-inline'" in msgs and "'unsafe-eval'" in msgs and "https:" in msgs
    assert ("referrer-policy", "medium") in keys(res)
    assert ("strict-transport-security", "low") in keys(res)
    assert ("x-frame-options", "medium") not in keys(res)  # XFO present


def test_http_skips_hsts():
    res = grade_text((F / "curl-bad.txt").read_text(), https=False)
    assert not any(f["header"] == "strict-transport-security" for f in res["findings"])


@pytest.mark.parametrize(
    "csp,expect_unsafe_inline",
    [
        ("script-src 'self' 'unsafe-inline'", True),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc'", False),  # ignored by CSP2+ browsers
        ("script-src 'strict-dynamic' 'unsafe-inline' 'sha256-abc'", False),
        ("default-src 'self' 'unsafe-inline'", True),
    ],
)
def test_csp_unsafe_inline(csp, expect_unsafe_inline):
    out = []
    mod.check_csp(csp, lambda *a: out.append(a))
    assert any("unsafe-inline" in a[2] for a in out) is expect_unsafe_inline


def test_csp_default_none_covers_object_src():
    out = []
    mod.check_csp("default-src 'none'; script-src 'self'; base-uri 'none'", lambda *a: out.append(a))
    assert out == []


def test_cors_null_origin():
    res = grade_text("HTTP/2 200\naccess-control-allow-origin: null\n")
    assert ("access-control-allow-origin", "high") in keys(res)


def test_har_selects_html_documents():
    data = json.loads((F / "site.har").read_text())
    responses = mod.parse_har(data)
    assert len(responses) == 2
    chosen = mod.select(responses, True, False, "")
    assert [r["url"] for r in chosen] == ["https://www.example.com/"]
    res = mod.evaluate(chosen[0], True)
    assert ("content-security-policy", "medium") in keys(res)  # report-only
    assert res["grade"] == "B"
    assert len(mod.select(responses, True, True, "")) == 2
    assert len(mod.select(responses, True, True, "app.js")) == 1


@pytest.mark.parametrize(
    "score,g", [(100, "A"), (90, "A"), (89, "B"), (70, "C"), (60, "D"), (59, "F"), (0, "F")]
)
def test_grade(score, g):
    assert mod.grade(score) == g


def test_cli(tmp_path):
    assert run_script(SKILL, SCRIPT, str(F / "curl-good.txt")).returncode == 0
    r = run_script(SKILL, SCRIPT, str(F / "curl-bad.txt"))
    assert r.returncode == 1 and r.stdout.startswith("F (")
    assert run_script(SKILL, SCRIPT, str(F / "curl-bad.txt"), "--min-grade", "F").returncode == 0
    assert run_script(SKILL, SCRIPT, str(F / "site.har")).returncode == 0
    assert run_script(SKILL, SCRIPT, str(F / "site.har"), "--min-grade", "A").returncode == 1
    j = run_script(SKILL, SCRIPT, "-", "--json", "--all", stdin=(F / "curl-redirect.txt").read_text())
    assert [x["status"] for x in json.loads(j.stdout)["results"]] == [301, 200]
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    assert run_script(SKILL, SCRIPT, str(empty)).returncode == 2
    bad = tmp_path / "bad.har"
    bad.write_text("{oops")
    assert run_script(SKILL, SCRIPT, str(bad)).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0


GOOD_BASE = (
    "HTTP/2 200\n"
    "strict-transport-security: max-age=31536000; includeSubDomains\n"
    "x-content-type-options: nosniff\n"
    "referrer-policy: strict-origin-when-cross-origin\n"
    "permissions-policy: camera=()\n"
    "cross-origin-opener-policy: same-origin\n"
)


def test_frame_ancestors_wildcard_is_not_protection():
    text = (
        GOOD_BASE
        + "content-security-policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors *\nx-frame-options: DENY\n"
    )
    res = grade_text(text)
    msgs = [f["message"] for f in res["findings"]]
    assert any("frame-ancestors allows *" in m for m in msgs)
    assert res["score"] == 90


def test_invalid_x_frame_options_value():
    text = (
        GOOD_BASE
        + "content-security-policy: default-src 'self'; object-src 'none'; base-uri 'self'\nx-frame-options: ALLOWALL\n"
    )
    res = grade_text(text)
    xfo = [f for f in res["findings"] if f["header"] == "x-frame-options"]
    assert len(xfo) == 1 and xfo[0]["severity"] == "medium" and "ignore" in xfo[0]["message"]
    ok = (
        GOOD_BASE
        + "content-security-policy: default-src 'self'; object-src 'none'; base-uri 'self'\nx-frame-options: sameorigin\n"
    )
    assert not [f for f in grade_text(ok)["findings"] if f["header"] == "x-frame-options"]


def test_conflicting_duplicate_headers():
    text = (
        GOOD_BASE
        + "content-security-policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\n"
        + "x-frame-options: DENY\nx-frame-options: SAMEORIGIN\nx-content-type-options: nosniff\n"
    )
    res = grade_text(text)
    dup = [(f["header"], f["severity"]) for f in res["findings"] if "different values" in f["message"]]
    assert dup == [("x-frame-options", "low")]  # identical nosniff copies are fine
