"""Tests for cookie_check.py and jwt_lint.py. Tokens are built at test time."""

import base64
import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "auth-session-review"
cookies = load_script(SKILL, "cookie_check.py")
jwt = load_script(SKILL, "jwt_lint.py")
F = FIXTURES / SKILL
NOW = 1_795_000_000  # fixed "current" time for JWT checks


def checks(findings):
    out = {}
    for f in findings:
        out.setdefault(f.cookie, set()).add((f.check, f.severity))
    return out


def all_findings(cookie_list):
    out = []
    for c in cookie_list:
        out += cookies.check_cookie(c)
    return out


def test_parse_set_cookie():
    name, value, attrs = cookies.parse_set_cookie('a="x=y"; Path=/; Secure; HttpOnly; SameSite=Lax')
    assert (name, value) == ("a", "x=y")
    assert attrs == {"path": "/", "secure": True, "httponly": True, "samesite": "Lax"}


def test_raw_headers():
    text = (F / "login-headers.txt").read_text()
    found = checks(all_findings(cookies.cookies_from_headers(text)))
    assert {("httponly", "high"), ("secure", "high"), ("samesite", "medium")} <= found["PHPSESSID"]
    assert ("lifetime", "medium") in found["remember_me"]
    assert ("prefix", "high") in found["__Host-sid"]  # Path=/app
    assert ("samesite-none", "high") in found["tracking"]
    assert "csrftoken" not in found  # readable by JS on purpose, Secure + SameSite set
    assert "auth" not in found  # Max-Age=0 deletion cookie


def test_har_http_and_domain_and_expires():
    data = json.loads((F / "session.har").read_text())
    jar = cookies.cookies_from_har(data)
    assert {c.name for c in jar} == {"session_id", "connect.sid", "prefs"}  # newline-joined header split
    found = checks(all_findings(jar))
    assert ("set-over-http", "high") in found["session_id"]
    assert ("domain", "low") in found["connect.sid"]
    assert ("lifetime", "medium") in found["connect.sid"]  # Expires one year after response
    assert "prefs" not in found


def test_good_cookies_are_clean():
    jar = cookies.cookies_from_headers((F / "good-headers.txt").read_text())
    assert all_findings(jar) == []


def test_jwt_value_is_reported_without_value():
    token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxIn0." + "c2lnbmF0dXJl"  # fake value, gitleaks:allow
    jar = cookies.cookies_from_headers(
        f"Set-Cookie: __Host-token={token}; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
    (f,) = all_findings(jar)
    assert f.check == "jwt-in-cookie" and token not in f.message


def test_cookie_cli(tmp_path):
    r = run_script(SKILL, "cookie_check.py", str(F / "login-headers.txt"))
    assert r.returncode == 1 and "fakevalue" not in r.stdout
    assert run_script(SKILL, "cookie_check.py", str(F / "good-headers.txt")).returncode == 0
    j = run_script(SKILL, "cookie_check.py", str(F / "session.har"), "--json")
    assert j.returncode == 1 and "fakevalue" not in j.stdout
    assert json.loads(j.stdout)["cookies"] == ["connect.sid", "prefs", "session_id"]
    raw = "Set-Cookie: sid=x; Secure; HttpOnly; SameSite=Lax\n"
    r = run_script(SKILL, "cookie_check.py", "-", "--url", "http://example.com/", stdin=raw)
    assert r.returncode == 1 and "set-over-http" in r.stdout
    assert (
        run_script(
            SKILL, "cookie_check.py", "-", "--fail-on", "none", stdin=raw.replace("Secure; ", "")
        ).returncode
        == 0
    )
    bad = tmp_path / "bad.har"
    bad.write_text("{not json")
    assert run_script(SKILL, "cookie_check.py", str(bad)).returncode == 2
    assert run_script(SKILL, "cookie_check.py", str(tmp_path / "missing")).returncode == 2
    assert run_script(SKILL, "cookie_check.py", "--help").returncode == 0


# --- jwt_lint ---------------------------------------------------------------


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_token(header, payload, sig="c2lnbmF0dXJlLW5vdC1yZWFs"):
    return f"{b64(header)}.{b64(payload)}.{sig}"


GOOD_PAYLOAD = {
    "sub": "42",
    "iss": "https://auth.example.com",
    "aud": "api",
    "iat": NOW - 60,
    "exp": NOW + 840,
}


def lint(header, payload, sig="c2ln"):
    h, p, n = jwt.decode(make_token(header, payload, sig))
    return {(f["check"], f["severity"]) for f in jwt.lint(h, p, n, NOW, 24)}


def test_good_rs256_token_is_clean():
    assert lint({"alg": "RS256", "typ": "JWT", "kid": "2026-01"}, GOOD_PAYLOAD) == set()


def test_alg_none_and_missing_claims():
    found = lint({"alg": "none"}, {"sub": "1"}, sig="")
    assert {("alg-none", "high"), ("exp", "high"), ("iat", "low"), ("iss", "low"), ("aud", "low")} <= found


def test_hs256_long_lifetime_and_sensitive_claims():
    payload = dict(GOOD_PAYLOAD, exp=NOW + 30 * 86400, password="x", email="a@example.com")
    found = lint({"alg": "HS256"}, payload)
    assert {
        ("alg-hmac", "info"),
        ("lifetime", "medium"),
        ("sensitive-claim", "high"),
        ("pii-claim", "info"),
    } <= found


def test_embedded_keys_kid_and_expired():
    header = {"alg": "RS256", "jku": "https://example.com/jwks.json", "kid": "../../keys/a"}
    found = lint(header, dict(GOOD_PAYLOAD, exp=NOW - 10))
    assert {("header-jku", "medium"), ("kid", "low"), ("expired", "info")} <= found


def test_empty_signature():
    assert ("signature", "high") in lint({"alg": "RS256"}, GOOD_PAYLOAD, sig="")


@pytest.mark.parametrize("token", ["abc", "a.b", "!!.!!.!!", "a.b.c.d.e"])
def test_decode_errors(token):
    with pytest.raises(ValueError):
        jwt.decode(token)


def test_jwt_cli_never_prints_signature_or_values(tmp_path):
    sig = "U0lHTkFUVVJFLXNob3VsZC1uZXZlci1wcmludA"
    token = make_token({"alg": "HS256"}, dict(GOOD_PAYLOAD, name="Alice Example", role="admin"), sig)
    r = run_script(SKILL, "jwt_lint.py", "--now", str(NOW), stdin="Bearer " + token + "\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert sig not in r.stdout and "Alice Example" not in r.stdout and "admin" not in r.stdout
    assert "name, role, sub" in r.stdout
    f = tmp_path / "t.txt"
    f.write_text(make_token({"alg": "none"}, {"sub": "1"}, ""))
    j = run_script(SKILL, "jwt_lint.py", "--file", str(f), "--json", "--now", str(NOW))
    assert j.returncode == 1 and json.loads(j.stdout)["header"] == {"alg": "none"}
    assert run_script(SKILL, "jwt_lint.py", "--file", str(f), "--fail-on", "none").returncode == 0
    assert run_script(SKILL, "jwt_lint.py", stdin="not-a-token").returncode == 2
    assert run_script(SKILL, "jwt_lint.py", "--help").returncode == 0


def test_future_iat_and_nbf_beyond_leeway():
    found = lint({"alg": "RS256"}, dict(GOOD_PAYLOAD, iat=NOW + 3600, nbf=NOW + 3600, exp=NOW + 4000))
    assert {("iat-future", "low"), ("nbf-future", "low")} <= found
    within = lint({"alg": "RS256"}, dict(GOOD_PAYLOAD, iat=NOW + 120))
    assert not any(check.endswith("-future") for check, _ in within)


def test_exp_before_start():
    # exp written in seconds but iat in milliseconds: the token is never valid
    found = lint({"alg": "RS256"}, dict(GOOD_PAYLOAD, iat=(NOW - 60) * 1000))
    assert ("exp-before-start", "medium") in found


def test_jwt_cli_leeway_option():
    token = make_token({"alg": "RS256"}, dict(GOOD_PAYLOAD, iat=NOW + 600))
    strict = run_script(SKILL, "jwt_lint.py", "--now", str(NOW), "--json", stdin=token)
    assert "iat-future" in {f["check"] for f in json.loads(strict.stdout)["findings"]}
    loose = run_script(SKILL, "jwt_lint.py", "--now", str(NOW), "--json", "--leeway", "900", stdin=token)
    assert "iat-future" not in {f["check"] for f in json.loads(loose.stdout)["findings"]}
