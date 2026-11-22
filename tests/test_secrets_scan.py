"""Tests for secrets_scan.py.

Fake secrets are assembled from pieces at test time so that no complete token-shaped
string is committed to the repository (keeps gitleaks and push protection quiet).
"""

import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "secrets-scan"
SCRIPT = "secrets_scan.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL

AWS_ID = "AKIA" + "Z7Q2X9W4" + "V3K8T6R1"
AWS_SECRET = "q8Zr2LmXv7Np4Kd9" + "Wb3Ty6Hc1Fs5Jg0Ae8Ru2MoP"  # fake value, gitleaks:allow
GH = "ghp_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"
STRIPE_LIVE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_TEST = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
SLACK = "xox" + "b-1234567890-0987654321-AbCdEfGhIjKlMnOp"
GOOGLE = "AIza" + "SyD3x8Kq2Lm9Np4Rt7Vw1Yz5Bc6Df0Gh8Jk"
JWT = (
    "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gF"
)
PRIVATE_KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
DB_PASS = "Tr0ub4dor-z9Qx"
GENERIC = "N8v#qL2!xR7zP4wK"

ALL_SECRETS = [AWS_ID, AWS_SECRET, GH, STRIPE_LIVE, SLACK, GOOGLE, JWT, DB_PASS, GENERIC]


def rules(findings):
    return {f.rule for f in findings}


@pytest.fixture
def leaky_repo(tmp_path):
    root = tmp_path / "leaky"
    (root / "src").mkdir(parents=True)
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "src" / "config.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{AWS_ID}"\n'
        f'aws_secret_access_key = "{AWS_SECRET}"\n'
        f'GITHUB_TOKEN = "{GH}"\n'
        f'db_password = "{GENERIC}"\n'
        'API_KEY = os.environ["API_KEY"]\n'
    )
    (root / "src" / "app.js").write_text(
        f'const stripe = require("stripe")("{STRIPE_LIVE}");\n'
        f'const slack = "{SLACK}";\n'
        f'const maps = "{GOOGLE}";\n'
        f'const url = "postgres://app:{DB_PASS}@db.example.com/app";\n'
        f"const t = '{JWT}';\n"
    )
    (root / "deploy.key").write_text(PRIVATE_KEY_HEADER + "\nnot-a-real-key-body\n")
    (root / ".env").write_text("SECRET=short\n")
    (root / ".env.example").write_text("SECRET=changeme\n")
    (root / "node_modules" / "pkg" / "index.js").write_text(f'const k = "{GH}";\n')
    (root / ".git" / "config").write_text(f'token = "{GH}"\n')
    (root / "logo.png").write_bytes(b"\x89PNG\x00\x00" + GH.encode())
    return root


def test_detects_provider_tokens(leaky_repo):
    findings, scanned = mod.scan_paths([leaky_repo])
    found = rules(findings)
    assert {
        "aws-access-key-id",
        "aws-secret-access-key",
        "github-token",
        "stripe-live-key",
        "slack-token",
        "google-api-key",
        "jwt",
        "url-credentials",
        "private-key",
        "generic-secret",
        "sensitive-file",
    } <= found
    paths = {f.path for f in findings}
    assert not any("node_modules" in p or ".git/" in p or p.endswith(".png") for p in paths)
    assert not any(p.endswith(".env.example") for p in paths)
    assert any(p.endswith("/.env") for p in paths)
    assert scanned >= 4


def test_env_lookups_are_not_flagged(leaky_repo):
    findings, _ = mod.scan_paths([leaky_repo / "src" / "config.py"])
    assert all(f.line != 5 for f in findings)


def test_output_never_contains_full_secret(leaky_repo):
    r = run_script(SKILL, SCRIPT, str(leaky_repo))
    j = run_script(SKILL, SCRIPT, str(leaky_repo), "--json")
    assert r.returncode == 1 and j.returncode == 1
    for secret in ALL_SECRETS:
        assert secret not in r.stdout, secret
        assert secret not in j.stdout, secret
    assert "AKIA****" in r.stdout
    data = json.loads(j.stdout)
    assert data["counts"]["high"] >= 5


def test_clean_fixture_has_no_findings():
    findings, scanned = mod.scan_paths([F / "clean"])
    assert scanned == 3
    assert findings == []
    assert run_script(SKILL, SCRIPT, str(F / "clean")).returncode == 0


def test_inline_allow_and_examples():
    allowed = f'token = "{GH}"  # gitleaks:allow\n'
    assert mod.scan_text(allowed) == []
    assert rules(mod.scan_text(allowed, inline_allow=False)) == {"github-token"}
    example = "key = AKIAIOSFODNN7EXAMPLE\n"
    assert mod.scan_text(example) == []
    assert "aws-access-key-id" in rules(mod.scan_text(example, include_examples=True))


def test_stripe_test_key_is_low():
    (f,) = mod.scan_text(f'stripe = "{STRIPE_TEST}"')
    assert (f.rule, f.severity) == ("stripe-test-key", "low")


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme123"',
        "password = ${DB_PASSWORD}",
        'secret = "<your-secret-here>"',
        "token = self.request.token",
        "api_key = get_api_key()",
        "password: Optional[str] = None",
        'password = "aaaaaaaaaaaa"',
        "$password = $_POST['password'];",
        'SECRET_KEY = "xxxxxxxxxxxxxxxxxxxx"',
        "url = 'https://user:${PASS}@example.com'",
    ],
)
def test_placeholders_are_ignored(line):
    assert mod.scan_text(line) == []


def test_entropy_threshold():
    low = 'password = "summersummer"'
    assert mod.scan_text(low) == []
    assert mod.shannon_entropy("aaaa") == 0
    assert mod.shannon_entropy("abcd") == 2
    assert mod.scan_text(f'password = "{GENERIC}"', min_entropy=4.5) == []


def test_redact_and_fingerprint():
    assert mod.redact(GH) == "ghp_********"
    assert mod.redact("abc") == "ab******"
    assert mod.fingerprint("x", "y") == mod.fingerprint("x", "y")
    assert mod.fingerprint("x", "y") != mod.fingerprint("x", "z")


def test_baseline_roundtrip(leaky_repo, tmp_path):
    base = tmp_path / "baseline.json"
    r = run_script(SKILL, SCRIPT, str(leaky_repo), "--write-baseline", str(base))
    assert r.returncode == 0
    data = json.loads(base.read_text())
    assert data["fingerprints"]
    assert GH not in base.read_text()
    r = run_script(SKILL, SCRIPT, str(leaky_repo), "--baseline", str(base))
    assert r.returncode == 0, r.stdout


def test_cli_options(leaky_repo, tmp_path):
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
    assert run_script(SKILL, SCRIPT, str(tmp_path / "missing")).returncode == 2
    assert run_script(SKILL, SCRIPT, str(leaky_repo), "--fail-on", "none").returncode == 0
    r = run_script(SKILL, SCRIPT, str(leaky_repo), "--exclude", "src/*", "--exclude", "*.key", "--json")
    paths = {f["path"] for f in json.loads(r.stdout)["findings"]}
    assert not any("/src/" in p or p.endswith(".key") for p in paths)
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert run_script(SKILL, SCRIPT, str(leaky_repo), "--baseline", str(bad)).returncode == 2
