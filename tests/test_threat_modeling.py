import csv
import io
import json

import pytest

from conftest import FIXTURES, load_script, run_script

SKILL = "threat-modeling"
SCRIPT = "stride.py"
mod = load_script(SKILL, SCRIPT)
F = FIXTURES / SKILL


def shop():
    return mod.load_model(json.loads((F / "shop.json").read_text()))


def test_stride_per_element_counts():
    rows = mod.generate(shop())
    per = {}
    for r in rows:
        per.setdefault(r["element"], set()).add(r["stride"])
    assert per["Customer browser"] == set("SR")
    assert per["Web/API"] == set("STRIDE")
    assert per["Postgres"] == set("TRID")
    assert per["Browse and checkout (Customer browser -> Web/API)"] == set("TID")
    # 2 externals*2 + 2 processes*6 + 2 stores*4 + 5 flows*3 + 1 unauthenticated boundary flow
    assert len(rows) == 4 + 12 + 8 + 15 + 1


def test_ids_are_sequential_and_sorted_by_score():
    rows = mod.generate(shop())
    assert [r["id"] for r in rows] == [f"T{i:02d}" for i in range(1, len(rows) + 1)]
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)


def test_model_facts_raise_risk():
    rows = mod.generate(shop())
    top = rows[0]
    assert top["category"] == "Spoofing" and "Payment webhook" in top["element"]
    assert top["risk"] == "High"
    pg_i = next(r for r in rows if r["element"] == "Postgres" and r["stride"] == "I")
    assert (pg_i["likelihood"], pg_i["impact"], pg_i["risk"]) == (3, 3, "High")
    redis_flow = next(r for r in rows if r["element"].startswith("Sessions") and r["stride"] == "I")
    assert "plain-text protocol 'redis'" in redis_flow["notes"] and redis_flow["likelihood"] == 3
    https_flow = next(r for r in rows if r["element"].startswith("Browse") and r["stride"] == "I")
    assert https_flow["likelihood"] == 1 and https_flow["impact"] == 3
    tls_flow = next(r for r in rows if r["element"].startswith("SQL queries") and r["stride"] == "T")
    assert tls_flow["likelihood"] == 1


@pytest.mark.parametrize(
    "proto,expected",
    [
        ("https", True),
        ("postgres-tls", True),
        ("rediss", True),
        ("redis", False),
        ("http", False),
        ("", False),
    ],
)
def test_encrypted(proto, expected):
    assert mod.encrypted(proto) is expected


def test_risk_label():
    assert [mod.risk_label(s) for s in (9, 6, 4, 3, 2, 1)] == [
        "High",
        "High",
        "Medium",
        "Medium",
        "Low",
        "Low",
    ]


@pytest.mark.parametrize(
    "data,message",
    [
        ({}, "elements"),
        ({"elements": [{"type": "process"}]}, "id"),
        ({"elements": [{"id": "a", "type": "database"}]}, "type must be"),
        ({"elements": [{"id": "a", "type": "process"}, {"id": "a", "type": "store"}]}, "duplicate"),
        (
            {"elements": [{"id": "a", "type": "process"}], "flows": [{"from": "a", "to": "b"}]},
            "not an element",
        ),
        ([], "JSON object"),
    ],
)
def test_invalid_models(data, message):
    with pytest.raises(mod.ModelError, match=message):
        mod.load_model(data)


def test_markdown_output_escapes_pipes():
    model = mod.load_model({"system": "x", "elements": [{"id": "a", "type": "process", "name": "A|B"}]})
    md = mod.to_markdown(model, mod.generate(model))
    assert "A\\|B" in md and md.startswith("# Threat model: x")


def test_cli_formats(tmp_path):
    md = run_script(SKILL, SCRIPT, str(F / "shop.json"))
    assert md.returncode == 0 and "| ID | Element | STRIDE |" in md.stdout
    js = run_script(SKILL, SCRIPT, str(F / "shop.json"), "--format", "json", "--min-risk", "High")
    data = json.loads(js.stdout)
    assert data["threats"] and all(t["risk"] == "High" for t in data["threats"])
    cs = run_script(SKILL, SCRIPT, str(F / "shop.json"), "--format", "csv")
    rows = list(csv.DictReader(io.StringIO(cs.stdout)))
    assert rows[0]["id"] == "T01" and "mitigation" in rows[0]
    assert run_script(SKILL, SCRIPT, "-", stdin=(F / "shop.json").read_text()).returncode == 0
    assert run_script(SKILL, SCRIPT, str(F / "bad-ref.json")).returncode == 2
    assert run_script(SKILL, SCRIPT, str(F / "bad-type.json")).returncode == 2
    assert run_script(SKILL, SCRIPT, str(tmp_path / "none.json")).returncode == 2
    assert run_script(SKILL, SCRIPT, "--help").returncode == 0
