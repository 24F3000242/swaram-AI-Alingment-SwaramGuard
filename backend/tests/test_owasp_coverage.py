"""The OWASP Agentic Top 10 mapping stays in sync with the real rule list."""
from fastapi.testclient import TestClient

from app.main import app
from app.modules.detection.owasp import OWASP_AGENTIC, coverage
from app.modules.detection.rules import DEFAULT_RULES


def test_all_ten_risks_and_every_rule_are_mapped():
    assert [r["id"] for r in OWASP_AGENTIC] == [f"ASI{i:02d}" for i in range(1, 11)]
    c = coverage()
    assert c["rules_not_mapped"] == []
    known = {r.rule_id for r in DEFAULT_RULES}
    assert all(x["rule_id"] in known for r in c["risks"] for x in r["rules"])  # no mapping to a rule that doesn't exist
    assert all(r["coverage"] in ("strong", "partial") and r["gaps"] for r in OWASP_AGENTIC)  # gaps stated, always


def test_endpoint_serves_it():
    body = TestClient(app).get("/api/coverage/owasp").json()
    assert body["summary"]["strong"] + body["summary"]["partial"] == 10
