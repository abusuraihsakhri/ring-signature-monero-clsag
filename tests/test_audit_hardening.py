"""Regression coverage for audit integrity, API access and CLI safety."""
import copy

import pytest
from fastapi.testclient import TestClient

from agents.api import app
from agents.base import AuditTrail, SecurityException
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from cli import main as primary_cli
from ring_clsag_sign.cli import main as secondary_cli


@pytest.mark.parametrize("field", [
    "audit_id", "timestamp", "actor", "actor_tier", "event_type",
    "payload_hash", "prev_hash", "current_hash",
])
def test_audit_detects_single_entry_tampering(field):
    trail = AuditTrail(secret_key="known-test-key")
    trail.log("worker", "unit", "EVALUATE", {"status": "ok"})
    assert trail.verify_integrity()
    trail.logs[0][field] = "tampered"
    assert not trail.verify_integrity(), field


def test_audit_detects_forged_relinked_chain():
    trail = AuditTrail(secret_key="known-test-key")
    trail.log("worker", "unit", "FIRST", {"count": 1})
    trail.log("worker", "unit", "SECOND", {"count": 2})
    assert trail.verify_integrity()
    trail.logs[0]["current_hash"] = "0" * 64
    trail.logs[1]["prev_hash"] = "0" * 64
    assert not trail.verify_integrity()


def test_public_trail_is_defensive_copy():
    trail = AuditTrail(secret_key="known-test-key")
    trail.log("worker", "unit", "EVALUATE", {"ok": True})
    snapshot = trail.get_trail()
    snapshot[0]["event_type"] = "MUTATED"
    snapshot.append({})
    assert len(trail.get_trail()) == 1
    assert trail.verify_integrity()


def test_metadata_sensitive_identifier_rejected():
    payload = SystemTaskPayload(
        task_id="T-001", target_identifier="KEY-001",
        primary_metric=1.0, attributes={"contact": "example@example.com"}
    )
    with pytest.raises(SecurityException):
        SystemSupervisor().process_task(payload)


def test_audit_logs_require_explicit_authorization(monkeypatch):
    client = TestClient(app)
    monkeypatch.delenv("AUDIT_LOGS_API_KEY", raising=False)
    assert client.get("/api/audit/logs").status_code == 403
    monkeypatch.setenv("AUDIT_LOGS_API_KEY", "unit-test-key")
    assert client.get("/api/audit/logs").status_code == 403
    response = client.get("/api/audit/logs",
                          headers={"X-Audit-Api-Key": "unit-test-key"})
    assert response.status_code == 200
    assert response.json()["verified"] is True


def test_api_rejects_sensitive_task_without_internal_error():
    client = TestClient(app)
    response = client.post("/api/audit", json={
        "task_id": "test@example.com",
        "target_identifier": "KEY-001",
        "primary_metric": 4,
    })
    assert response.status_code == 422


def test_local_console_served_from_api():
    client = TestClient(app)
    html = client.get("/")
    assert html.status_code == 200
    assert "app.js" in html.text
    js = client.get("/app.js")
    assert js.status_code == 200
    assert "evaluateLocally" in js.text


@pytest.mark.parametrize("command", [primary_cli, secondary_cli])
def test_batch_does_not_overwrite_input(tmp_path, command):
    csv_path = tmp_path / "input.csv"
    original = "task_id,target_identifier,primary_metric\nT-001,KEY-001,2\n"
    csv_path.write_text(original, encoding="utf-8")
    assert command(["batch", "-i", str(csv_path), "-o", str(csv_path)]) == 1
    assert csv_path.read_text(encoding="utf-8") == original
