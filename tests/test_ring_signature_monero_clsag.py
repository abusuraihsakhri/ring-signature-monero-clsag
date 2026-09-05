"""
Automated Pytest Test Suite for Ring Signature Monero Clsag.
Domain: Post-Quantum Cryptography & Hardware Security
Standard: NIST FIPS 203/204/205 / ISO/IEC 17825 Standards
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import PHIGuard, AuditLogger, SecurityException
from agents.models import SystemTaskPayload, UrgencyLevel, SystemIntegrityStatus
from agents.workers import InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker
from agents.supervisor import SystemSupervisor
from cli import main


def test_phi_guard_enforcement():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("Patient MRN-994827 blood culture positive for Staphylococcus")

    # Clean text passes
    PHIGuard.assert_no_phi("Analytical assay specimen KEY-001 optimal")


def test_specialized_workers():
    # Worker 1: QC Invariant
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    alerts1 = InvariantQCWorker.evaluate(p1)
    assert len(alerts1) == 1
    assert alerts1[0].urgency == UrgencyLevel.ELEVATED

    # Worker 2: Safety
    p2 = SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True)
    alerts2 = SafetyEscalationWorker.evaluate(p2)
    assert len(alerts2) == 1
    assert alerts2[0].urgency == UrgencyLevel.CRITICAL_STAT

    # Worker 3: Protocol Conformance
    p3 = SystemTaskPayload(task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = ProtocolConformanceWorker.evaluate(p3)
    assert len(alerts3) == 1


def test_supervisor_consensus_and_audit():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="TASK-PROD-01",
        target_identifier="KEY-PROD-01",
        primary_metric=12.0,
        secondary_metric=4.0,
        status_descriptor="NOMINAL"
    )
    dossier = supervisor.process_task(payload)
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.integrity_status == SystemIntegrityStatus.VALIDATED
    assert dossier.audit_hash != ""

    # Verify cryptographic audit trail
    assert AuditLogger.verify_integrity() is True

    # CLI tests
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "specifications"]) == 0
    assert main(["verify-audit"]) == 0


# --- New validation and edge-case tests ---

def test_metric_nan_rejected():
    """NaN metric values must be rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T-NAN", target_identifier="KEY-NAN", primary_metric=float("nan"))


def test_metric_inf_rejected():
    """Infinite metric values must be rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T-INF", target_identifier="KEY-INF", secondary_metric=float("inf"))


def test_empty_task_id_rejected():
    """Empty task_id must be rejected."""
    with pytest.raises(ValueError, match="non-empty"):
        SystemTaskPayload(task_id="   ", target_identifier="KEY-01", primary_metric=10.0)


def test_empty_target_identifier_rejected():
    """Empty target_identifier must be rejected."""
    with pytest.raises(ValueError, match="non-empty"):
        SystemTaskPayload(task_id="T1", target_identifier="", primary_metric=10.0)


def test_batch_missing_file_returns_error():
    """Batch command with missing input file should return exit code 1."""
    assert main(["batch", "-i", "nonexistent_file_xyz.csv"]) == 1


def test_phi_redaction():
    """PHIGuard.redact_phi should replace PII with placeholder."""
    redacted = PHIGuard.redact_phi("Contact patient at 555-123-4567 or test@example.com")
    assert "555-123-4567" not in redacted
    assert "test@example.com" not in redacted
    assert "[REDACTED_IDENTIFIER]" in redacted


def test_audit_trail_integrity_tamper_detection():
    """Audit trail should detect tampering with previous hash."""
    from agents.base import AuditTrail
    trail = AuditTrail(secret_key="test-key-for-integrity")
    trail.log("test", "tier", "EVENT_A", {"data": 1})
    trail.log("test", "tier", "EVENT_B", {"data": 2})
    assert trail.verify_integrity() is True

    # Tamper with the first entry's current_hash
    if trail.logs:
        trail.logs[0]["current_hash"] = "TAMPERED_HASH"
    assert trail.verify_integrity() is False


def test_supervisor_all_urgency_levels():
    """Supervisor should correctly classify all urgency levels."""
    supervisor = SystemSupervisor(model_provider="mock")

    # ROUTINE: all metrics nominal
    p_routine = SystemTaskPayload(
        task_id="T-ROUTINE", target_identifier="KEY-R",
        primary_metric=10.0, secondary_metric=5.0,
        status_descriptor="NOMINAL", is_critical_flag=False
    )
    d = supervisor.process_task(p_routine)
    assert d.overall_urgency == UrgencyLevel.ROUTINE

    # ELEVATED: primary metric exceeds threshold
    p_elevated = SystemTaskPayload(
        task_id="T-ELEV", target_identifier="KEY-E",
        primary_metric=30.0, secondary_metric=5.0,
        status_descriptor="NOMINAL", is_critical_flag=False
    )
    d = supervisor.process_task(p_elevated)
    assert d.overall_urgency == UrgencyLevel.ELEVATED

    # CRITICAL: is_critical_flag set
    p_critical = SystemTaskPayload(
        task_id="T-CRIT", target_identifier="KEY-C",
        primary_metric=10.0, secondary_metric=5.0,
        status_descriptor="NOMINAL", is_critical_flag=True
    )
    d = supervisor.process_task(p_critical)
    assert d.overall_urgency == UrgencyLevel.CRITICAL_STAT
