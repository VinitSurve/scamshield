"""Unit tests for StateManager, Job Tracking, Checkpoint Persistence, and Logging."""

import tempfile
from pathlib import Path
import pytest
from scamshield_ml.state import (
    STATUS_COMPLETED,
    STATUS_INTERRUPTED,
    STATUS_RUNNING,
    StateManager,
)


@pytest.fixture
def temp_state():
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        db_path = Path(f.name)
        sm = StateManager(db_path=db_path)
        yield sm


def test_initial_phases_seeded(temp_state):
    phases = temp_state.get_all_phases()
    assert len(phases) == 12
    phase_names = [p.name for p in phases]
    assert "audit" in phase_names
    assert "collection" in phase_names
    assert "train_logistic" in phase_names
    assert "train_ensemble" in phase_names


def test_phase_status_update_and_progress(temp_state):
    temp_state.set_phase_status("collection", STATUS_RUNNING, 50, "Ingesting samples")
    phase = temp_state.get_phase("collection")
    assert phase.status == STATUS_RUNNING
    assert phase.progress == 50
    assert phase.details == "Ingesting samples"

    temp_state.set_phase_status("collection", STATUS_COMPLETED, None, "Completed")
    phase_after = temp_state.get_phase("collection")
    assert phase_after.status == STATUS_COMPLETED
    assert phase_after.progress == 100
    assert phase_after.completed_at is not None


def test_active_job_lifecycle(temp_state):
    job_id = "test_job_001"
    temp_state.start_job(job_id, "Test ANN Training", "train_ann", total_epochs=20)
    job = temp_state.get_job(job_id)
    assert job["status"] == STATUS_RUNNING
    assert job["total_epochs"] == 20

    temp_state.update_job_progress(job_id, current_epoch=5, progress=25, checkpoint_path="/path/chk5.joblib")
    job_updated = temp_state.get_job(job_id)
    assert job_updated["current_epoch"] == 5
    assert job_updated["progress"] == 25
    assert job_updated["last_checkpoint"] == "/path/chk5.joblib"

    temp_state.mark_job_interrupted(job_id)
    job_int = temp_state.get_job(job_id)
    assert job_int["status"] == STATUS_INTERRUPTED

    temp_state.complete_job(job_id)
    job_comp = temp_state.get_job(job_id)
    assert job_comp["status"] == STATUS_COMPLETED


def test_experiment_recording(temp_state):
    temp_state.record_experiment(
        experiment_id="EXP-TEST-001",
        model_name="logistic",
        parameters={"C": 1.0},
        metrics={"f1": 0.89, "accuracy": 0.91},
        dataset_version="v1.0.0",
        dataset_hash="a1b2c3d4",
        duration_sec=1.5,
    )

    exp = temp_state.get_experiment("EXP-TEST-001")
    assert exp is not None
    assert exp.model_name == "logistic"
    assert exp.metrics["f1"] == 0.89
    assert exp.parameters["C"] == 1.0


def test_structured_logging(temp_state):
    temp_state.log("INFO", "Starting pipeline test", phase="test_phase")
    temp_state.log("ERROR", "Simulated failure", phase="test_phase", error_type="NETWORK_TIMEOUT")

    logs = temp_state.get_logs(limit=10)
    assert len(logs) == 2

    error_logs = temp_state.get_logs(errors_only=True)
    assert len(error_logs) == 1
    assert error_logs[0]["error_type"] == "NETWORK_TIMEOUT"
