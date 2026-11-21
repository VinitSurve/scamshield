"""Persistent State & Experiment Registry for ScamShield ML Lab.

Uses an SQLite transactional database to record pipeline phases, jobs,
checkpoints, experiments, logs, and API health across sessions.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Base paths
ML_LAB_DIR = Path(__file__).resolve().parent.parent.parent
STATE_DIR = ML_LAB_DIR / "state"
LOGS_DIR = ML_LAB_DIR / "logs"
ARTIFACTS_DIR = ML_LAB_DIR / "artifacts"
CHECKPOINTS_DIR = ARTIFACTS_DIR / "checkpoints"
DB_PATH = STATE_DIR / "scamshield_ml.db"
LOG_FILE = LOGS_DIR / "pipeline.log"

STATE_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
(ARTIFACTS_DIR / "models").mkdir(parents=True, exist_ok=True)
(ARTIFACTS_DIR / "preprocessing").mkdir(parents=True, exist_ok=True)


# Status enumerations
STATUS_PENDING = "PENDING"
STATUS_QUEUED = "QUEUED"
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_INTERRUPTED = "INTERRUPTED"
STATUS_PAUSED = "PAUSED"
STATUS_BLOCKED = "BLOCKED"
STATUS_SKIPPED = "SKIPPED"

# Standard pipeline phases with weights for overall progress
PIPELINE_PHASES = [
    ("audit", "Repository & Architecture Audit", 5, []),
    ("collection", "Dataset Collection & Ingestion", 10, ["audit"]),
    ("cleaning", "Dataset Cleaning & Normalization", 10, ["collection"]),
    ("validation", "Dataset Quality & Leakage Validation", 10, ["cleaning"]),
    ("train_logistic", "Baseline Model (TF-IDF + Logistic Regression)", 10, ["validation"]),
    ("train_knn", "K-Nearest Neighbors (KNN)", 10, ["validation"]),
    ("train_ann", "Artificial Neural Network (ANN / MLP)", 15, ["validation"]),
    ("train_url", "URL Structural Classifier", 10, ["validation"]),
    ("train_ensemble", "Ensemble Learning (Soft Voting)", 10, ["train_logistic", "train_knn", "train_ann", "train_url"]),
    ("multi_agent", "Multi-Agent Threat Intelligence", 10, ["train_ensemble"]),
    ("platform_integration", "Inference Server & Platform Integration", 5, ["train_ensemble"]),
    ("verification", "Comprehensive Verification Suite", 5, ["multi_agent", "platform_integration"]),
]


@dataclass
class PhaseInfo:
    name: str
    display_name: str
    status: str
    progress: int
    started_at: Optional[str]
    completed_at: Optional[str]
    details: str
    last_checkpoint: Optional[str]
    weight: int
    dependencies: List[str]


@dataclass
class ExperimentInfo:
    experiment_id: str
    model_name: str
    parameters: Dict[str, Any]
    metrics: Dict[str, Any]
    dataset_version: str
    dataset_hash: str
    duration_sec: float
    status: str
    checkpoint_path: Optional[str]
    artifact_path: Optional[str]
    notes: str
    created_at: str


class StateManager:
    """Thread-safe SQLite state manager for pipeline tracking and experiment registry."""

    _instance: Optional[StateManager] = None

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    @classmethod
    def get_instance(cls) -> StateManager:
        if cls._instance is None:
            cls._instance = StateManager()
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cur = conn.cursor()
            # Pipeline phases table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_phases (
                    name TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    details TEXT,
                    last_checkpoint TEXT,
                    weight INTEGER NOT NULL DEFAULT 10,
                    dependencies TEXT
                )
            """)

            # Experiments table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id TEXT PRIMARY KEY,
                    model_name TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    metrics TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
                    dataset_hash TEXT NOT NULL,
                    duration_sec REAL NOT NULL DEFAULT 0.0,
                    status TEXT NOT NULL,
                    checkpoint_path TEXT,
                    artifact_path TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            # Active Jobs / Checkpoints table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS active_jobs (
                    job_id TEXT PRIMARY KEY,
                    task_name TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    current_epoch INTEGER DEFAULT 0,
                    total_epochs INTEGER DEFAULT 0,
                    last_checkpoint TEXT,
                    checkpoint_data TEXT,
                    error_message TEXT,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # API Keys health table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    masked_key TEXT NOT NULL,
                    is_healthy INTEGER NOT NULL DEFAULT 1,
                    last_checked TEXT,
                    last_used TEXT,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    cooldown_until REAL NOT NULL DEFAULT 0.0,
                    notes TEXT
                )
            """)

            # Logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    task_id TEXT,
                    phase TEXT,
                    message TEXT NOT NULL,
                    error_type TEXT
                )
            """)

            # Seed default pipeline phases if empty
            for name, display, weight, deps in PIPELINE_PHASES:
                cur.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_phases
                    (name, display_name, status, progress, weight, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, display, STATUS_PENDING, 0, weight, json.dumps(deps)),
                )
            conn.commit()

    # ----------------------------------------------------
    # Phase & Progress Methods
    # ----------------------------------------------------
    def get_phase(self, name: str) -> Optional[PhaseInfo]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM pipeline_phases WHERE name = ?", (name,)).fetchone()
            if not row:
                return None
            return PhaseInfo(
                name=row["name"],
                display_name=row["display_name"],
                status=row["status"],
                progress=row["progress"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                details=row["details"] or "",
                last_checkpoint=row["last_checkpoint"],
                weight=row["weight"],
                dependencies=json.loads(row["dependencies"] or "[]"),
            )

    def get_all_phases(self) -> List[PhaseInfo]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM pipeline_phases ORDER BY rowid ASC").fetchall()
            return [
                PhaseInfo(
                    name=r["name"],
                    display_name=r["display_name"],
                    status=r["status"],
                    progress=r["progress"],
                    started_at=r["started_at"],
                    completed_at=r["completed_at"],
                    details=r["details"] or "",
                    last_checkpoint=r["last_checkpoint"],
                    weight=r["weight"],
                    dependencies=json.loads(r["dependencies"] or "[]"),
                )
                for r in rows
            ]

    def set_phase_status(
        self,
        name: str,
        status: str,
        progress: Optional[int] = None,
        details: Optional[str] = None,
        last_checkpoint: Optional[str] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            current = conn.execute("SELECT started_at FROM pipeline_phases WHERE name = ?", (name,)).fetchone()
            started_at = current["started_at"] if current and current["started_at"] else now_iso
            completed_at = now_iso if status == STATUS_COMPLETED else None

            updates = ["status = ?"]
            params: List[Any] = [status]

            if progress is not None:
                updates.append("progress = ?")
                params.append(progress)
            elif status == STATUS_COMPLETED:
                updates.append("progress = 100")

            if details is not None:
                updates.append("details = ?")
                params.append(details)

            if last_checkpoint is not None:
                updates.append("last_checkpoint = ?")
                params.append(last_checkpoint)

            if status == STATUS_RUNNING and not current["started_at"]:
                updates.append("started_at = ?")
                params.append(now_iso)

            if completed_at:
                updates.append("completed_at = ?")
                params.append(completed_at)

            params.append(name)
            query = f"UPDATE pipeline_phases SET {', '.join(updates)} WHERE name = ?"
            conn.execute(query, params)
            conn.commit()

        self.log(
            level="INFO",
            message=f"Phase '{name}' status set to {status} (progress: {progress or 0}%)",
            phase=name,
        )

    def calculate_overall_progress(self) -> float:
        phases = self.get_all_phases()
        total_weight = sum(p.weight for p in phases)
        if total_weight == 0:
            return 0.0
        weighted_progress = sum((p.progress / 100.0) * p.weight for p in phases)
        return round((weighted_progress / total_weight) * 100.0, 1)

    # ----------------------------------------------------
    # Active Jobs & Checkpoints
    # ----------------------------------------------------
    def start_job(
        self,
        job_id: str,
        task_name: str,
        phase: str,
        total_epochs: int = 1,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO active_jobs
                (job_id, task_name, phase, status, progress, current_epoch, total_epochs, started_at, updated_at)
                VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?)
                """,
                (job_id, task_name, phase, STATUS_RUNNING, total_epochs, now_iso, now_iso),
            )
            conn.commit()

    def update_job_progress(
        self,
        job_id: str,
        current_epoch: int,
        progress: int,
        checkpoint_path: Optional[str] = None,
        checkpoint_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        data_json = json.dumps(checkpoint_data) if checkpoint_data else None
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE active_jobs
                SET current_epoch = ?, progress = ?, last_checkpoint = coalesce(?, last_checkpoint),
                    checkpoint_data = coalesce(?, checkpoint_data), updated_at = ?
                WHERE job_id = ?
                """,
                (current_epoch, progress, checkpoint_path, data_json, now_iso, job_id),
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM active_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return None
            return dict(row)

    def get_active_job(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM active_jobs WHERE status = ? ORDER BY updated_at DESC LIMIT 1",
                (STATUS_RUNNING,),
            ).fetchone()
            if not row:
                return None
            return dict(row)

    def mark_job_interrupted(self, job_id: str, checkpoint_path: Optional[str] = None) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE active_jobs
                SET status = ?, last_checkpoint = coalesce(?, last_checkpoint), updated_at = ?
                WHERE job_id = ?
                """,
                (STATUS_INTERRUPTED, checkpoint_path, now_iso, job_id),
            )
            conn.commit()

    def complete_job(self, job_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE active_jobs SET status = ?, progress = 100, updated_at = ? WHERE job_id = ?",
                (STATUS_COMPLETED, now_iso, job_id),
            )
            conn.commit()

    # ----------------------------------------------------
    # Experiments Registry
    # ----------------------------------------------------
    def record_experiment(
        self,
        experiment_id: str,
        model_name: str,
        parameters: Dict[str, Any],
        metrics: Dict[str, Any],
        dataset_version: str,
        dataset_hash: str,
        duration_sec: float,
        status: str = STATUS_COMPLETED,
        checkpoint_path: Optional[str] = None,
        artifact_path: Optional[str] = None,
        notes: str = "",
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO experiments
                (experiment_id, model_name, parameters, metrics, dataset_version, dataset_hash,
                 duration_sec, status, checkpoint_path, artifact_path, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    experiment_id,
                    model_name,
                    json.dumps(parameters),
                    json.dumps(metrics),
                    dataset_version,
                    dataset_hash,
                    duration_sec,
                    status,
                    checkpoint_path,
                    artifact_path,
                    notes,
                    now_iso,
                ),
            )
            conn.commit()

    def get_experiments(self) -> List[ExperimentInfo]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM experiments ORDER BY created_at DESC").fetchall()
            return [
                ExperimentInfo(
                    experiment_id=r["experiment_id"],
                    model_name=r["model_name"],
                    parameters=json.loads(r["parameters"] or "{}"),
                    metrics=json.loads(r["metrics"] or "{}"),
                    dataset_version=r["dataset_version"],
                    dataset_hash=r["dataset_hash"],
                    duration_sec=r["duration_sec"],
                    status=r["status"],
                    checkpoint_path=r["checkpoint_path"],
                    artifact_path=r["artifact_path"],
                    notes=r["notes"] or "",
                    created_at=r["created_at"],
                )
                for r in rows
            ]

    def get_experiment(self, experiment_id: str) -> Optional[ExperimentInfo]:
        with self._get_connection() as conn:
            r = conn.execute("SELECT * FROM experiments WHERE experiment_id = ?", (experiment_id,)).fetchone()
            if not r:
                return None
            return ExperimentInfo(
                experiment_id=r["experiment_id"],
                model_name=r["model_name"],
                parameters=json.loads(r["parameters"] or "{}"),
                metrics=json.loads(r["metrics"] or "{}"),
                dataset_version=r["dataset_version"],
                dataset_hash=r["dataset_hash"],
                duration_sec=r["duration_sec"],
                status=r["status"],
                checkpoint_path=r["checkpoint_path"],
                artifact_path=r["artifact_path"],
                notes=r["notes"] or "",
                created_at=r["created_at"],
            )

    # ----------------------------------------------------
    # Logging
    # ----------------------------------------------------
    def log(
        self,
        level: str,
        message: str,
        task_id: Optional[str] = None,
        phase: Optional[str] = None,
        error_type: Optional[str] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO pipeline_logs (timestamp, level, task_id, phase, message, error_type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now_iso, level.upper(), task_id, phase, message, error_type),
            )
            conn.commit()

        # Write to log file
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{now_iso}] [{level.upper()}] [{phase or 'core'}] {message}\n")
        except Exception:
            pass

    def get_logs(self, limit: int = 50, errors_only: bool = False, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM pipeline_logs WHERE 1=1"
            params: List[Any] = []
            if errors_only:
                query += " AND level IN ('ERROR', 'CRITICAL')"
            if task_id:
                query += " AND task_id = ?"
                params.append(task_id)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in reversed(rows)]

    # ----------------------------------------------------
    # Next Action & Pending Tasks (TODO)
    # ----------------------------------------------------
    def get_todo_tasks(self) -> List[Dict[str, Any]]:
        phases = self.get_all_phases()
        todo = []
        for p in phases:
            if p.status != STATUS_COMPLETED:
                p_level = "P0" if p.name in ["audit", "collection", "cleaning", "validation", "train_logistic"] else "P1"
                if p.name in ["verification", "platform_integration"]:
                    p_level = "P2"
                todo.append({
                    "phase": p.name,
                    "title": p.display_name,
                    "status": p.status,
                    "priority": p_level,
                    "dependencies": p.dependencies,
                    "progress": p.progress,
                    "command": f"uv run scamshield-ml train {p.name.replace('train_', '')} --resume" if p.name.startswith("train_") else f"uv run scamshield-ml {p.name} --resume",
                })
        return todo

    def get_next_action(self) -> str:
        # Check for interrupted jobs
        with self._get_connection() as conn:
            interrupted = conn.execute(
                "SELECT * FROM active_jobs WHERE status = ? ORDER BY updated_at DESC LIMIT 1",
                (STATUS_INTERRUPTED,),
            ).fetchone()
            if interrupted:
                return f"Resume interrupted {interrupted['task_name']}: uv run scamshield-ml train {interrupted['phase'].replace('train_', '')} --resume"

        # Check for first uncompleted phase whose dependencies are met
        phases = self.get_all_phases()
        completed_names = {p.name for p in phases if p.status == STATUS_COMPLETED}
        for p in phases:
            if p.status != STATUS_COMPLETED:
                deps_met = all(dep in completed_names for dep in p.dependencies)
                if deps_met:
                    if p.name.startswith("train_"):
                        model_cmd = p.name.replace("train_", "")
                        return f"Train {p.display_name}: uv run scamshield-ml train {model_cmd} --resume"
                    elif p.name == "collection":
                        return "Collect and prepare dataset: uv run scamshield-ml dataset collect --resume"
                    elif p.name == "cleaning":
                        return "Preprocess & clean dataset: uv run scamshield-ml dataset preprocess --resume"
                    elif p.name == "validation":
                        return "Validate dataset quality & leakage: uv run scamshield-ml dataset validate"
                    elif p.name == "audit":
                        return "Run repository audit: uv run scamshield-ml dataset audit"
                    elif p.name == "multi_agent":
                        return "Run multi-agent security evaluation: uv run scamshield-ml evaluate"
                    elif p.name == "platform_integration":
                        return "Serve inference API: uv run scamshield-ml serve"
                    elif p.name == "verification":
                        return "Run complete verification: uv run scamshield-ml verify"
                    return f"Run phase {p.name}"

        return "All pipeline phases completed successfully! Run 'uv run scamshield-ml leaderboard' or 'uv run scamshield-ml serve'"
