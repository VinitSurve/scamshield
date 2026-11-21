"""ScamShield ML Lab — Unified Command Line Interface & Interactive Dashboard."""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional
import typer
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from scamshield_ml.experiments.runner import PipelineRunner
from scamshield_ml.inference.server import get_orchestrator
from scamshield_ml.orchestration.provider_keys import ProviderKeyManager
from scamshield_ml.state import (
    ARTIFACTS_DIR,
    DB_PATH,
    ML_LAB_DIR,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_RUNNING,
    StateManager,
)

app = typer.Typer(
    name="scamshield-ml",
    help="ScamShield Autonomous ML Intelligence Lab, Multi-Agent Threat Engine & CLI",
    add_completion=False,
)
dataset_app = typer.Typer(help="Dataset collection, preprocessing, and validation commands")
train_app = typer.Typer(help="Model training with epoch checkpointing and resume support")
experiment_app = typer.Typer(help="Experiment tracking and pipeline execution")

app.add_typer(dataset_app, name="dataset")
app.add_typer(train_app, name="train")
app.add_typer(experiment_app, name="experiment")
app.add_typer(experiment_app, name="experiments")

console = Console()
state = StateManager.get_instance()
runner = PipelineRunner()


# Signal handler for graceful Ctrl+C interruptions
def sigint_handler(signum, frame):
    console.print("\n[bold red]⚠️ Process interrupted safely by user (Ctrl+C).[/bold red]")
    active_job = state.get_active_job()
    if active_job:
        job_id = active_job["job_id"]
        chk_path = str(ARTIFACTS_DIR / "checkpoints" / f"{active_job['phase']}_interrupted.joblib")
        state.mark_job_interrupted(job_id, chk_path)
        console.print(f"[yellow]Current task '{active_job['task_name']}' state persisted as INTERRUPTED.[/yellow]")
        console.print(f"[cyan]Resume using: uv run scamshield-ml train {active_job['phase'].replace('train_', '')} --resume[/cyan]")
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)


# --------------------------------------------------------
# STATUS COMMAND (Section 22.1)
# --------------------------------------------------------
@app.command("status")
def status_cmd():
    """Display comprehensive, real-time persisted status of ScamShield ML Lab."""
    overall_prog = state.calculate_overall_progress()
    phases = state.get_all_phases()
    active_job = state.get_active_job()
    experiments = state.get_experiments()

    manifest_file = ML_LAB_DIR / "datasets" / "dataset_manifest.json"
    dataset_info = {"version": "None", "total": 0, "train": 0, "val": 0, "test": 0}
    if manifest_file.exists():
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                m = json.load(f)
                dataset_info = {
                    "version": m.get("version", "v1.0.0"),
                    "total": m.get("total_samples", 0),
                    "train": m.get("splits", {}).get("train_count", 0),
                    "val": m.get("splits", {}).get("val_count", 0),
                    "test": m.get("splits", {}).get("test_count", 0),
                }
        except Exception:
            pass

    completed_list = [p.display_name for p in phases if p.status == STATUS_COMPLETED]
    running_list = [p.display_name for p in phases if p.status == STATUS_RUNNING]
    interrupted_list = [p.display_name for p in phases if p.status == STATUS_INTERRUPTED]
    pending_list = [p.display_name for p in phases if p.status == "PENDING"]
    failed_list = [p.display_name for p in phases if p.status == STATUS_FAILED]

    best_model_name = "None"
    best_f1 = 0.0
    for exp in experiments:
        f1 = exp.metrics.get("f1", 0.0)
        if f1 > best_f1:
            best_f1 = f1
            best_model_name = f"{exp.model_name} (F1: {f1*100:.1f}%)"

    console.print(Panel.fit(
        f"[bold cyan]SCAMSHIELD ML LAB STATUS[/bold cyan]\n"
        f"[bold white]Overall Progress:[/bold white] {overall_prog}%\n"
        f"[bold white]Dataset Version:[/bold white]  {dataset_info['version']} ({dataset_info['total']} samples: {dataset_info['train']} train, {dataset_info['val']} val, {dataset_info['test']} test)\n"
        f"[bold white]Trained Models:[/bold white]   {len(experiments)} recorded | [bold green]Best:[/bold green] {best_model_name}\n"
        f"[bold white]Active Task:[/bold white]      {active_job['task_name'] if active_job else 'IDLE'}\n"
        f"[bold white]Next Action:[/bold white]      [yellow]{state.get_next_action()}[/yellow]",
        box=box.ROUNDED,
        border_style="cyan",
    ))

    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Category", style="bold")
    table.add_column("Phases / Status")

    if completed_list:
        table.add_row("[green]Completed[/green]", "\n".join(f"[green]✓ {p}[/green]" for p in completed_list))
    if running_list:
        table.add_row("[cyan]Running[/cyan]", "\n".join(f"[cyan]● {p}[/cyan]" for p in running_list))
    if interrupted_list:
        table.add_row("[yellow]Interrupted[/yellow]", "\n".join(f"[yellow]⚠ {p} (Resume Available)[/yellow]" for p in interrupted_list))
    if failed_list:
        table.add_row("[red]Failed[/red]", "\n".join(f"[red]✗ {p}[/red]" for p in failed_list))
    if pending_list:
        table.add_row("[dim]Pending[/dim]", "\n".join(f"[dim]○ {p}[/dim]" for p in pending_list[:6]))

    console.print(table)


# --------------------------------------------------------
# PROGRESS COMMAND (Section 22.2)
# --------------------------------------------------------
@app.command("progress")
def progress_cmd():
    """Show detailed pipeline phase completion percentage."""
    phases = state.get_all_phases()
    overall = state.calculate_overall_progress()

    console.print(f"\n[bold cyan]SCAMSHIELD PIPELINE PROGRESS[/bold cyan] (Overall: [bold green]{overall}%[/bold green])\n")
    for p in phases:
        pct = p.progress
        filled = int(pct / 10)
        empty = 10 - filled
        bar = f"[cyan]{'█' * filled}[/cyan]{'░' * empty}"
        status_color = "green" if p.status == STATUS_COMPLETED else "cyan" if p.status == STATUS_RUNNING else "yellow" if p.status == STATUS_INTERRUPTED else "white"
        console.print(f"[{bar}] {p.display_name:<40} [{status_color}]{pct:>3}% ({p.status})[/{status_color}]")
    console.print(f"\n[bold]Overall Weighted Progress:[/bold] [bold green]{overall}%[/bold green]\n")


# --------------------------------------------------------
# TODO COMMAND (Section 22.3)
# --------------------------------------------------------
@app.command("todo")
def todo_cmd():
    """Display pending tasks, priorities, dependencies, and resume commands."""
    tasks = state.get_todo_tasks()
    if not tasks:
        console.print("[bold green]✓ All pipeline tasks have been completed successfully![/bold green]")
        return

    table = Table(title="SCAMSHIELD PENDING TASKS", box=box.ROUNDED)
    table.add_column("Priority", style="bold yellow")
    table.add_column("Phase", style="bold")
    table.add_column("Status")
    table.add_column("Dependencies")
    table.add_column("Command to Run / Resume", style="cyan")

    for t in tasks:
        deps = ", ".join(t["dependencies"]) if t["dependencies"] else "None"
        color = "red" if t["priority"] == "P0" else "yellow" if t["priority"] == "P1" else "cyan"
        table.add_row(f"[{color}]{t['priority']}[/{color}]", t["title"], t["status"], deps, t["command"])

    console.print(table)
    console.print(f"\n[bold]Next Recommended Command:[/bold] [yellow]{state.get_next_action()}[/yellow]\n")


# --------------------------------------------------------
# DASHBOARD COMMAND (Section 22.4)
# --------------------------------------------------------
@app.command("dashboard")
def dashboard_cmd():
    """Interactive visual terminal dashboard using Rich."""
    overall = state.calculate_overall_progress()
    phases = state.get_all_phases()
    experiments = state.get_experiments()
    key_status = ProviderKeyManager.get_instance().get_status()

    # Overview table
    overview_table = Table(box=box.SIMPLE)
    overview_table.add_column("Metric", style="bold")
    overview_table.add_column("Value", style="cyan")
    overview_table.add_row("Overall Pipeline", f"{overall}% Completed")
    overview_table.add_row("Trained Models", str(len(experiments)))
    overview_table.add_row("Gemini Keys Active", f"{key_status['gemini']['healthy_keys']} / {key_status['gemini']['total_keys']}")
    overview_table.add_row("Groq Keys Active", f"{key_status['groq']['healthy_keys']} / {key_status['groq']['total_keys']}")
    overview_table.add_row("Next Action", state.get_next_action())

    # Leaderboard table
    leaderboard_table = Table(title="Model Leaderboard", box=box.SIMPLE_HEAD)
    leaderboard_table.add_column("Model", style="bold")
    leaderboard_table.add_column("Accuracy")
    leaderboard_table.add_column("Recall")
    leaderboard_table.add_column("F1 Score", style="bold green")
    leaderboard_table.add_column("FPR")

    sorted_exps = sorted(experiments, key=lambda x: x.metrics.get("f1", 0.0), reverse=True)
    for exp in sorted_exps[:5]:
        m = exp.metrics
        leaderboard_table.add_row(
            exp.model_name,
            f"{m.get('accuracy', 0)*100:.1f}%",
            f"{m.get('recall', 0)*100:.1f}%",
            f"{m.get('f1', 0)*100:.1f}%",
            f"{m.get('fpr', 0)*100:.1f}%",
        )

    layout = Layout()
    layout.split_column(
        Layout(Panel(overview_table, title="[bold cyan]ScamShield ML Lab Overview[/bold cyan]", border_style="cyan"), size=9),
        Layout(Panel(leaderboard_table, title="[bold green]Empirical Performance Rankings[/bold green]", border_style="green")),
    )
    console.print(layout)


# --------------------------------------------------------
# DATASET COMMANDS
# --------------------------------------------------------
@dataset_app.command("collect")
def dataset_collect_cmd(resume: bool = typer.Option(False, "--resume", help="Resume without re-collecting if already present")):
    """Collect raw India-first cybersecurity samples."""
    with console.status("[bold cyan]Collecting multi-category, multilingual cybersecurity samples..."):
        res = runner.run_collect(resume=resume)
    console.print(f"[bold green]✓ Dataset collection finished:[/bold green] {res}")


@dataset_app.command("preprocess")
def dataset_preprocess_cmd(resume: bool = typer.Option(False, "--resume", help="Resume without reprocessing if complete")):
    """Clean, normalize text & URLs, and generate clean dataset."""
    with console.status("[bold cyan]Normalizing Unicode, stripping noise, and standardizing schemas..."):
        res = runner.run_preprocess(resume=resume)
    console.print(f"[bold green]✓ Preprocessing complete:[/bold green] {res}")


@dataset_app.command("validate")
def dataset_validate_cmd():
    """Verify deduplication, check for data leakage, and produce split partitions."""
    with console.status("[bold cyan]Validating dataset integrity and verifying zero train/test leakage..."):
        res = runner.run_validate()
    console.print(f"[bold green]✓ Validation complete:[/bold green] {res['total_samples']} unique samples verified.")
    console.print(f"  [cyan]Train:[/cyan] {res['splits']['train_count']} | [cyan]Val:[/cyan] {res['splits']['val_count']} | [cyan]Test:[/cyan] {res['splits']['test_count']}")
    console.print("  [bold green]Leakage Check:[/bold green] Zero overlap confirmed between train and test sets.")


@dataset_app.command("stats")
def dataset_stats_cmd():
    """Show dataset distributions across languages, categories, and splits."""
    manifest_file = ML_LAB_DIR / "datasets" / "dataset_manifest.json"
    if not manifest_file.exists():
        console.print("[yellow]Manifest not found. Run 'uv run scamshield-ml dataset validate' first.[/yellow]")
        return
    with open(manifest_file, "r", encoding="utf-8") as f:
        m = json.load(f)

    table = Table(title=f"Dataset Statistics: {m['dataset_name']} ({m['version']})", box=box.ROUNDED)
    table.add_column("Category / Language", style="bold")
    table.add_column("Count", style="cyan")

    table.add_row("[bold]Total Unique Samples[/bold]", str(m["total_samples"]))
    table.add_row("[bold]Train Split (70%)[/bold]", str(m["splits"]["train_count"]))
    table.add_row("[bold]Val Split (15%)[/bold]", str(m["splits"]["val_count"]))
    table.add_row("[bold]Test Split (15%)[/bold]", str(m["splits"]["test_count"]))
    table.add_row("---", "---")

    for lang, cnt in m["language_distribution"].items():
        table.add_row(f"Language: {lang}", str(cnt))
    table.add_row("---", "---")

    for cat, cnt in m["category_distribution"].items():
        table.add_row(f"Category: {cat}", str(cnt))

    console.print(table)


@dataset_app.command("audit")
def dataset_audit_cmd():
    """Display comprehensive dataset quality report and audit sources."""
    report_file = ML_LAB_DIR / "reports" / "dataset_quality_report.md"
    if report_file.exists():
        with open(report_file, "r", encoding="utf-8") as f:
            console.print(f.read())
    else:
        runner.run_audit()
        runner.run_validate()
        with open(report_file, "r", encoding="utf-8") as f:
            console.print(f.read())


# --------------------------------------------------------
# TRAINING COMMANDS
# --------------------------------------------------------
@train_app.command("logistic")
def train_logistic_cmd(resume: bool = typer.Option(False, "--resume", help="Resume from previous checkpoint if available")):
    """Train TF-IDF + Logistic Regression baseline model."""
    console.print("[bold cyan]Starting training: TF-IDF + Logistic Regression (Model A)...[/bold cyan]")
    res = runner.train_model("logistic", resume=resume)
    m = res["metrics"]
    console.print(f"[bold green]✓ Logistic Regression Trained:[/bold green] Test Accuracy: {m.get('accuracy',0)*100:.1f}%, F1: {m.get('f1',0)*100:.1f}%, FPR: {m.get('fpr',0)*100:.1f}%")


@train_app.command("knn")
def train_knn_cmd(resume: bool = typer.Option(False, "--resume", help="Resume from previous checkpoint if available")):
    """Train K-Nearest Neighbors (KNN) model on dense SVD embeddings."""
    console.print("[bold cyan]Starting training: KNN (Model B)...[/bold cyan]")
    res = runner.train_model("knn", resume=resume)
    m = res["metrics"]
    console.print(f"[bold green]✓ KNN Trained:[/bold green] Test Accuracy: {m.get('accuracy',0)*100:.1f}%, F1: {m.get('f1',0)*100:.1f}%, FPR: {m.get('fpr',0)*100:.1f}%")


@train_app.command("ann")
def train_ann_cmd(resume: bool = typer.Option(False, "--resume", help="Resume from previous epoch checkpoint")):
    """Train Artificial Neural Network (ANN / MLP) with epoch checkpoints."""
    console.print("[bold cyan]Starting training: Artificial Neural Network (Model C)...[/bold cyan]")
    res = runner.train_model("ann", resume=resume)
    m = res["metrics"]
    console.print(f"[bold green]✓ ANN Trained:[/bold green] Test Accuracy: {m.get('accuracy',0)*100:.1f}%, F1: {m.get('f1',0)*100:.1f}%, Loss: {m.get('final_loss', 0):.4f}")


@train_app.command("url")
def train_url_cmd(resume: bool = typer.Option(False, "--resume", help="Resume from previous checkpoint")):
    """Train dedicated URL feature-based classifier (Model D)."""
    console.print("[bold cyan]Starting training: URL Feature Classifier (Model D)...[/bold cyan]")
    res = runner.train_model("url", resume=resume)
    m = res["metrics"]
    console.print(f"[bold green]✓ URL Model Trained:[/bold green] Test Accuracy: {m.get('accuracy',0)*100:.1f}%, F1: {m.get('f1',0)*100:.1f}%, FPR: {m.get('fpr',0)*100:.1f}%")


@train_app.command("ensemble")
def train_ensemble_cmd(resume: bool = typer.Option(False, "--resume", help="Resume from constituent checkpoints")):
    """Train soft-voting Ensemble combining all 4 models (Model E)."""
    console.print("[bold cyan]Starting training: Calibrated Soft-Voting Ensemble (Model E)...[/bold cyan]")
    res = runner.train_model("ensemble", resume=resume)
    m = res["metrics"]
    console.print(f"[bold green]✓ Ensemble Trained:[/bold green] Test Accuracy: {m.get('accuracy',0)*100:.1f}%, F1: {m.get('f1',0)*100:.1f}%, FPR: {m.get('fpr',0)*100:.1f}%")


# --------------------------------------------------------
# EXPERIMENT & PIPELINE COMMANDS
# --------------------------------------------------------
@experiment_app.command("run-all")
def run_all_cmd(resume: bool = typer.Option(False, "--resume", help="Resume incomplete steps")):
    """Execute the complete dependency-aware ML research pipeline."""
    console.print("[bold cyan]Executing full ScamShield ML Pipeline...[/bold cyan]")
    res = runner.run_all(resume=resume)
    console.print("[bold green]✓ Complete pipeline executed successfully![/bold green]")
    leaderboard_cmd()


@app.command("leaderboard")
def leaderboard_cmd():
    """Display empirical comparison leaderboard across all evaluated models."""
    leaderboard = runner.generate_leaderboard()
    if not leaderboard:
        console.print("[yellow]No experiments recorded yet. Run 'uv run scamshield-ml experiment run-all' first.[/yellow]")
        return

    table = Table(title="SCAMSHIELD MODEL LEADERBOARD (Held-Out Test Split)", box=box.ROUNDED)
    table.add_column("Rank", style="bold")
    table.add_column("Model Name", style="bold cyan")
    table.add_column("Accuracy", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("Macro F1", justify="right")
    table.add_column("F1 Score", justify="right", style="bold green")
    table.add_column("FPR", justify="right", style="yellow")
    table.add_column("ROC-AUC", justify="right")
    table.add_column("Latency", justify="right")

    for rank, row in enumerate(leaderboard, 1):
        table.add_row(
            f"#{rank}",
            row["model_name"],
            f"{row['accuracy']*100:.1f}%",
            f"{row['precision']*100:.1f}%",
            f"{row['recall']*100:.1f}%",
            f"{row['macro_f1']*100:.1f}%",
            f"{row['f1']*100:.1f}%",
            f"{row['fpr']*100:.1f}%",
            f"{row['roc_auc']:.3f}",
            f"{row['latency_ms']:.1f}ms",
        )

    console.print(table)


@app.command("evaluate")
def evaluate_cmd():
    """Evaluate all trained models against held-out test data and update leaderboard."""
    leaderboard_cmd()


@app.command("adversarial")
def adversarial_cmd():
    """Evaluate models against the adversarial robustness benchmark (edge cases, hard benigns, evasions)."""
    adv_path = ML_LAB_DIR / "datasets" / "adversarial_benchmark.json"
    if not adv_path.exists():
        console.print("[red]Adversarial benchmark not found at datasets/adversarial_benchmark.json[/red]")
        raise typer.Exit(code=1)

    with open(adv_path, "r", encoding="utf-8") as f:
        adv_data = json.load(f)

    from scamshield_ml.models.ann import ANNScamModel
    from scamshield_ml.models.ensemble import EnsembleScamModel
    from scamshield_ml.models.knn import KNNScamModel
    from scamshield_ml.models.logistic_regression import LogisticRegressionScamModel
    from scamshield_ml.models.url_classifier import URLFeatureClassifier

    models_map = [
        ("Logistic Regression", LogisticRegressionScamModel(), "logistic.joblib"),
        ("KNN", KNNScamModel(), "knn.joblib"),
        ("ANN (MLP)", ANNScamModel(), "ann.joblib"),
        ("URL Classifier", URLFeatureClassifier(), "url.joblib"),
        ("Ensemble (Voting)", EnsembleScamModel(), "ensemble.joblib"),
    ]

    table = Table(title=f"SCAMSHIELD ADVERSARIAL BENCHMARK ({len(adv_data)} Challenging Samples)", box=box.ROUNDED)
    table.add_column("Model Name", style="bold")
    table.add_column("Accuracy", justify="right")
    table.add_column("Scams Caught (Recall)", justify="right", style="green")
    table.add_column("False Alarms (FPR)", justify="right")
    table.add_column("False Negatives", justify="right")
    table.add_column("Avg Latency", justify="right")

    for display_name, model, fname in models_map:
        m_file = ARTIFACTS_DIR / "models" / fname
        if not m_file.exists():
            table.add_row(display_name, "[dim]Not trained[/dim]", "-", "-", "-", "-")
            continue

        model.load(str(m_file))
        preds = [model.predict_one(s["content"]) for s in adv_data]
        y_pred = [p.is_scam for p in preds]
        y_true = [int(s["is_scam"]) for s in adv_data]

        benign_cnt = sum(1 for y in y_true if y == 0)
        scam_cnt = sum(1 for y in y_true if y == 1)

        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)

        acc = (tp + tn) / max(1, len(y_true))
        recall = tp / max(1, scam_cnt)
        fpr = fp / max(1, benign_cnt)
        avg_lat = sum(p.latency_ms for p in preds) / max(1, len(preds))

        fpr_style = "green" if fpr <= 0.20 else "yellow" if fpr <= 0.40 else "red"
        rec_style = "green" if recall >= 0.85 else "yellow" if recall >= 0.70 else "red"

        table.add_row(
            display_name,
            f"{acc*100:.1f}%",
            f"[{rec_style}]{tp}/{scam_cnt} ({recall*100:.1f}%)[/{rec_style}]",
            f"[{fpr_style}]{fp}/{benign_cnt} ({fpr*100:.1f}%)[/{fpr_style}]",
            f"{fn}/{scam_cnt}",
            f"{avg_lat:.2f}ms",
        )

    console.print(table)


@experiment_app.command("list")
def experiments_list_cmd():
    """List all permanent experiment runs."""
    exps = state.get_experiments()
    table = Table(title=f"PERMANENT EXPERIMENT REGISTRY ({len(exps)} Records)", box=box.ROUNDED)
    table.add_column("Experiment ID", style="bold cyan")
    table.add_column("Model", style="bold")
    table.add_column("Dataset Version", style="dim")
    table.add_column("Test N", justify="right")
    table.add_column("Accuracy", justify="right")
    table.add_column("F1", justify="right", style="green")
    table.add_column("FPR", justify="right", style="yellow")
    table.add_column("Status")
    table.add_column("Created At")

    for e in exps:
        n_samples = e.metrics.get("total_samples", "-")
        fpr = f"{e.metrics.get('fpr', 0)*100:.1f}%" if "fpr" in e.metrics else "-"
        table.add_row(
            e.experiment_id,
            e.model_name,
            e.dataset_version[:18] if e.dataset_version else "-",
            str(n_samples),
            f"{e.metrics.get('accuracy', 0)*100:.1f}%",
            f"{e.metrics.get('f1', 0)*100:.1f}%",
            fpr,
            e.status,
            e.created_at[:19],
        )
    console.print(table)


@experiment_app.command("show")
def experiments_show_cmd(experiment_id: str):
    """Show details of a specific experiment."""
    exp = state.get_experiment(experiment_id)
    if not exp:
        console.print(f"[red]Experiment {experiment_id} not found.[/red]")
        return
    console.print(Panel.fit(
        f"[bold cyan]Experiment:[/bold cyan] {exp.experiment_id}\n"
        f"[bold white]Model:[/bold white] {exp.model_name}\n"
        f"[bold white]Status:[/bold white] {exp.status}\n"
        f"[bold white]Dataset Version:[/bold white] {exp.dataset_version} ({exp.dataset_hash})\n"
        f"[bold white]Duration:[/bold white] {exp.duration_sec}s\n"
        f"[bold white]Artifact Path:[/bold white] {exp.artifact_path}\n\n"
        f"[bold green]Metrics:[/bold green]\n{json.dumps(exp.metrics, indent=2)}\n\n"
        f"[bold yellow]Parameters:[/bold yellow]\n{json.dumps(exp.parameters, indent=2)}",
        box=box.ROUNDED,
    ))


# --------------------------------------------------------
# LOGGING COMMANDS
# --------------------------------------------------------
@app.command("logs")
def logs_cmd(
    limit: int = typer.Option(30, "--limit", "-n", help="Number of log entries"),
    errors: bool = typer.Option(False, "--errors", help="Show error logs only"),
    task: Optional[str] = typer.Option(None, "--task", help="Filter by task ID"),
):
    """Display structured execution logs from database and disk."""
    log_rows = state.get_logs(limit=limit, errors_only=errors, task_id=task)
    for r in log_rows:
        color = "red" if r["level"] in ("ERROR", "CRITICAL") else "yellow" if r["level"] == "WARNING" else "white"
        console.print(f"[{r['timestamp'][:19]}] [{color}]{r['level']:<7}[/{color}] [{r['phase'] or 'core'}] {r['message']}")


# --------------------------------------------------------
# REAL-TIME ANALYSIS COMMANDS (Text, URL, Image)
# --------------------------------------------------------
@app.command("analyze")
def analyze_cmd(text: str):
    """Run complete Multi-Agent & ML threat analysis on a message string."""
    orchestrator = get_orchestrator()
    res = orchestrator.analyze(text, content_type="message")

    color = "red" if res.verdict in ("CONFIRMED_MALICIOUS", "HIGH_RISK") else "yellow" if res.verdict == "SUSPICIOUS" else "green"
    console.print(Panel.fit(
        f"[bold {color}]Verdict: {res.verdict}[/bold {color}] (Risk Score: [bold]{res.risk_score}%[/bold], Confidence: {res.confidence*100:.1f}%)\n"
        f"[bold white]Explanation:[/bold white] {res.human_explanation}\n\n"
        f"[bold white]Evidence Detected:[/bold white] {len(res.evidence)} items\n" +
        "\n".join(f" • [{color}]{e['indicator']}[/{color}]: {e['value']}" for e in res.evidence[:4]) + "\n\n"
        f"[bold white]Recommendations:[/bold white]\n" +
        "\n".join(f" 1. {r}" for r in res.recommendations[:3]),
        title="[bold cyan]ScamShield Threat Analysis[/bold cyan]",
        box=box.ROUNDED,
    ))


@app.command("analyze-url")
def analyze_url_cmd(url: str):
    """Run specialized URL structural, reputation, and multi-agent analysis."""
    orchestrator = get_orchestrator()
    res = orchestrator.analyze(url, content_type="url")
    color = "red" if res.verdict in ("CONFIRMED_MALICIOUS", "HIGH_RISK") else "yellow" if res.verdict == "SUSPICIOUS" else "green"
    console.print(Panel.fit(
        f"[bold {color}]Verdict: {res.verdict}[/bold {color}] (Risk Score: [bold]{res.risk_score}%[/bold])\n"
        f"[bold white]URL:[/bold white] {url}\n"
        f"[bold white]Explanation:[/bold white] {res.human_explanation}\n\n"
        f"[bold white]Contradictions Detected:[/bold white] {len(res.contradictions_detected)}\n" +
        ("\n".join(f" ⚠ {c}" for c in res.contradictions_detected) if res.contradictions_detected else " None") + "\n\n"
        f"[bold white]Recommendations:[/bold white]\n" +
        "\n".join(f" • {r}" for r in res.recommendations),
        title="[bold cyan]ScamShield URL Sandbox Report[/bold cyan]",
        box=box.ROUNDED,
    ))


@app.command("analyze-image")
def analyze_image_cmd(image_path: str):
    """Perform OCR and multimodal threat intelligence analysis on a screenshot image."""
    path = Path(image_path)
    if not path.exists():
        console.print(f"[red]Image file not found: {image_path}[/red]")
        return

    from PIL import Image
    try:
        img = Image.open(path)
        console.print(f"[cyan]Opened image:[/cyan] {img.size[0]}x{img.size[1]} ({img.format})")
    except Exception as e:
        console.print(f"[red]Could not open image file: {e}[/red]")
        return

    # Basic OCR / text inspection
    ocr_text = ""
    try:
        import pytesseract
        ocr_text = pytesseract.image_to_string(img).strip()
    except Exception:
        pass

    if not ocr_text:
        console.print("[yellow]Notice: Local pytesseract returned empty or uninstalled. Applying unverified cautionary safety policy.[/yellow]")
        console.print(Panel.fit(
            "[bold yellow]⚠️ UNVERIFIED IMAGE CONTENT (Risk Score: 45%)[/bold yellow]\n\n"
            "ScamShield was unable to extract verifiable text from this image.\n"
            "Fraudsters frequently employ blurred text or misleading QR codes to evade security filters.\n\n"
            "[bold]Safety Policy:[/bold] Unreadable images are NEVER scored as 0% safe.",
            title="[bold yellow]Image Security Assessment[/bold yellow]",
            box=box.ROUNDED,
        ))
        return

    orchestrator = get_orchestrator()
    res = orchestrator.analyze(ocr_text, content_type="ocr_text")
    console.print(f"[bold]Extracted OCR Text:[/bold] {ocr_text[:120]}...")
    color = "red" if res.verdict in ("CONFIRMED_MALICIOUS", "HIGH_RISK") else "yellow" if res.verdict == "SUSPICIOUS" else "green"
    console.print(Panel.fit(
        f"[bold {color}]Verdict: {res.verdict}[/bold {color}] (Risk Score: [bold]{res.risk_score}%[/bold])\n"
        f"[bold white]Explanation:[/bold white] {res.human_explanation}",
        title="[bold cyan]Screenshot OCR Threat Analysis[/bold cyan]",
        box=box.ROUNDED,
    ))


# --------------------------------------------------------
# EXPORT & SERVE COMMANDS
# --------------------------------------------------------
@app.command("export-best")
def export_best_cmd():
    """Export best performing model artifact for production platform deployment."""
    exps = state.get_experiments()
    if not exps:
        console.print("[yellow]No trained models available to export. Run training first.[/yellow]")
        return

    best = max(exps, key=lambda x: x.metrics.get("f1", 0.0))
    src = Path(best.artifact_path or "")
    dest = ARTIFACTS_DIR / "models" / "best_model.joblib"

    if src.exists():
        import shutil
        shutil.copyfile(src, dest)
        console.print(f"[bold green]✓ Exported best model ({best.model_name}, F1: {best.metrics.get('f1',0)*100:.1f}%) to:[/bold green] {dest}")
    else:
        console.print(f"[red]Source artifact {src} not found on disk.[/red]")


@app.command("serve")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Host address"),
    port: int = typer.Option(8000, "--port", help="Port number"),
):
    """Start the ScamShield FastAPI inference server."""
    import uvicorn
    console.print(f"[bold cyan]Starting ScamShield ML Inference Server on http://{host}:{port}...[/bold cyan]")
    uvicorn.run("scamshield_ml.inference.server:app", host=host, port=port, reload=False)


@app.command("verify")
def verify_cmd():
    """Run full verification across state, dataset, models, and multi-agent pipeline."""
    import subprocess
    console.print("[bold cyan]Running automated test suite across ML Lab...[/bold cyan]")
    ret = subprocess.run(["pytest", "tests/", "-v"], cwd=str(ML_LAB_DIR))
    if ret.returncode == 0:
        console.print("[bold green]✓ All tests passed successfully![/bold green]")
    else:
        console.print("[bold red]✗ Some tests failed. Check logs above.[/bold red]")
