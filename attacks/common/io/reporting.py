from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from attacks.common.models import AnalysisReport, TimingSample

logger = logging.getLogger(__name__)


def create_run_directory(base_results_dir: Path, attack_name: str) -> Path:
    """Create a timestamped directory for a single attack run."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    run_directory = base_results_dir / attack_name / timestamp
    run_directory.mkdir(parents=True, exist_ok=True)

    plots_directory = run_directory / "plots"
    plots_directory.mkdir(exist_ok=True)

    logger.info("Created run directory: %s", run_directory)
    return run_directory


def save_timing_samples_csv(samples: list[TimingSample], output_path: Path) -> None:
    """Write timing samples to a CSV file."""
    with open(output_path, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["password_group", "attempt", "response_time_ns", "timestamp"])
        for sample in samples:
            writer.writerow([
                sample.password_group,
                sample.attempt,
                sample.response_time_ns,
                sample.timestamp,
            ])

    logger.info("Saved %d timing samples to %s", len(samples), output_path)


def save_metadata(
    output_path: Path,
    attack_name: str,
    config_dict: dict,
    software_versions: dict | None = None,
    netem_profile: str = "clean",
) -> None:
    """Write experiment metadata for reproducibility."""
    metadata = {
        "attack_name": attack_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config": config_dict,
        "netem_profile": netem_profile,
        "software_versions": software_versions or {},
    }

    with open(output_path, "w") as json_file:
        json.dump(metadata, json_file, indent=2)

    logger.info("Saved metadata to %s", output_path)


def save_analysis_report(report: AnalysisReport, output_path: Path) -> None:
    """Write the analysis report as JSON."""
    report_dict = {
        "attack_name": report.attack_name,
        "success": report.success,
        "summary": report.summary,
        "raw_csv_path": str(report.raw_csv_path),
        "plots": [str(plot_path) for plot_path in report.plots],
        "metadata": report.metadata,
    }

    with open(output_path, "w") as json_file:
        json.dump(report_dict, json_file, indent=2)

    logger.info("Saved analysis report to %s", output_path)


def load_timing_samples_csv(input_path: Path) -> list[TimingSample]:
    """Load timing samples from a CSV file."""
    samples = []
    with open(input_path, newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            samples.append(TimingSample(
                password_group=row["password_group"],
                attempt=int(row["attempt"]),
                response_time_ns=int(row["response_time_ns"]),
                timestamp=float(row["timestamp"]),
            ))

    logger.info("Loaded %d timing samples from %s", len(samples), input_path)
    return samples
