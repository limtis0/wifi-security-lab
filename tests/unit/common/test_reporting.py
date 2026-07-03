from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacks.common.models import TimingSample
from attacks.common.io.reporting import (
    create_run_directory,
    load_timing_samples_csv,
    save_analysis_report,
    save_metadata,
    save_timing_samples_csv,
)
from tests.conftest import make_analysis_report, make_timing_sample, make_timing_samples


# --- create_run_directory ---


class TestCreateRunDirectory:
    def test_creates_directory_with_plots_subdir(self, output_dir: Path):
        run_directory = create_run_directory(output_dir, "test_attack")

        assert run_directory.exists()
        assert run_directory.is_dir()
        assert (run_directory / "plots").exists()
        assert (run_directory / "plots").is_dir()

    def test_two_rapid_calls_produce_distinct_directories(self, output_dir: Path):
        first_directory = create_run_directory(output_dir, "test_attack")
        second_directory = create_run_directory(output_dir, "test_attack")

        assert first_directory.exists()
        assert second_directory.exists()


# --- save/load timing samples round-trip ---


class TestTimingSamplesRoundTrip:
    def test_round_trip_preserves_data(self, output_dir: Path):
        original_samples = make_timing_samples(5, group="round_trip_group")
        csv_path = output_dir / "samples.csv"

        save_timing_samples_csv(original_samples, csv_path)
        loaded_samples = load_timing_samples_csv(csv_path)

        assert len(loaded_samples) == len(original_samples)
        for loaded, original in zip(loaded_samples, original_samples):
            assert loaded.password_group == original.password_group
            assert loaded.attempt == original.attempt
            assert loaded.response_time_ns == original.response_time_ns
            assert loaded.timestamp == original.timestamp

    def test_empty_list_round_trips(self, output_dir: Path):
        csv_path = output_dir / "empty.csv"

        save_timing_samples_csv([], csv_path)
        loaded_samples = load_timing_samples_csv(csv_path)

        assert loaded_samples == []

    def test_zero_response_time_round_trips(self, output_dir: Path):
        sample = make_timing_sample(response_time_ns=0)
        csv_path = output_dir / "zero.csv"

        save_timing_samples_csv([sample], csv_path)
        loaded = load_timing_samples_csv(csv_path)

        assert loaded[0].response_time_ns == 0


# --- save_metadata ---


class TestSaveMetadata:
    def test_produces_valid_json_with_expected_keys(self, output_dir: Path):
        metadata_path = output_dir / "metadata.json"

        save_metadata(
            metadata_path,
            attack_name="timing",
            config_dict={"samples": 1000},
        )

        with open(metadata_path) as json_file:
            data = json.load(json_file)

        assert data["attack_name"] == "timing"
        assert data["config"] == {"samples": 1000}
        assert "netem_profile" in data
        assert "timestamp" in data

    def test_none_software_versions_defaults_to_empty_dict(self, output_dir: Path):
        metadata_path = output_dir / "metadata.json"

        save_metadata(
            metadata_path,
            attack_name="timing",
            config_dict={},
            software_versions=None,
        )

        with open(metadata_path) as json_file:
            data = json.load(json_file)

        assert data["software_versions"] == {}


# --- save_analysis_report ---


class TestSaveAnalysisReport:
    def test_produces_valid_json_with_expected_keys(self, output_dir: Path):
        report = make_analysis_report(
            attack_name="downgrade",
            success=False,
            summary="Downgrade failed",
        )
        report_path = output_dir / "analysis.json"

        save_analysis_report(report, report_path)

        with open(report_path) as json_file:
            data = json.load(json_file)

        assert data["attack_name"] == "downgrade"
        assert data["success"] is False
        assert data["summary"] == "Downgrade failed"


# --- load_timing_samples_csv errors ---


class TestLoadTimingSamplesCsvErrors:
    def test_nonexistent_file_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_timing_samples_csv(Path("/nonexistent/path/samples.csv"))
