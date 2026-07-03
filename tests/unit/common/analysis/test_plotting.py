from __future__ import annotations

from pathlib import Path

from attacks.common.analysis.plotting import (
    plot_timing_boxplot,
    plot_timing_cdf,
    plot_timing_histogram,
)


class TestPlotTimingHistogram:
    def test_creates_png_file(self, output_dir: Path):
        grouped = {"group_a": [100_000, 200_000, 300_000], "group_b": [400_000, 500_000, 600_000]}
        output_path = output_dir / "histogram.png"

        result = plot_timing_histogram(grouped, output_path)

        assert result == output_path
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_single_group(self, output_dir: Path):
        grouped = {"only_group": [100_000, 200_000]}
        output_path = output_dir / "single.png"

        plot_timing_histogram(grouped, output_path)

        assert output_path.exists()

    def test_empty_dict(self, output_dir: Path):
        output_path = output_dir / "empty.png"

        plot_timing_histogram({}, output_path)

        assert output_path.exists()


class TestPlotTimingBoxplot:
    def test_creates_png_file(self, output_dir: Path):
        grouped = {"group_a": [100_000, 200_000, 300_000]}
        output_path = output_dir / "boxplot.png"

        result = plot_timing_boxplot(grouped, output_path)

        assert result == output_path
        assert output_path.exists()

    def test_empty_dict(self, output_dir: Path):
        output_path = output_dir / "empty_box.png"

        plot_timing_boxplot({}, output_path)

        assert output_path.exists()


class TestPlotTimingCdf:
    def test_creates_png_file(self, output_dir: Path):
        grouped = {"group_a": [100_000, 200_000, 300_000]}
        output_path = output_dir / "cdf.png"

        result = plot_timing_cdf(grouped, output_path)

        assert result == output_path
        assert output_path.exists()

    def test_empty_dict(self, output_dir: Path):
        output_path = output_dir / "empty_cdf.png"

        plot_timing_cdf({}, output_path)

        assert output_path.exists()
