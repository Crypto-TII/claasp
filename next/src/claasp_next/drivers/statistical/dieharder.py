"""Optional command-line driver for Dieharder."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.analysis.statistical_datasets import StatisticalDataset
from claasp_next.analysis.statistical_results import DieharderReport, StatisticalTestRun
from claasp_next.drivers.statistical.parsers import parse_dieharder_report


class DieharderDriver:
    """Run Dieharder against a canonical CLAASP statistical byte stream."""

    def __init__(self, executable: str = "dieharder", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        dataset: StatisticalDataset,
        *,
        test: int | None = None,
    ) -> StatisticalTestRun[DieharderReport]:
        """Execute all tests or one numbered test and parse stdout."""

        if not isinstance(dataset, StatisticalDataset):
            raise TypeError("dataset must be a StatisticalDataset")
        if test is not None and (not isinstance(test, int) or isinstance(test, bool) or test < 0):
            raise ValueError("test must be a non-negative integer")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"Dieharder executable {self.executable!r} was not found")

        with TemporaryDirectory(prefix="claasp-next-dieharder-") as directory:
            input_path = Path(directory) / "dataset.bin"
            with input_path.open("wb") as stream:
                dataset.write_binary(stream)
            tool_arguments = (
                ("-g", "201", "-f", str(input_path), "-a")
                if test is None
                else ("-g", "201", "-f", str(input_path), "-d", str(test))
            )
            start = monotonic()
            completed = subprocess.run(
                (executable, *tool_arguments),
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start

        if completed.returncode != 0:
            diagnostic = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(
                f"Dieharder failed with exit code {completed.returncode}: {diagnostic}"
            )
        report = parse_dieharder_report(completed.stdout)
        version = self._version(executable)
        stable_arguments = tuple(
            "{dataset}" if argument == str(input_path) else argument for argument in tool_arguments
        )
        return StatisticalTestRun(
            suite="dieharder",
            suite_version=version,
            dataset_sha256=dataset.digest(),
            command=(self.executable, *stable_arguments),
            runtime_seconds=elapsed,
            report=report,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _version(self, executable: str) -> str:
        completed = subprocess.run(
            (executable, "-h"),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        output = completed.stdout.strip() or completed.stderr.strip()
        return output.splitlines()[0].strip() if output else "unknown"
