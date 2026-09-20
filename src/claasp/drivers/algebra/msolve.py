"""Command-line msolve input driver."""

import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp.drivers.algebra.base import AlgebraExecutionResult


class MsolveDriver:
    """Execute an already serialized msolve input artifact."""

    def __init__(self, executable: str = "msolve", timeout_seconds: float | None = None) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def execute(self, input_text: str) -> AlgebraExecutionResult:
        """Run msolve and return its output artifact text."""

        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"msolve executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-msolve-") as directory:
            input_path = Path(directory) / "system.ms"
            output_path = Path(directory) / "result.ms"
            input_path.write_text(input_text, encoding="utf-8")
            start = monotonic()
            completed = subprocess.run(
                [executable, "-f", str(input_path), "-o", str(output_path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            if completed.returncode != 0 or not output_path.exists():
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
            result_text = output_path.read_text(encoding="utf-8")
        return AlgebraExecutionResult(completed.stdout, completed.stderr, elapsed, result_text)
