"""Command-line Singular program driver."""

import shutil
import subprocess
from time import monotonic

from claasp.drivers.algebra.base import AlgebraExecutionResult


class SingularDriver:
    """Execute an already serialized Singular program."""

    def __init__(self, executable: str = "Singular", timeout_seconds: float | None = None) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def execute(self, program: str) -> AlgebraExecutionResult:
        """Run ``program`` without coupling execution to polynomial lowering."""

        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"Singular executable {self.executable!r} was not found")
        start = monotonic()
        completed = subprocess.run(
            [executable, "--no-tty", "--quiet"],
            input=program,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        elapsed = monotonic() - start
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
        return AlgebraExecutionResult(completed.stdout, completed.stderr, elapsed)
