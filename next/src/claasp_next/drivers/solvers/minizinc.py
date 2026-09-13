"""Command-line MiniZinc driver with no Python package dependency."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.representations.constraints.cp import MiniZincModel
from claasp_next.representations.constraints.sat import CNFFormula


class CPStatus(str, Enum):
    """Portable MiniZinc solve outcomes."""

    SATISFIED = "satisfied"
    UNSATISFIABLE = "unsatisfiable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CPResult:
    """MiniZinc status, projected named values, and process diagnostics."""

    status: CPStatus
    values: Mapping[str, object] | None
    runtime_seconds: float
    solver: str
    stdout: str
    stderr: str

    @property
    def is_satisfied(self) -> bool:
        """Whether MiniZinc produced a solution."""

        return self.status is CPStatus.SATISFIED

    @property
    def is_satisfiable(self) -> bool:
        """SAT-compatible spelling used by the common analysis facade."""

        return self.is_satisfied

    @property
    def assignment(self) -> Mapping[str, int] | None:
        """Expose Boolean solution values through the common solver contract."""

        if self.values is None:
            return None
        return {name: int(value) if isinstance(value, bool) else value for name, value in self.values.items()}


class MiniZincSolver:
    """Execute a ``MiniZincModel`` through the external MiniZinc CLI."""

    def __init__(
        self,
        solver: str = "gecode",
        executable: str = "minizinc",
        timeout_seconds: float | None = None,
    ) -> None:
        if not solver or not isinstance(solver, str):
            raise ValueError("solver must be a non-empty string")
        if not executable or not isinstance(executable, str):
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.solver = solver
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def solve(self, model: MiniZincModel | CNFFormula) -> CPResult:
        """Run a MiniZinc or portable CNF representation."""

        if isinstance(model, CNFFormula):
            from claasp_next.representations.constraints.cp import BooleanMiniZincLowerer

            model = BooleanMiniZincLowerer().lower(model)
        if not isinstance(model, MiniZincModel):
            raise TypeError("model must be a MiniZincModel or CNFFormula")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"MiniZinc executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-next-minizinc-") as directory:
            path = Path(directory) / "problem.mzn"
            path.write_text(model.source(), encoding="utf-8")
            start = monotonic()
            completed = subprocess.run(
                [executable, "--solver", self.solver, "--output-mode", "json", str(path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
        if completed.returncode != 0:
            raise RuntimeError(
                "MiniZinc failed: " + (completed.stderr.strip() or completed.stdout.strip())
            )
        status, values = _parse_output(completed.stdout)
        if values is not None and model.name_mapping:
            logical_names = dict(model.name_mapping)
            values = {logical_names.get(name, name): value for name, value in values.items()}
        return CPResult(status, values, elapsed, self.solver, completed.stdout, completed.stderr)


def _parse_output(output: str) -> tuple[CPStatus, Mapping[str, object] | None]:
    if "=====UNSATISFIABLE=====" in output:
        return CPStatus.UNSATISFIABLE, None
    if "=====UNKNOWN=====" in output:
        return CPStatus.UNKNOWN, None
    payload = output.split("----------", 1)[0].strip()
    if not payload:
        raise RuntimeError("MiniZinc returned no status or solution")
    try:
        values = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("MiniZinc returned invalid JSON output") from error
    if not isinstance(values, dict):
        raise RuntimeError("MiniZinc JSON solution must be an object")
    return CPStatus.SATISFIED, values
