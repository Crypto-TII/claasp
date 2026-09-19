"""Command-line MiniSat driver."""

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.drivers.solvers.base import SatResult, SatStatus
from claasp_next.representations.constraints.sat.cnf import CNFFormula
from claasp_next.representations.constraints.sat.exporters import DimacsExporter


class MinisatSolver:
    """Execute MiniSat without adding a Python package dependency.

    ``executable`` may be a command on ``PATH`` or an explicit filesystem
    path. Each solve uses an isolated temporary directory.
    """

    def __init__(self, executable: str = "minisat", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def solve(
        self,
        formula: CNFFormula,
        assumptions: Mapping[str, int | bool] | None = None,
    ) -> SatResult:
        """Solve ``formula`` with optional named unit assumptions."""

        if not isinstance(formula, CNFFormula):
            raise TypeError("formula must be a CNFFormula")
        executable = self._resolve_executable()
        assumption_clauses = self._assumption_clauses(formula, assumptions or {})
        augmented = CNFFormula(
            formula.variables,
            formula.clauses + assumption_clauses,
            formula.provenance + ("assumption",) * len(assumption_clauses),
        )
        with TemporaryDirectory(prefix="claasp-next-minisat-") as directory:
            input_path = Path(directory) / "problem.cnf"
            result_path = Path(directory) / "result.txt"
            input_path.write_text(
                DimacsExporter().export(augmented, include_variable_map=False), encoding="ascii"
            )
            start = monotonic()
            completed = subprocess.run(
                [executable, "-verb=0", str(input_path), str(result_path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            if completed.returncode not in (10, 20):
                raise RuntimeError(
                    f"MiniSat failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            if not result_path.exists():
                raise RuntimeError("MiniSat did not create its result file")
            status, assignment = self._parse_result(
                result_path.read_text(encoding="ascii"), augmented.variables
            )
            expected_status = (
                SatStatus.SATISFIABLE if completed.returncode == 10 else SatStatus.UNSATISFIABLE
            )
            if status is not expected_status:
                raise RuntimeError("MiniSat exit code and result status disagree")
            if status is SatStatus.SATISFIABLE and not augmented.is_satisfied(assignment):
                raise RuntimeError(
                    "MiniSat returned an assignment that does not satisfy the formula"
                )
            return SatResult(status, assignment, elapsed, completed.stdout, completed.stderr)

    def _resolve_executable(self) -> str:
        resolved = shutil.which(self.executable)
        if resolved is None:
            raise FileNotFoundError(f"MiniSat executable {self.executable!r} was not found")
        return resolved

    @staticmethod
    def _assumption_clauses(
        formula: CNFFormula, assumptions: Mapping[str, int | bool]
    ) -> tuple[tuple[int, ...], ...]:
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        clauses = []
        for name, value in assumptions.items():
            if name not in indices:
                raise ValueError(f"assumption refers to unknown variable {name!r}")
            if not isinstance(value, (int, bool)) or value not in (0, 1, False, True):
                raise ValueError(f"assumption for {name!r} must be Boolean")
            clauses.append(((indices[name] if value else -indices[name]),))
        return tuple(clauses)

    @staticmethod
    def _parse_result(
        text: str, variables: tuple[str, ...]
    ) -> tuple[SatStatus, dict[str, int] | None]:
        tokens = text.split()
        if not tokens:
            raise RuntimeError("MiniSat returned an empty result")
        if tokens[0] == "UNSAT":
            return SatStatus.UNSATISFIABLE, None
        if tokens[0] != "SAT":
            raise RuntimeError(f"unrecognized MiniSat status {tokens[0]!r}")
        literals = [int(token) for token in tokens[1:] if token != "0"]
        if any(abs(literal) > len(variables) for literal in literals):
            raise RuntimeError("MiniSat assignment refers to an unknown variable")
        assignment_by_index = {abs(literal): int(literal > 0) for literal in literals}
        expected = set(range(1, len(variables) + 1))
        if set(assignment_by_index) != expected:
            raise RuntimeError("MiniSat returned an incomplete assignment")
        return SatStatus.SATISFIABLE, {
            name: assignment_by_index[index] for index, name in enumerate(variables, 1)
        }
