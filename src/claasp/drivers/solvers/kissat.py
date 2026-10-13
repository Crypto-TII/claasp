"""Command-line Kissat driver."""

import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.representations.constraints.sat.cnf import CNFFormula
from claasp.representations.constraints.sat.exporters import DimacsExporter


class KissatSolver:
    """Execute the Kissat SAT solver on an immutable CNF formula.

    ``executable`` may be a command on ``PATH`` or an explicit filesystem
    path. Each solve uses an isolated temporary directory.

    EXAMPLES::

        >>> KissatSolver().executable
        'kissat'
    """

    def __init__(self, executable: str = "kissat", timeout_seconds: float | None = None) -> None:
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
        with TemporaryDirectory(prefix="claasp-kissat-") as directory:
            input_path = Path(directory) / "problem.cnf"
            input_path.write_text(
                DimacsExporter().export(augmented, include_variable_map=False), encoding="ascii"
            )
            start = monotonic()
            completed = subprocess.run(
                [executable, "-s", str(input_path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            if completed.returncode not in (10, 20):
                raise RuntimeError(
                    f"Kissat failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            status, assignment = self._parse_result(completed.stdout, augmented.variables)
            expected_status = (
                SatStatus.SATISFIABLE if completed.returncode == 10 else SatStatus.UNSATISFIABLE
            )
            if status is not expected_status:
                raise RuntimeError("Kissat exit code and result status disagree")
            if status is SatStatus.SATISFIABLE:
                if assignment is None or not augmented.is_satisfied(assignment):
                    raise RuntimeError(
                        "Kissat returned an assignment that does not satisfy the formula"
                    )
            return SatResult(
                status,
                assignment,
                elapsed,
                completed.stdout,
                completed.stderr,
                self._parse_peak_memory(completed.stdout),
            )

    def version(self) -> str:
        """Return the installed Kissat version."""

        completed = subprocess.run(
            [self._resolve_executable(), "--version"],
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise RuntimeError("Kissat did not report its version")
        return completed.stdout.strip().splitlines()[0]

    def _resolve_executable(self) -> str:
        resolved = shutil.which(self.executable)
        if resolved is None:
            raise FileNotFoundError(f"Kissat executable {self.executable!r} was not found")
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
        lines = tuple(line.strip() for line in text.splitlines() if line.strip())
        statuses = tuple(line for line in lines if line.startswith("s "))
        if statuses == ("s UNSATISFIABLE",):
            return SatStatus.UNSATISFIABLE, None
        if statuses != ("s SATISFIABLE",):
            raise RuntimeError("Kissat returned an unrecognized or missing status")
        literals = [
            int(token)
            for line in lines
            if line.startswith("v ")
            for token in line[2:].split()
            if token != "0"
        ]
        if any(abs(literal) > len(variables) for literal in literals):
            raise RuntimeError("Kissat assignment refers to an unknown variable")
        assignment_by_index = {abs(literal): int(literal > 0) for literal in literals}
        expected = set(range(1, len(variables) + 1))
        if set(assignment_by_index) != expected:
            raise RuntimeError("Kissat returned an incomplete assignment")
        return SatStatus.SATISFIABLE, {
            name: assignment_by_index[index] for index, name in enumerate(variables, 1)
        }

    @staticmethod
    def _parse_peak_memory(text: str, platform: str = sys.platform) -> int | None:
        prefix = "c maximum-resident-set-size:"
        lines = tuple(line.strip() for line in text.splitlines() if line.startswith(prefix))
        if len(lines) != 1:
            return None
        tokens = lines[0].removeprefix(prefix).split()
        if len(tokens) < 2 or tokens[1] != "bytes" or not tokens[0].isdigit():
            return None
        reported = int(tokens[0])
        # Kissat normalizes Linux's KiB-valued ru_maxrss to bytes. Darwin
        # already reports bytes, but Kissat applies the same multiplication.
        return reported // 1024 if platform == "darwin" else reported
