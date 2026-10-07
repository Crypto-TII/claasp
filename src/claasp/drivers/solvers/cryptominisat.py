"""Command-line CryptoMiniSat driver with native-XOR support."""

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.representations.constraints.sat.exporters import (
    CryptoMiniSatDimacsExporter,
    DimacsExporter,
)
from claasp.representations.constraints.sat.model import CNFFormula, NativeXorCNFFormula


class CryptoMiniSatSolver:
    """Execute CryptoMiniSat on ordinary CNF or native parity clauses.

    The solver is an optional command-line dependency. ``executable`` may be a
    command on ``PATH`` or an explicit filesystem path.

    EXAMPLES::

        >>> solver = CryptoMiniSatSolver(timeout_seconds=30)
        >>> (solver.executable, solver.timeout_seconds)
        ('cryptominisat5', 30)
    """

    def __init__(
        self,
        executable: str = "cryptominisat5",
        timeout_seconds: float | None = None,
    ) -> None:
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
        augmented = self._with_assumptions(formula, assumption_clauses)
        if isinstance(augmented, NativeXorCNFFormula):
            rendered = CryptoMiniSatDimacsExporter().export(augmented, include_variable_map=False)
        else:
            rendered = DimacsExporter().export(augmented, include_variable_map=False)
        with TemporaryDirectory(prefix="claasp-cryptominisat-") as directory:
            input_path = Path(directory) / "problem.cnf"
            input_path.write_text(rendered, encoding="ascii")
            start = monotonic()
            completed = subprocess.run(
                [executable, "--verb=0", str(input_path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            if completed.returncode not in (10, 20):
                raise RuntimeError(
                    f"CryptoMiniSat failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            status, assignment = self._parse_result(completed.stdout, augmented.variables)
            expected_status = (
                SatStatus.SATISFIABLE if completed.returncode == 10 else SatStatus.UNSATISFIABLE
            )
            if status is not expected_status:
                raise RuntimeError("CryptoMiniSat exit code and result status disagree")
            if status is SatStatus.SATISFIABLE:
                if assignment is None or not augmented.is_satisfied(assignment):
                    raise RuntimeError(
                        "CryptoMiniSat returned an assignment that does not satisfy the formula"
                    )
            return SatResult(status, assignment, elapsed, completed.stdout, completed.stderr)

    def version(self) -> str:
        """Return the installed CryptoMiniSat version banner."""

        completed = subprocess.run(
            [self._resolve_executable(), "--version"],
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        lines = tuple(line for line in completed.stdout.splitlines() if "version" in line.lower())
        if completed.returncode != 0 or not lines:
            raise RuntimeError("CryptoMiniSat did not report its version")
        return lines[0].removeprefix("c ").strip()

    def _resolve_executable(self) -> str:
        resolved = shutil.which(self.executable)
        if resolved is None:
            raise FileNotFoundError(f"CryptoMiniSat executable {self.executable!r} was not found")
        return resolved

    @staticmethod
    def _with_assumptions(
        formula: CNFFormula, assumption_clauses: tuple[tuple[int, ...], ...]
    ) -> CNFFormula:
        provenance = formula.provenance + ("assumption",) * len(assumption_clauses)
        if isinstance(formula, NativeXorCNFFormula):
            return NativeXorCNFFormula(
                formula.variables,
                formula.clauses + assumption_clauses,
                provenance,
                formula.constraint_models,
                formula.xor_clauses,
                formula.xor_provenance,
            )
        return CNFFormula(
            formula.variables,
            formula.clauses + assumption_clauses,
            provenance,
            formula.constraint_models,
        )

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
            raise RuntimeError("CryptoMiniSat returned an unrecognized or missing status")
        literals = [
            int(token)
            for line in lines
            if line.startswith("v ")
            for token in line[2:].split()
            if token != "0"
        ]
        if any(abs(literal) > len(variables) for literal in literals):
            raise RuntimeError("CryptoMiniSat assignment refers to an unknown variable")
        assignment_by_index = {abs(literal): int(literal > 0) for literal in literals}
        expected = set(range(1, len(variables) + 1))
        if set(assignment_by_index) != expected:
            raise RuntimeError("CryptoMiniSat returned an incomplete assignment")
        return SatStatus.SATISFIABLE, {
            name: assignment_by_index[index] for index, name in enumerate(variables, 1)
        }
