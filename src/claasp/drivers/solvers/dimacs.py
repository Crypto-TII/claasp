"""Portable CNF execution through additional command-line SAT solvers."""

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp._catalogue_metadata import _entry
from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.representations.constraints.sat.exporters import DimacsExporter
from claasp.representations.constraints.sat.model import CNFFormula, _require_plain_cnf


class _DimacsSolver:
    executable_name = ""
    options: tuple[str, ...] = ()
    status_exit_codes: tuple[int, int] = (10, 20)
    yices_output = False

    def __init__(self, executable: str | None = None, timeout_seconds: float | None = None) -> None:
        selected = self.executable_name if executable is None else executable
        if not isinstance(selected, str) or not selected:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = selected
        self.timeout_seconds = timeout_seconds

    def solve(
        self,
        formula: CNFFormula,
        assumptions: Mapping[str, int | bool] | None = None,
    ) -> SatResult:
        """Solve plain CNF and independently check a satisfying assignment."""

        _require_plain_cnf(formula)
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"{self.executable!r} was not found")
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        unit_clauses = []
        for name, value in (assumptions or {}).items():
            if name not in indices:
                raise ValueError(f"assumption refers to unknown variable {name!r}")
            if not isinstance(value, (bool, int)) or value not in (0, 1, False, True):
                raise ValueError(f"assumption for {name!r} must be Boolean")
            unit_clauses.append((indices[name] if value else -indices[name],))
        augmented = CNFFormula(
            formula.variables,
            formula.clauses + tuple(unit_clauses),
            formula.provenance + ("assumption",) * len(unit_clauses),
        )
        with TemporaryDirectory(prefix=f"claasp-{self.executable_name}-") as directory:
            input_path = Path(directory) / "problem.cnf"
            input_path.write_text(
                DimacsExporter().export(augmented, include_variable_map=False), encoding="ascii"
            )
            command = [executable, *self.options, str(input_path)]
            start = monotonic()
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
        status, assignment = self._parse_result(completed.stdout, augmented.variables)
        expected_code = self.status_exit_codes[0 if status is SatStatus.SATISFIABLE else 1]
        if completed.returncode != expected_code:
            raise RuntimeError(
                f"{self.executable_name} exited with {completed.returncode} after reporting "
                f"{status.value}: {completed.stderr.strip()}"
            )
        if assignment is not None and not augmented.is_satisfied(assignment):
            raise RuntimeError(f"{self.executable_name} returned an invalid assignment")
        return SatResult(status, assignment, elapsed, completed.stdout, completed.stderr)

    def _parse_result(
        self, output: str, variables: tuple[str, ...]
    ) -> tuple[SatStatus, dict[str, int] | None]:
        lines = tuple(line.strip() for line in output.splitlines() if line.strip())
        if self.yices_output:
            statuses = tuple(line for line in lines if line in ("sat", "unsat"))
            sat, unsat = "sat", "unsat"
            model_lines = lines[1:]
        else:
            statuses = tuple(line for line in lines if line.startswith("s "))
            sat, unsat = "s SATISFIABLE", "s UNSATISFIABLE"
            model_lines = tuple(line[2:] for line in lines if line.startswith("v "))
        if statuses == (unsat,):
            return SatStatus.UNSATISFIABLE, None
        if statuses != (sat,):
            raise RuntimeError(f"{self.executable_name} returned no unambiguous SAT status")
        try:
            literals = [
                int(token) for line in model_lines for token in line.split() if token != "0"
            ]
        except ValueError as exc:
            raise RuntimeError(f"{self.executable_name} returned an invalid model") from exc
        if any(abs(literal) > len(variables) for literal in literals):
            raise RuntimeError(f"{self.executable_name} model names an unknown variable")
        assignment_by_index: dict[int, int] = {}
        for literal in literals:
            value = int(literal > 0)
            index = abs(literal)
            if index in assignment_by_index and assignment_by_index[index] != value:
                raise RuntimeError(f"{self.executable_name} returned a contradictory model")
            assignment_by_index[index] = value
        return SatStatus.SATISFIABLE, {
            name: assignment_by_index.get(index, 0) for index, name in enumerate(variables, 1)
        }


class CadicalSolver(_DimacsSolver):
    """Run CaDiCaL on a portable CNF formula.

    EXAMPLES::

        >>> CadicalSolver().executable
        'cadical'
    """

    executable_name = "cadical"


class GlucoseSolver(_DimacsSolver):
    """Run Glucose with model output enabled.

    EXAMPLES::

        >>> GlucoseSolver().executable
        'glucose'
    """

    executable_name = "glucose"
    options = ("-model",)


class GlucoseSyrupSolver(_DimacsSolver):
    """Run parallel Glucose Syrup with model output enabled.

    Silence verbose statistics because Glucose Syrup 4.1 divides by zero
    when printing statistics for formulas solved without conflicts.

    EXAMPLES::

        >>> GlucoseSyrupSolver().executable
        'glucose-syrup'
    """

    executable_name = "glucose-syrup"
    options = ("-model", "-verb=0")


class ParKissatSolver(_DimacsSolver):
    """Run ParKissat on a portable CNF formula.

    EXAMPLES::

        >>> ParKissatSolver().executable
        'parkissat'
    """

    executable_name = "parkissat"
    options = ("-c=1",)
    status_exit_codes = (0, 0)


class YicesSatSolver(_DimacsSolver):
    """Run Yices' DIMACS SAT frontend.

    EXAMPLES::

        >>> YicesSatSolver().executable
        'yices-sat'
    """

    executable_name = "yices-sat"
    options = ("--model",)
    status_exit_codes = (0, 0)
    yices_output = True


__catalogue__ = tuple(
    _entry(
        "driver",
        solver,
        name=name,
        kind="solver",
        availability="executable",
        target=solver.executable_name,
    )
    for solver, name in (
        (CadicalSolver, "cadical"),
        (GlucoseSolver, "glucose"),
        (GlucoseSyrupSolver, "glucose_syrup"),
        (ParKissatSolver, "parkissat"),
        (YicesSatSolver, "yices_sat"),
    )
)
