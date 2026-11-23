"""Portable linear-model execution through CBC, SCIP, and SoPlex."""

import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp._catalogue_metadata import _entry
from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.representations.constraints.milp.exporter import LPExporter
from claasp.representations.constraints.milp.model import MILPModel, VariableKind
from claasp.representations.constraints.sat import CNFFormula

_NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"


class _ExternalLinearSolver:
    executable_name = ""
    supports_integrality = True

    def __init__(self, executable: str | None = None, timeout_seconds: float | None = None) -> None:
        selected = self.executable_name if executable is None else executable
        if not isinstance(selected, str) or not selected:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = selected
        self.timeout_seconds = timeout_seconds

    def solve(self, model: MILPModel | CNFFormula) -> MILPResult | SatResult:
        """Optimize a portable model and independently check its witness."""

        if isinstance(model, CNFFormula):
            if not self.supports_integrality:
                raise TypeError(f"{self.executable_name} does not support binary variables")
            from claasp.representations.constraints.milp.boolean import cnf_to_milp

            solved = self.solve(cnf_to_milp(model))
            assert isinstance(solved, MILPResult)
            if solved.status is MILPStatus.UNKNOWN:
                raise RuntimeError(f"{self.executable_name} could not decide the Boolean formula")
            boolean_assignment = (
                None
                if solved.assignment is None
                else {name: round(value) for name, value in solved.assignment.items()}
            )
            if boolean_assignment is not None and not model.is_satisfied(boolean_assignment):
                raise RuntimeError(f"{self.executable_name} returned an invalid Boolean witness")
            return SatResult(
                SatStatus.SATISFIABLE if solved.is_feasible else SatStatus.UNSATISFIABLE,
                boolean_assignment,
                solved.runtime_seconds,
                solved.stdout,
                solved.stderr,
            )
        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel or CNFFormula")
        if not self.supports_integrality and any(
            variable.kind is not VariableKind.CONTINUOUS for variable in model.variables
        ):
            raise TypeError(f"{self.executable_name} does not support integer variables")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"{self.executable!r} was not found")
        with TemporaryDirectory(prefix=f"claasp-{self.executable_name}-") as directory:
            problem_path = Path(directory) / "problem.lp"
            result_path = Path(directory) / "result.sol"
            problem_path.write_text(LPExporter().export(model), encoding="ascii")
            command = self._command(executable, problem_path, result_path)
            start = monotonic()
            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
            if completed.returncode != 0:
                raise RuntimeError(
                    f"{self.executable_name} failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            solution = result_path.read_text(encoding="ascii") if result_path.exists() else ""
            status, assignment, objective = self._parse_solution(solution, completed.stdout, model)
        if assignment is not None:
            if not model.is_feasible(assignment):
                raise RuntimeError(f"{self.executable_name} returned an infeasible assignment")
            recomputed = model.objective_value(assignment)
            if objective is None or abs(recomputed - objective) > 1e-6 * max(1, abs(recomputed)):
                raise RuntimeError(
                    f"{self.executable_name} objective disagrees with its assignment"
                )
        return MILPResult(
            status, assignment, objective, elapsed, completed.stdout, completed.stderr
        )

    def _command(self, executable: str, problem: Path, result: Path) -> list[str]:
        raise NotImplementedError

    def _parse_solution(
        self, solution: str, stdout: str, model: MILPModel
    ) -> tuple[MILPStatus, dict[str, float] | None, float | None]:
        raise NotImplementedError


class CbcSolver(_ExternalLinearSolver):
    """Solve portable MILP models with COIN-BC.

    EXAMPLES::

        >>> CbcSolver().executable
        'cbc'
    """

    executable_name = "cbc"

    def _command(self, executable: str, problem: Path, result: Path) -> list[str]:
        command = [executable, str(problem)]
        if self.timeout_seconds is not None:
            command.extend(("sec", str(self.timeout_seconds)))
        return [*command, "solve", "solu", str(result)]

    def _parse_solution(self, solution, stdout, model):
        lines = solution.splitlines()
        if not lines:
            raise RuntimeError("CBC did not write a solution status")
        header = lines[0]
        if header.startswith("Infeasible"):
            return MILPStatus.INFEASIBLE, None, None
        if not header.startswith("Optimal"):
            return MILPStatus.UNKNOWN, None, None
        match = re.search(rf"objective value\s+({_NUMBER})", header)
        if match is None:
            raise RuntimeError("CBC did not report an objective")
        assignment = {variable.name: 0.0 for variable in model.variables}
        for line in lines[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[0].lstrip("*").isdigit() and fields[1] in assignment:
                assignment[fields[1]] = float(fields[2])
        return MILPStatus.OPTIMAL, assignment, float(match.group(1))


class ScipSolver(_ExternalLinearSolver):
    """Solve portable MILP models with SCIP.

    EXAMPLES::

        >>> ScipSolver().executable
        'scip'
    """

    executable_name = "scip"

    def _command(self, executable: str, problem: Path, result: Path) -> list[str]:
        command = [executable, "-c", f"read {problem}"]
        if self.timeout_seconds is not None:
            command.extend(("-c", f"set limits time {self.timeout_seconds}"))
        return [
            *command,
            "-c",
            "optimize",
            "-c",
            f"write solution {result}",
            "-c",
            "quit",
        ]

    def _parse_solution(self, solution, stdout, model):
        lines = solution.splitlines()
        if not lines or not lines[0].startswith("solution status:"):
            raise RuntimeError("SCIP did not write a solution status")
        if "infeasible" in lines[0]:
            return MILPStatus.INFEASIBLE, None, None
        if "optimal solution found" not in lines[0]:
            return MILPStatus.UNKNOWN, None, None
        if len(lines) < 2 or not lines[1].startswith("objective value:"):
            raise RuntimeError("SCIP did not report an objective")
        objective = float(lines[1].split(":", 1)[1].strip())
        assignment = {variable.name: 0.0 for variable in model.variables}
        for line in lines[2:]:
            fields = line.split()
            if len(fields) >= 2 and fields[0] in assignment:
                assignment[fields[0]] = float(fields[1])
        return MILPStatus.OPTIMAL, assignment, objective


class SoplexSolver(_ExternalLinearSolver):
    """Solve continuous LP models with SoPlex; integer models are rejected.

    EXAMPLES::

        >>> SoplexSolver().executable
        'soplex'
    """

    executable_name = "soplex"
    supports_integrality = False

    def _command(self, executable: str, problem: Path, result: Path) -> list[str]:
        command = [executable, "-x"]
        if self.timeout_seconds is not None:
            command.append(f"-t{self.timeout_seconds}")
        return [*command, str(problem)]

    def _parse_solution(self, solution, stdout, model):
        match = re.search(r"SoPlex status\s*:\s*problem is solved \[([^]]+)\]", stdout)
        if match is None:
            raise RuntimeError("SoPlex did not report a solve status")
        if match.group(1) == "infeasible":
            return MILPStatus.INFEASIBLE, None, None
        if match.group(1) != "optimal":
            return MILPStatus.UNKNOWN, None, None
        objective_match = re.search(rf"Objective value\s*:\s*({_NUMBER})", stdout)
        if objective_match is None:
            raise RuntimeError("SoPlex did not report an objective")
        assignment = {variable.name: 0.0 for variable in model.variables}
        if "Primal solution (name, value):" not in stdout:
            raise RuntimeError("SoPlex did not print a primal solution")
        primal = stdout.split("Primal solution (name, value):", 1)[1]
        for line in primal.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] in assignment:
                assignment[fields[0]] = float(fields[1])
            elif line.startswith("All other variables"):
                break
        return MILPStatus.OPTIMAL, assignment, float(objective_match.group(1))


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
        (CbcSolver, "coin_bc"),
        (ScipSolver, "scip"),
        (SoplexSolver, "soplex"),
    )
)
