"""Command-line driver for the open-source GLPK optimizer."""

import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.drivers.solvers.base import SatResult, SatStatus
from claasp_next.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp_next.representations.constraints.milp.exporter import LPExporter
from claasp_next.representations.constraints.milp.model import MILPModel
from claasp_next.representations.constraints.sat import CNFFormula


class GLPKSolver:
    """Solve a portable model through a local ``glpsol`` executable."""

    def __init__(self, executable: str = "glpsol", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def solve(self, model: MILPModel | CNFFormula) -> MILPResult | SatResult:
        """Optimize ``model`` and independently validate any returned witness."""

        if isinstance(model, CNFFormula):
            from claasp_next.representations.constraints.milp.boolean import cnf_to_milp

            solved = self.solve(cnf_to_milp(model))
            if solved.status is MILPStatus.UNKNOWN:
                raise RuntimeError("GLPK returned unknown; Boolean infeasibility is not proved")
            assignment = (
                None
                if solved.assignment is None
                else {name: round(value) for name, value in solved.assignment.items()}
            )
            if assignment is not None and not model.is_satisfied(assignment):
                raise RuntimeError("GLPK binary witness violates the original Boolean clauses")
            return SatResult(
                SatStatus.SATISFIABLE if solved.is_feasible else SatStatus.UNSATISFIABLE,
                assignment,
                solved.runtime_seconds,
                solved.stdout,
                solved.stderr,
            )
        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"GLPK executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-next-glpk-") as directory:
            problem_path = Path(directory) / "problem.lp"
            result_path = Path(directory) / "result.sol"
            mapping_path = Path(directory) / "problem.glp"
            problem_path.write_text(LPExporter().export(model), encoding="ascii")
            command = [
                executable,
                "--lp",
                str(problem_path),
                "--write",
                str(result_path),
                "--wglp",
                str(mapping_path),
            ]
            if self.timeout_seconds is not None:
                command.extend(("--tmlim", str(max(1, int(self.timeout_seconds)))))
            start = monotonic()
            completed = subprocess.run(
                command, text=True, capture_output=True, timeout=self.timeout_seconds, check=False
            )
            elapsed = monotonic() - start
            if completed.returncode != 0 or not result_path.exists():
                raise RuntimeError(
                    f"GLPK failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                )
            status, assignment, objective = self._parse_solution(
                result_path.read_text(encoding="ascii"),
                model,
                self._parse_column_names(mapping_path.read_text(encoding="ascii")),
            )
        if assignment is not None:
            if not model.is_feasible(assignment):
                raise RuntimeError("GLPK returned an assignment that is not feasible")
            recomputed = model.objective_value(assignment)
            if objective is None or abs(recomputed - objective) > 1e-6:
                raise RuntimeError("GLPK objective disagrees with the returned assignment")
        return MILPResult(
            status, assignment, objective, elapsed, completed.stdout, completed.stderr
        )

    @staticmethod
    def _parse_solution(text: str, model: MILPModel, column_names: dict[int, str]):
        status_code = None
        objective = None
        values: dict[int, float] = {}
        for line in text.splitlines():
            fields = line.split()
            if not fields or fields[0] == "c":
                continue
            if fields[0] == "s":
                if fields[1] == "mip":
                    status_code, objective = fields[4], float(fields[5])
                elif fields[1] == "bas":
                    status_code, objective = fields[4], float(fields[5])
                else:
                    raise RuntimeError(f"unsupported GLPK solution kind {fields[1]!r}")
            elif fields[0] == "j":
                # MIP: j column value. Basic LP: j column status primal dual.
                values[int(fields[1])] = float(fields[2] if len(fields) == 3 else fields[3])
        if status_code == "u":
            return MILPStatus.UNKNOWN, None, None
        if status_code in {"i", "n"}:
            return MILPStatus.INFEASIBLE, None, None
        statuses = {"o": MILPStatus.OPTIMAL, "f": MILPStatus.FEASIBLE}
        if status_code not in statuses:
            raise RuntimeError(f"unrecognized GLPK solution status {status_code!r}")
        if set(values) != set(column_names):
            raise RuntimeError("GLPK returned an incomplete assignment")
        assignment = {column_names[index]: value for index, value in values.items()}
        if set(assignment) != {variable.name for variable in model.variables}:
            raise RuntimeError("GLPK column map disagrees with model variables")
        return statuses[status_code], assignment, objective

    @staticmethod
    def _parse_column_names(text: str) -> dict[int, str]:
        names = {}
        for line in text.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[:2] == ["n", "j"]:
                names[int(fields[2])] = fields[3]
        if not names:
            raise RuntimeError("GLPK did not emit a column-name map")
        return names
