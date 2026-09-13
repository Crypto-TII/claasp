"""Command-line adapter for the open-source GLPK optimizer."""

from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.milp.exporter import LPExporter
from claasp_next.milp.model import MILPModel
from claasp_next.milp.solvers.base import MILPResult, MILPStatus


class GLPKSolver:
    """Solve a portable model through a local ``glpsol`` executable."""

    def __init__(self, executable: str = "glpsol", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def solve(self, model: MILPModel) -> MILPResult:
        """Optimize ``model`` and independently validate any returned witness."""

        if not isinstance(model, MILPModel):
            raise TypeError("model must be an MILPModel")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"GLPK executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-next-glpk-") as directory:
            problem_path = Path(directory) / "problem.lp"
            result_path = Path(directory) / "result.sol"
            problem_path.write_text(LPExporter().export(model), encoding="ascii")
            command = [executable, "--lp", str(problem_path), "--write", str(result_path)]
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
                result_path.read_text(encoding="ascii"), model
            )
        if assignment is not None:
            if not model.is_feasible(assignment):
                raise RuntimeError("GLPK returned an assignment that is not feasible")
            recomputed = model.objective_value(assignment)
            if objective is None or abs(recomputed - objective) > 1e-6:
                raise RuntimeError("GLPK objective disagrees with the returned assignment")
        return MILPResult(status, assignment, objective, elapsed, completed.stdout, completed.stderr)

    @staticmethod
    def _parse_solution(text: str, model: MILPModel):
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
        if status_code in {"i", "n", "u"}:
            return MILPStatus.INFEASIBLE, None, None
        statuses = {"o": MILPStatus.OPTIMAL, "f": MILPStatus.FEASIBLE}
        if status_code not in statuses:
            raise RuntimeError(f"unrecognized GLPK solution status {status_code!r}")
        if set(values) != set(range(1, len(model.variables) + 1)):
            raise RuntimeError("GLPK returned an incomplete assignment")
        assignment = {
            variable.name: values[index] for index, variable in enumerate(model.variables, 1)
        }
        return statuses[status_code], assignment, objective
