"""Command-line driver for the open-source GLPK optimizer."""

import shutil
import subprocess
from pathlib import Path
from queue import Empty, Queue
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic

from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.drivers.solvers.milp_results import MILPResult, MILPStatus
from claasp.drivers.solvers.progress import MILPProgressLog
from claasp.representations.constraints.milp.exporter import LPExporter
from claasp.representations.constraints.milp.model import MILPModel
from claasp.representations.constraints.sat import CNFFormula


class GLPKSolver:
    """Solve a portable model through a local ``glpsol`` executable."""

    def __init__(
        self,
        executable: str = "glpsol",
        timeout_seconds: float | None = None,
        *,
        progress_log: MILPProgressLog | None = None,
    ) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.progress_log = progress_log

    def solve(self, model: MILPModel | CNFFormula) -> MILPResult | SatResult:
        """Optimize ``model`` and independently validate any returned witness."""

        if isinstance(model, CNFFormula):
            from claasp.representations.constraints.milp.boolean import cnf_to_milp

            solved = self.solve(cnf_to_milp(model))
            assert isinstance(solved, MILPResult)
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
        with TemporaryDirectory(prefix="claasp-glpk-") as directory:
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
            if self.progress_log is None:
                completed = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            else:
                completed = self._run_with_progress(command)
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
        result = MILPResult(
            status, assignment, objective, elapsed, completed.stdout, completed.stderr
        )
        if self.progress_log is not None:
            if assignment is not None:
                self.progress_log.record_solution(model, assignment, status=status.value)
            self.progress_log.finish(result)
        return result

    def _run_with_progress(self, command):
        # Drain both streams concurrently: a verbose stderr must not deadlock
        # the stdout reader. The timeout also applies when neither emits lines.
        assert self.progress_log is not None
        events: Queue[tuple[str, str | None]] = Queue()
        output: dict[str, list[str]] = {"stdout": [], "stderr": []}
        with subprocess.Popen(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1
        ) as process:

            def read(name, stream):
                try:
                    for line in stream:
                        events.put((name, line))
                finally:
                    events.put((name, None))

            threads = [
                Thread(target=read, args=(name, stream), daemon=True)
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
            ]
            for thread in threads:
                thread.start()
            started = monotonic()
            closed = 0
            try:
                while closed < 2:
                    remaining = (
                        None
                        if self.timeout_seconds is None
                        else self.timeout_seconds - (monotonic() - started)
                    )
                    if remaining is not None and remaining <= 0:
                        raise subprocess.TimeoutExpired(command, self.timeout_seconds or 0)
                    try:
                        name, line = events.get(
                            timeout=min(0.1, remaining) if remaining is not None else 0.1
                        )
                    except Empty:
                        continue
                    if line is None:
                        closed += 1
                    else:
                        output[name].append(line)
                        self.progress_log.feed(line, "GLPK")
                process.wait(
                    timeout=None
                    if self.timeout_seconds is None
                    else max(0.001, self.timeout_seconds - (monotonic() - started))
                )
            except BaseException:
                process.kill()
                process.wait()
                raise
            finally:
                for thread in threads:
                    thread.join()
        return subprocess.CompletedProcess(
            command, process.returncode, "".join(output["stdout"]), "".join(output["stderr"])
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
