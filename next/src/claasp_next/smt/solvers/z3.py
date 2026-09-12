"""Command-line Z3 adapter for Boolean SMT formulas."""

from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from time import monotonic

from claasp_next.boolean import CNFFormula
from claasp_next.boolean.solvers import SatResult, SatStatus
from claasp_next.smt.exporter import SMTLibExporter
from claasp_next.smt.formula import SMTFormula


class Z3Solver:
    """Execute the open-source ``z3`` command without a Python dependency."""

    def __init__(self, executable: str = "z3", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def solve(self, formula: SMTFormula | CNFFormula) -> SatResult:
        """Solve an SMT formula, accepting CNF at the shared facade boundary."""

        if isinstance(formula, CNFFormula):
            formula = SMTFormula.from_cnf(formula)
        if not isinstance(formula, SMTFormula):
            raise TypeError("formula must be an SMTFormula or CNFFormula")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"Z3 executable {self.executable!r} was not found")
        with TemporaryDirectory(prefix="claasp-next-z3-") as directory:
            path = Path(directory) / "problem.smt2"
            path.write_text(SMTLibExporter().export(formula), encoding="ascii")
            start = monotonic()
            completed = subprocess.run(
                [executable, "-smt2", str(path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
        if completed.returncode != 0:
            raise RuntimeError(f"Z3 failed: {completed.stderr.strip() or completed.stdout.strip()}")
        status, assignment = self._parse_output(completed.stdout, formula.variables)
        return SatResult(status, assignment, elapsed, completed.stdout, completed.stderr)

    @staticmethod
    def _parse_output(text: str, variables: tuple[str, ...]):
        lines = text.splitlines()
        if not lines:
            raise RuntimeError("Z3 returned an empty result")
        if lines[0].strip() == "unsat":
            return SatStatus.UNSATISFIABLE, None
        if lines[0].strip() != "sat":
            raise RuntimeError(f"unrecognized Z3 status {lines[0].strip()!r}")
        pairs = dict(re.findall(r"\(([A-Za-z0-9_]+)\s+(true|false)\)", "\n".join(lines[1:])))
        if set(pairs) != set(variables):
            raise RuntimeError("Z3 returned an incomplete assignment")
        return SatStatus.SATISFIABLE, {
            name: int(pairs[name] == "true") for name in variables
        }
