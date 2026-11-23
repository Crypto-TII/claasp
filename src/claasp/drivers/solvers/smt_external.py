"""Boolean SMT execution through MathSAT and Yices."""

import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic

from claasp._catalogue_metadata import _entry
from claasp.drivers.solvers.base import SatResult, SatStatus
from claasp.representations.constraints.sat import CNFFormula
from claasp.representations.constraints.smt.exporter import SMTLibExporter
from claasp.representations.constraints.smt.formula import SMTFormula


class _SMTExternalSolver:
    executable_name = ""
    options: tuple[str, ...] = ()

    def __init__(self, executable: str | None = None, timeout_seconds: float | None = None) -> None:
        selected = self.executable_name if executable is None else executable
        if not isinstance(selected, str) or not selected:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = selected
        self.timeout_seconds = timeout_seconds

    def solve(self, formula: SMTFormula | CNFFormula) -> SatResult:
        """Solve Boolean SMT or CNF and check the returned assignment."""

        if isinstance(formula, CNFFormula):
            formula = SMTFormula.from_cnf(formula)
        elif not isinstance(formula, SMTFormula):
            raise TypeError("formula must be an SMTFormula or CNFFormula")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"{self.executable!r} was not found")
        with TemporaryDirectory(prefix=f"claasp-{self.executable_name}-") as directory:
            path = Path(directory) / "problem.smt2"
            path.write_text(SMTLibExporter().export(formula), encoding="ascii")
            start = monotonic()
            completed = subprocess.run(
                [executable, *self.options, str(path)],
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            elapsed = monotonic() - start
        lines = tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())
        if completed.returncode != 0 or not lines:
            raise RuntimeError(
                f"{self.executable_name} failed: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        if lines[0] == "unsat":
            return SatResult(
                SatStatus.UNSATISFIABLE, None, elapsed, completed.stdout, completed.stderr
            )
        if lines[0] != "sat":
            raise RuntimeError(
                f"{self.executable_name} returned {lines[0]!r} instead of SAT status"
            )
        pairs = re.findall(r"\(([A-Za-z0-9_]+)\s+(true|false)\)", completed.stdout)
        values: dict[str, int] = {}
        for name, value in pairs:
            bit = int(value == "true")
            if name in values and values[name] != bit:
                raise RuntimeError(f"{self.executable_name} returned a contradictory model")
            values[name] = bit
        if set(values) != set(formula.variables):
            raise RuntimeError(f"{self.executable_name} returned an incomplete model")
        if not formula.to_cnf().is_satisfied(values):
            raise RuntimeError(f"{self.executable_name} returned an invalid model")
        return SatResult(SatStatus.SATISFIABLE, values, elapsed, completed.stdout, completed.stderr)


class MathSatSolver(_SMTExternalSolver):
    """Run MathSAT on a Boolean SMT or CNF formula.

    EXAMPLES::

        >>> MathSatSolver().executable
        'mathsat'
    """

    executable_name = "mathsat"
    options = ("-model",)


class YicesSolver(_SMTExternalSolver):
    """Run Yices' SMT-LIB frontend on a Boolean SMT or CNF formula.

    EXAMPLES::

        >>> YicesSolver().executable
        'yices-smt2'
    """

    executable_name = "yices-smt2"


__catalogue__ = (
    _entry(
        "driver",
        MathSatSolver,
        name="mathsat",
        kind="solver",
        availability="executable",
        target="mathsat",
    ),
    _entry(
        "driver",
        YicesSolver,
        name="yices",
        kind="solver",
        availability="executable",
        target="yices-smt2",
    ),
)
