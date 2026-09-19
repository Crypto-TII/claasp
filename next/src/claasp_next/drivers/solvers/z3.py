"""Command-line Z3 driver for Boolean SMT formulas."""

import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from queue import Empty, Queue
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic

from claasp_next.drivers.solvers import SatResult, SatStatus
from claasp_next.representations.constraints.sat import CNFFormula
from claasp_next.representations.constraints.smt.exporter import SMTLibExporter
from claasp_next.representations.constraints.smt.formula import SMTFormula


class Z3Solver:
    """Execute the open-source ``z3`` command without a Python dependency."""

    def __init__(self, executable: str = "z3", timeout_seconds: float | None = None) -> None:
        if not isinstance(executable, str) or not executable:
            raise ValueError("executable must be a non-empty string")
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def version(self) -> str:
        """Read executable provenance without requiring a Python Z3 package."""
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"Z3 executable {self.executable!r} was not found")
        completed = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds or 10,
            check=True,
        )
        return completed.stdout.strip()

    @contextmanager
    def incremental(self, formula: SMTFormula):
        """Reuse one isolated Z3 process for append-only Boolean formulas.

        Per-query timeouts and complete named assignments use the same driver
        contract as ``solve``. The process is always terminated on context exit.
        """
        if not isinstance(formula, SMTFormula):
            raise TypeError("formula must be an SMTFormula")
        executable = shutil.which(self.executable)
        if executable is None:
            raise FileNotFoundError(f"Z3 executable {self.executable!r} was not found")
        session = _IncrementalZ3(executable, formula, self.timeout_seconds)
        try:
            yield session
        finally:
            session.close()

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
        # Z3 reports an error for the trailing get-value command after UNSAT;
        # the preceding status is nevertheless a valid completed solve.
        if completed.returncode != 0 and not completed.stdout.startswith("unsat"):
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
        return SatStatus.SATISFIABLE, {name: int(pairs[name] == "true") for name in variables}


class _IncrementalZ3:
    """Private process lifetime; the public representation remains immutable."""

    def __init__(self, executable, formula, timeout_seconds):
        self.formula = formula
        self.timeout_seconds = timeout_seconds
        self.prepared = False
        self.lines = Queue()
        self.errors = []
        self.process = subprocess.Popen(
            [executable, "-in", "-smt2"],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
        self.reader = Thread(target=self._read_output, daemon=True)
        self.error_reader = Thread(target=self._read_errors, daemon=True)
        self.reader.start()
        self.error_reader.start()

    def _read_output(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _read_errors(self):
        for line in self.process.stderr:
            self.errors.append(line)

    def solve(self, formula):
        previous = self.formula
        if (
            formula.variables != previous.variables
            or formula.assertions[: len(previous.assertions)] != previous.assertions
        ):
            raise ValueError(
                "incremental formulas must append assertions without changing declarations"
            )
        start = monotonic()
        if not self.prepared:
            text = (
                SMTLibExporter().export(previous, include_values=False).rsplit("(check-sat)", 1)[0]
            )
            self.prepared = True
        else:
            text = ""
        delta = SMTFormula(
            formula.variables,
            formula.assertions[len(previous.assertions) :],
            formula.provenance[len(previous.assertions) :],
        )
        text += "\n".join(
            line
            for line in SMTLibExporter().export(delta).splitlines()
            if line.startswith("(assert ")
        )
        text += (
            f'\n(check-sat)\n(get-value ({" ".join(formula.variables)}))\n(echo "__claasp_end__")\n'
        )
        self.process.stdin.write(text)
        self.process.stdin.flush()
        output = []
        while True:
            timeout = (
                None
                if self.timeout_seconds is None
                else max(0, self.timeout_seconds - (monotonic() - start))
            )
            try:
                line = self.lines.get(timeout=timeout)
            except Empty as error:
                raise subprocess.TimeoutExpired(self.process.args, self.timeout_seconds) from error
            if line is None:
                raise RuntimeError(
                    "Z3 incremental process ended without a complete result: "
                    + "".join(self.errors)
                )
            if line.strip().strip('"') == "__claasp_end__":
                break
            output.append(line)
        raw = "".join(output)
        status, assignment = Z3Solver._parse_output(raw, formula.variables)
        self.formula = formula
        return SatResult(status, assignment, monotonic() - start, raw, "".join(self.errors))

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.reader.join(timeout=1)
        self.error_reader.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
