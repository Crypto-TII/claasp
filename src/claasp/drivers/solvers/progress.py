# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

"""Portable live MILP bounds and improving solutions, ported from legacy CLAASP."""

import json
import math
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TextIO

GUROBI_SOLUTION_FILE_SETTLING_SECONDS = 2


def _to_float(text):
    try:
        return float(text.strip().rstrip("%"))
    except ValueError:
        return None


class _CplexProgressParser:
    # e.g. "*    12+    5                          900.0000      270.0000            70.00%", with the columns
    # "Node Left Objective IInf Best Integer Best Bound ItCnt Gap": empty cells are blank (e.g. Best Integer and Gap
    # until a trail is found, ItCnt in the rows of the trails found by heuristics) and Best Bound may be replaced by a
    # label of the cuts (e.g. "Cuts: 45"), hence the row is read from its end
    _PROGRESS_LINE = re.compile(r"^\*?\s*\d+\+?\s+\d+\+?\s")
    _CUTS_LABEL = re.compile(r"[A-Za-z][A-Za-z ]*:\s*\d+")

    def parse(self, line):
        if self._PROGRESS_LINE.match(line) is None:
            return None
        tokens = self._CUTS_LABEL.sub(" - ", line).split()
        has_trail = tokens[-1].endswith("%")
        if has_trail:
            tokens.pop()
        if tokens[-1].isdigit():  # the iteration count
            tokens.pop()
        return _to_float(tokens[-1]), _to_float(tokens[-2]) if has_trail else None, None


class _GlpkProgressParser:
    # e.g. "+ 18973: mip =   3.000000000e+03 >=   1.600000000e+01  99.5% (260; 25)", where "mip =" is replaced by
    # ">>>>>" when a better trail is found, the upper bound may be "not found yet" and the lower bound "tree is empty"
    _PROGRESS_LINE = re.compile(
        r"^\+\s*\d+:\s+(?:mip =|>>>>>)\s+(?P<upper>not found yet|\S+)\s+>=\s+(?P<lower>tree is empty|\S+)"
    )

    def parse(self, line):
        match = self._PROGRESS_LINE.match(line)
        if match is None:
            return None
        return _to_float(match["lower"]), _to_float(match["upper"]), None


class _GurobiProgressParser:
    # e.g. "H  123    45                    900.0000000  270.00000  70.0%  12.3    5s", where the first column marks a
    # new incumbent and the incumbent and the gap are "-" until a trail is found
    _PROGRESS_LINE = re.compile(
        r"^[H*]?\s*\d+\s+\d+\s.*\s(?P<upper>-|[\d.e+-]+)\s+(?P<lower>-|[\d.e+-]+)"
        r"\s+(?:-|[\d.]+%)\s+(?:-|[\d.]+)\s+\d+s$"
    )

    def parse(self, line):
        match = self._PROGRESS_LINE.match(line.rstrip())
        if match is None:
            return None
        return _to_float(match["lower"]), _to_float(match["upper"]), None


class _HighsProgressParser:
    # e.g. " L     305     106        81   0.00%   87.25490196     2700              96.77%     4185      6   1192
    # 138983    13.1s", where the first column (the source of a new incumbent) may be empty
    _PROGRESS_LINE = re.compile(
        r"^\s*(?:[A-Za-z]\s+)?\S+\s+\S+\s+\S+\s+(?P<tree>[\d.]+)%\s+(?P<lower>\S+)\s+(?P<upper>\S+)\s+\S+"
        r"\s+\S+\s+\S+\s+\S+\s+\S+\s+[\d.]+s\s*$"
    )

    def parse(self, line):
        match = self._PROGRESS_LINE.match(line)
        if match is None:
            return None
        return _to_float(match["lower"]), _to_float(match["upper"]), _to_float(match["tree"])


class _ScipProgressParser:
    # SCIP prints a table whose columns are separated by "|" and repeats its header every few lines, e.g.
    # " time | node  | left  |...|  dualbound   | primalbound  |  gap   | compl. "
    def __init__(self):
        self._columns = None

    def parse(self, line):
        fields = [field.strip() for field in line.split("|")]
        if "dualbound" in fields and "primalbound" in fields:
            self._columns = {name: index for index, name in enumerate(fields)}
            return None
        if self._columns is None or len(fields) != len(self._columns):
            return None
        lower = _to_float(fields[self._columns["dualbound"]])
        if lower is None:
            return None
        upper = _to_float(fields[self._columns["primalbound"]])
        tree = _to_float(fields[self._columns["compl."]]) if "compl." in self._columns else None
        return lower, upper, tree


# the parser of the output of each solver whose search can be logged
_PROGRESS_PARSERS = {
    "CPLEX_EXT": _CplexProgressParser,
    "GLPK": _GlpkProgressParser,
    "GLPK_EXT": _GlpkProgressParser,
    "GUROBI_EXT": _GurobiProgressParser,
    "HIGHS_EXT": _HighsProgressParser,
    "SCIP_EXT": _ScipProgressParser,
}
PROGRESS_LOG_SOLVERS = tuple(_PROGRESS_PARSERS)


class _HighsImprovingSolutions:
    # HiGHS appends each improving solution to a file, as a block "Objective <value>", "# Columns <-n>" followed by
    # the n nonzero variables (sparse format); the file is read incrementally, and only complete blocks are returned
    def __init__(self, base_path):
        self.file_path = f"{base_path}_improving.sol"
        self._options_file_path = f"{base_path}_highs_options.txt"
        self._offset = 0
        self._pending_lines = [""]

    def file_paths(self):
        return [self._options_file_path, self.file_path]

    def solver_command_arguments(self):
        with open(self._options_file_path, "w") as options_file:
            options_file.write(
                "mip_improving_solution_save = true\n"
                f"mip_improving_solution_file = {self.file_path}\n"
                "mip_improving_solution_report_sparse = true\n"
            )
        return f" --options_file {self._options_file_path}"

    def read_new_solutions(self, final=False):
        if not os.path.exists(self.file_path):
            return []
        with open(self.file_path) as solutions_file:
            solutions_file.seek(self._offset)
            text = solutions_file.read()
            self._offset = solutions_file.tell()
        lines = self._pending_lines[:-1] + (self._pending_lines[-1] + text).split("\n")
        solutions = []
        start = 0
        # the last element of lines is the (possibly empty) line that is still being written
        while start + 1 < len(lines) - 1:
            if not (
                lines[start].startswith("Objective") and lines[start + 1].startswith("# Columns")
            ):
                start += 1
                continue
            end = start + 2 + abs(int(lines[start + 1].split()[-1]))
            if end > len(lines) - 1:
                break
            solutions.append((float(lines[start].split()[-1]), "\n".join(lines[start + 2 : end])))
            start = end
        self._pending_lines = lines[start:]
        return solutions


class _GurobiImprovingSolutions:
    # Gurobi writes each improving solution to the file "<prefix>_<n>.sol", starting with "# Objective value = <value>";
    # a file is read once it is completely written, i.e. once the next file exists, or it has not been modified for
    # GUROBI_SOLUTION_FILE_SETTLING_SECONDS, or the search has ended
    def __init__(self, base_path):
        self._file_prefix = f"{base_path}_improving"
        self._next_index = 0

    def file_paths(self):
        # all the files written by Gurobi, including those not read (e.g. because the logging has stopped)
        number_of_files = self._next_index
        while os.path.exists(self._file_path(number_of_files)):
            number_of_files += 1
        return [self._file_path(index) for index in range(number_of_files)]

    def solver_command_arguments(self):
        return f" SolFiles={self._file_prefix}"

    def read_new_solutions(self, final=False):
        solutions = []
        while os.path.exists(self._file_path(self._next_index)) and self._is_complete(
            self._next_index, final
        ):
            with open(self._file_path(self._next_index)) as solution_file:
                solution_text = solution_file.read()
            objective = re.search(r"# Objective value = (\S+)", solution_text)
            if objective is None:
                raise ValueError("Gurobi solution file has no objective header")
            solutions.append((float(objective[1]), solution_text))
            self._next_index += 1
        return solutions

    def _is_complete(self, index, final):
        if final or os.path.exists(self._file_path(index + 1)):
            return True
        return (
            time.time() - os.path.getmtime(self._file_path(index))
            >= GUROBI_SOLUTION_FILE_SETTLING_SECONDS
        )

    def _file_path(self, index):
        return f"{self._file_prefix}_{index}.sol"


@dataclass(frozen=True, slots=True)
class MILPProgressSnapshot:
    """Observed solver bounds; a progress message is not an optimality proof.

    EXAMPLES::

        >>> MILPProgressSnapshot(1.0, 2.0, 3.0, None).incumbent
        3.0
    """

    elapsed_seconds: float
    dual_bound: float | None
    incumbent: float | None
    tree_percent: float | None


class MILPProgressLog:
    """Write live bounds as JSON lines without changing the optimization.

    ``objective_scale`` converts solver objectives into reported trail weights.
    Bounds retain their reported precision. Only a checked final solver result
    establishes feasibility or optimality. Improving assignments must be checked
    against the portable model before being written.

    EXAMPLES::

        >>> import io
        >>> stream = io.StringIO()
        >>> log = MILPProgressLog(stream, objective_scale=100)
        >>> snapshot = log.feed("+ 1: mip = 300 >= 200 33.3% (1; 0)", "GLPK")
        >>> (snapshot.dual_bound, snapshot.incumbent)
        (2.0, 3.0)
    """

    def __init__(
        self,
        destination: str | Path | TextIO,
        *,
        objective_scale: float = 1,
        minimum_interval_seconds: float = 10,
        heartbeat_seconds: float = 600,
    ):
        if not math.isfinite(objective_scale) or objective_scale <= 0:
            raise ValueError("objective_scale must be finite and positive")
        if minimum_interval_seconds < 0 or heartbeat_seconds <= 0:
            raise ValueError("logging intervals must be non-negative, with a positive heartbeat")
        self.destination = destination
        self.objective_scale = objective_scale
        self.minimum_interval_seconds = minimum_interval_seconds
        self.heartbeat_seconds = heartbeat_seconds
        self.snapshots: list[MILPProgressSnapshot] = []
        self._parsers: dict[str, Any] = {
            name: parser() for name, parser in _PROGRESS_PARSERS.items()
        }
        self._started = time.monotonic()
        self._last_written = float("-inf")
        self._incumbent: float | None = None
        self._bounds: tuple[float | None, float | None, float | None] | None = None

    def _write(self, record):
        text = json.dumps(record, allow_nan=False, sort_keys=True) + "\n"
        if isinstance(self.destination, (str, Path)):
            with open(self.destination, "a", encoding="utf-8") as stream:
                stream.write(text)
        else:
            self.destination.write(text)
            self.destination.flush()

    def feed(self, line: str, solver: str = "GLPK") -> MILPProgressSnapshot | None:
        """Parse one solver line; unrelated lines do not create a snapshot."""
        name = solver.upper()
        if name not in self._parsers:
            raise ValueError(f"unsupported progress format: {solver}")
        parsed = self._parsers[name].parse(line)
        return None if parsed is None else self.update(*parsed)

    def update(self, dual_bound=None, incumbent=None, tree_percent=None):
        """Record callback bounds, writing new incumbents without throttling."""
        scale = self.objective_scale
        clean = lambda value: value if value is not None and math.isfinite(value) else None
        dual, primal = clean(dual_bound), clean(incumbent)
        snapshot = MILPProgressSnapshot(
            time.monotonic() - self._started,
            None if dual is None else dual / scale,
            None if primal is None else primal / scale,
            clean(tree_percent),
        )
        self.snapshots.append(snapshot)
        now = snapshot.elapsed_seconds
        bounds = (snapshot.dual_bound, snapshot.incumbent, snapshot.tree_percent)
        improved = snapshot.incumbent is not None and snapshot.incumbent != self._incumbent
        changed = bounds != self._bounds
        if (
            improved
            or (changed and now - self._last_written >= self.minimum_interval_seconds)
            or now - self._last_written >= self.heartbeat_seconds
        ):
            self._write({"event": "bounds", **asdict(snapshot)})
            self._last_written, self._bounds = now, bounds
            self._incumbent = snapshot.incumbent
        return snapshot

    @staticmethod
    def parse_integer_solution(text, variable_indices):
        """Read legacy sparse integer solution files using zero-based indices.

        Primal values precede dual values; the first occurrence is retained.
        Missing sparse variables are zero. This is parsing only: feasibility
        must still be checked before using an imported assignment.

        EXAMPLES::

            >>> MILPProgressLog.parse_integer_solution("x_1 0.9999999\\nx_2 -2e-13\\n", {"a": 0, "b": 1})
            {'a': 1.0, 'b': 0.0}
        """
        number = r"[-+]?(?:[0-9]+[.]?[0-9]*|[.][0-9]+)(?:[eE][-+]?[0-9]+)?"
        values: dict[int, float] = {}
        for index, value in re.findall(r"[xyz]_([0-9]+)[\s]+[\*]?[\s]*(%s)" % number, text):
            values.setdefault(int(index), float(round(float(value))))
        if any(not isinstance(index, int) or index < 0 for index in variable_indices.values()):
            raise ValueError("variable indices must be non-negative integers")
        return {name: values.get(index + 1, 0.0) for name, index in variable_indices.items()}

    def record_solution(self, model, assignment, *, status="feasible"):
        """Write an improving assignment only after checking its feasibility."""
        if not model.is_feasible(assignment):
            raise ValueError("progress assignment violates the model")
        self._write(
            {
                "event": "solution",
                "status": status,
                "objective": model.objective_value(assignment) / self.objective_scale,
                "assignment": dict(assignment),
            }
        )

    def finish(self, result):
        """Record the final validated driver status, including interrupted searches."""
        self._write(
            {
                "event": "finished",
                "status": result.status.value,
                "runtime_seconds": result.runtime_seconds,
                "objective": None
                if result.objective_value is None
                else result.objective_value / self.objective_scale,
            }
        )


__all__ = ["MILPProgressLog", "MILPProgressSnapshot"]
