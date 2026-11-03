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

"""Live logging of the bounds proved by an external MILP solver during a lowest-weight trail search.

A MILP lowest-weight search is a single branch-and-bound optimisation. While it runs, the solver keeps a lower bound
on the optimal weight (the dual bound) and the best trail found so far (the incumbent, i.e. an upper bound) and prints
them periodically. :py:class:`MilpProgressLog` reads the output of the solver while it runs and appends to a log file
the bounds, converted to trail weights, and, when the solver can save them, the trails found along the way. The search
itself is not modified.
"""

import ctypes
import datetime
import math
import os
import re
import time
import tracemalloc
from contextlib import contextmanager

from sage.numerical.backends import glpk_backend as glpk_backend_module

from claasp.cipher_modules.models.milp.solvers import MODEL_DEFAULT_PATH
from claasp.cipher_modules.models.milp.utils.utils import _get_variables_value
from claasp.name_mappings import CIPHER_OUTPUT, SATISFIABLE

# a solution file of Gurobi not modified for this many seconds is considered completely written
# (2 seconds, so that more than 1 second has passed also on filesystems that record modification times in seconds)
GUROBI_SOLUTION_FILE_SETTLING_SECONDS = 2
# the lowest verbosity of the GLPK backend of Sage at which GLPK prints its bounds (it only changes the output)
GLPK_PROGRESS_VERBOSITY = 2
_GLPK_TERM_HOOK = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_char_p)
# a line whose only change is a better lower bound is written at most once every this many seconds
PROGRESS_LOG_MIN_SECONDS_BETWEEN_LOWER_BOUND_LINES = 10
# if nothing changes, a line is written anyway every this many seconds, to show that the search is still running
PROGRESS_LOG_HEARTBEAT_SECONDS = 600


def create_progress_log(model, search_name, solver_name, weight_precision, start_time):
    """
    Return a :py:class:`MilpProgressLog` for ``solver_name``, raising an error if the solver does not support it.

    INPUT:

    - ``model`` -- **MilpModel object**; the model of the search
    - ``search_name`` -- **string**; the name of the search, used in the name of the log file
    - ``solver_name`` -- **string**; the name of the solver solving the model
    - ``weight_precision`` -- **integer**; the number of decimals of the weight of the trail
    - ``start_time`` -- **float**; the time (as returned by ``time.time()``) at which the search started

    EXAMPLES::

        sage: import time
        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
        sage: from claasp.cipher_modules.models.milp.utils.milp_progress_log import create_progress_log
        sage: milp = MilpXorDifferentialModel(SpeckBlockCipher(number_of_rounds=2))
        sage: create_progress_log(milp, 'find_lowest_weight_xor_differential_trail', 'Coin', 2, time.time())
        Traceback (most recent call last):
        ...
        ValueError: Live logging of the search is not available for the COIN solver; ...
    """
    solver_name = solver_name.upper()
    if solver_name not in PROGRESS_LOG_SOLVERS:
        raise ValueError(
            f"Live logging of the search is not available for the {solver_name} solver; use log=False or one of the "
            f"solvers {', '.join(PROGRESS_LOG_SOLVERS)}."
        )
    file_name = f"{model.cipher_id}__milp_{search_name}__{solver_name}solver.log"
    return MilpProgressLog(file_name, model, search_name, solver_name, weight_precision, start_time)


def format_trail(cipher, components_values):
    """
    Return the values of the inputs and of the output of ``cipher`` in ``components_values`` on a single line.

    INPUT:

    - ``cipher`` -- **Cipher object**; the cipher of the trail
    - ``components_values`` -- **dictionary**; the values of the components of the trail, in standard format

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.milp.utils.milp_progress_log import format_trail
        sage: speck = SpeckBlockCipher(number_of_rounds=2)
        sage: components_values = {'plaintext': {'value': '0x00400000'}, 'key': {'value': '0x0'},
        ....:                      'cipher_output_1_12': {'value': '0x80008002'}}
        sage: format_trail(speck, components_values)
        'plaintext 0x00400000, key 0x0, cipher_output_1_12 0x80008002'
    """
    component_ids = cipher.inputs + [
        component.id for component in cipher.all_components() if component.type == CIPHER_OUTPUT
    ]
    # linear models store the output mask of a component with the "_o" suffix
    keys = [key for component_id in component_ids for key in (component_id, f"{component_id}_o")]
    return ", ".join(f"{key} {components_values[key]['value']}" for key in keys if key in components_values)


def _get_glp_term_hook():
    # glp_term_hook is looked up through the GLPK backend of Sage, hence in the GLPK library that Sage is linked to,
    # whose output is the one redirected to the log
    return ctypes.CDLL(glpk_backend_module.__file__).glp_term_hook


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
            if not (lines[start].startswith("Objective") and lines[start + 1].startswith("# Columns")):
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
        while os.path.exists(self._file_path(self._next_index)) and self._is_complete(self._next_index, final):
            with open(self._file_path(self._next_index)) as solution_file:
                solution_text = solution_file.read()
            solutions.append((float(re.search(r"# Objective value = (\S+)", solution_text)[1]), solution_text))
            self._next_index += 1
        return solutions

    def _is_complete(self, index, final):
        if final or os.path.exists(self._file_path(index + 1)):
            return True
        return time.time() - os.path.getmtime(self._file_path(index)) >= GUROBI_SOLUTION_FILE_SETTLING_SECONDS

    def _file_path(self, index):
        return f"{self._file_prefix}_{index}.sol"


class MilpProgressLog:
    """
    Append to a log file the bounds proved by a MILP solver, and the trails it finds, while it runs.

    Each line starts with the wall-clock time and the time elapsed since the beginning of the search (model building
    included). The bounds are converted to trail weights, the objective being the trail weight multiplied by
    ``10^weight_precision``. The lower bound written is the dual bound of the solver rounded down to an integer
    objective (with a tolerance of ``1e-6``), so that it never exceeds what the solver has proved, even when the solver
    reports a bound slightly above the optimum because of its numerical tolerances. The written lines are:

    - ``weight >= <lower bound> | weight <= <upper bound> | gap <gap> | tree <tree>``, where ``gap`` is
      ``(upper bound - lower bound) / upper bound`` and ``tree`` is the percentage of the branch-and-bound tree
      already explored, as estimated by the solver (``n/a`` if the solver does not estimate it). It is written when the
      upper bound improves, when the lower bound improves (at most once every
      ``PROGRESS_LOG_MIN_SECONDS_BETWEEN_LOWER_BOUND_LINES`` seconds), and, if nothing changes, every
      ``PROGRESS_LOG_HEARTBEAT_SECONDS`` seconds.
    - ``new trail, weight <weight>``, followed by a line with the values of the inputs and of the output of the cipher
      in the trail, each time the solver finds a better trail (only with the solvers that save these trails, see the
      table below).
    - at the end of the search, the optimal weight and the optimal trail, or a line stating that no trail was found,
      with the status of the search.

    Every solver logs the bounds and the optimal trail; the other information depends on the solver:

    ==============  ===========================  =======================
    Solver          Intermediate trails logged   Tree exploration logged
    ==============  ===========================  =======================
    ``CPLEX_EXT``   no                           no
    ``GLPK``        no                           no
    ``GLPK_EXT``    no                           no
    ``GUROBI_EXT``  yes                          no
    ``HIGHS_EXT``   yes                          yes
    ``SCIP_EXT``    no                           yes
    ==============  ===========================  =======================

    The logging is not available for the other solvers, and :py:func:`create_progress_log` raises an error with them:
    the bounds of ``Coin``, ``CVXOPT``, ``Gurobi``, ``InteractiveLP`` and ``PPL`` cannot be read while they solve, and
    ``GLPK/exact`` cannot solve these models, since it only supports continuous variables.

    .. NOTE::

        With the internal ``GLPK`` solver, the logging runs inside the solver call, which Sage protects with
        ``sig_on()``: interrupting the search (e.g. with Ctrl-C) exactly while a line of the log is being processed
        can leave the Sage session in an inconsistent state. The chance is small, since the logging runs for a fraction
        of a millisecond every few seconds, but use ``GLPK_EXT`` if the search may need to be interrupted.

    INPUT:

    - ``file_name`` -- **string**; the path of the log file; the content is appended
    - ``model`` -- **MilpModel object**; the model of the search
    - ``search_name`` -- **string**; the name of the search
    - ``solver_name`` -- **string**; the name of the solver, one of ``PROGRESS_LOG_SOLVERS``
    - ``weight_precision`` -- **integer**; the number of decimals of the weight of the trail
    - ``start_time`` -- **float**; the time (as returned by ``time.time()``) at which the search started

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
        sage: speck = SpeckBlockCipher(number_of_rounds=5)
        sage: milp = MilpXorDifferentialModel(speck)
        sage: trail = milp.find_lowest_weight_xor_differential_trail(solver_name='SCIP_EXT', log=True) # doctest: +SKIP
        sage: print(open(f'{speck.id}__milp_find_lowest_weight_xor_differential_trail__SCIP_EXTsolver.log').read()) # doctest: +SKIP
        2026-10-06 18:04:58 | 0:00:00 | search started: find_lowest_weight_xor_differential_trail, speck_p32_k64_o32_r5, SCIP_EXT solver
        2026-10-06 18:05:00 | 0:00:02 | weight >= 0.00 | weight <= 35.00 | gap 100.0% | tree n/a
        ...
        2026-10-06 18:05:29 | 0:00:31 | weight >= 9.00 | weight <= 9.00 | gap 0.0% | OPTIMAL
        2026-10-06 18:05:29 | 0:00:31 | optimal trail, weight 9.00
        plaintext 0x02110a04, key 0x0000000000000000, cipher_output_4_12 0x850a9520
    """

    def __init__(self, file_name, model, search_name, solver_name, weight_precision, start_time):
        self.file_name = file_name
        self._model = model
        self._solver_name = solver_name
        self._start_time = start_time
        self._weight_precision = weight_precision
        self._parser = _PROGRESS_PARSERS[solver_name]()
        # looked up here, so that a missing function raises an error before the model is built
        self._glp_term_hook = _get_glp_term_hook() if solver_name == "GLPK" else None
        self._glpk_pending_output = ""
        self._peak_memory = 0
        self._logging_memory = 0
        self._improving_solutions = None
        self._lower_bound = 0
        self._upper_bound = None
        self._tree = None
        self._written_bounds = None
        self._last_bounds_line_time = 0
        self._failed = False
        self._write(f"search started: {search_name}, {model.cipher_id}, {solver_name} solver")

    def solver_command_arguments(self, model_path):
        """
        Return the arguments to add to the command line of the solver, so that it saves the trails it finds.

        INPUT:

        - ``model_path`` -- **string**; the path of the .lp file of the model
        """
        improving_solutions_class = {
            "GUROBI_EXT": _GurobiImprovingSolutions,
            "HIGHS_EXT": _HighsImprovingSolutions,
        }.get(self._solver_name)
        if improving_solutions_class is None:
            return ""
        self._improving_solutions = improving_solutions_class(f"{MODEL_DEFAULT_PATH}/{model_path[:-3]}")
        return self._improving_solutions.solver_command_arguments()

    def finish_solver_run(self):
        """
        Write the trails found by the solver and not yet written, then remove the files created for the log.

        It is called when the solver has terminated, before the files with the trails are removed.
        """
        self._run_safely(self._write_new_trails, True)
        if self._improving_solutions is None:
            return
        for file_path in self._improving_solutions.file_paths():
            if os.path.exists(file_path):
                os.remove(file_path)

    @contextmanager
    def logging_glpk_output(self, glpk_backend):
        """
        Pass to :py:meth:`process_line` the output of the GLPK library, instead of printing it, while active.

        GLPK runs inside the Python process without releasing the GIL, hence its output cannot be read by another
        thread: it is received through the ``glp_term_hook`` callback of GLPK instead, which GLPK calls for each
        string it prints. The verbosity of ``glpk_backend`` is raised to ``GLPK_PROGRESS_VERBOSITY``, which only
        changes the output, and reset afterwards.

        INPUT:

        - ``glpk_backend`` -- **GLPKBackend object**; the backend of the Sage model solved while active
        """
        term_hook = _GLPK_TERM_HOOK(self._receive_glpk_output)
        glpk_backend.set_verbosity(GLPK_PROGRESS_VERBOSITY)
        self._glp_term_hook(term_hook, None)
        try:
            yield
        finally:
            self._glp_term_hook(None, None)
            glpk_backend.set_verbosity(0)
            if self._glpk_pending_output:
                self.process_line(self._glpk_pending_output)
                self._glpk_pending_output = ""

    def _receive_glpk_output(self, info, text):
        # GLPK may print a line in several strings
        self._glpk_pending_output += text.decode(errors="replace")
        *lines, self._glpk_pending_output = self._glpk_pending_output.split("\n")
        for line in lines:
            self.process_line(line)
        # a nonzero value prevents GLPK from printing the string: only its error messages are still printed
        return 0 if "Error" in text.decode(errors="replace") else 1

    def process_line(self, line):
        """
        Process a line of the output of the solver, writing to the log what has changed.

        The memory used by the logging is excluded from the peak memory traced by ``tracemalloc``, which is the memory
        reported for the search (see :py:meth:`peak_memory_without_logging`).

        INPUT:

        - ``line`` -- **string**; a line of the output of the solver
        """
        current_memory, peak_memory = tracemalloc.get_traced_memory()
        self._peak_memory = max(self._peak_memory, peak_memory - self._logging_memory)
        self._run_safely(self._process_line, line)
        self._logging_memory += tracemalloc.get_traced_memory()[0] - current_memory
        tracemalloc.reset_peak()

    def peak_memory_without_logging(self):
        """Return the peak memory traced by ``tracemalloc``, excluding the memory used by :py:meth:`process_line`."""
        return max(self._peak_memory, tracemalloc.get_traced_memory()[1] - self._logging_memory)

    def write_final(self, solution):
        """
        Write the result of the search to the log.

        INPUT:

        - ``solution`` -- **dictionary**; the solution returned by the search
        """
        self._run_safely(self._write_final, solution)

    def _run_safely(self, logging_function, argument):
        # the logging must never stop the search nor change its result: if it fails (e.g. because the disk is full or
        # the output of the solver has an unexpected format), the logging is stopped instead
        if self._failed:
            return
        try:
            logging_function(argument)
        except Exception as error:
            self._failed = True
            print(f"Live logging of the search stopped because of an error: {error!r}")

    def _process_line(self, line):
        self._write_new_trails()
        progress = self._parser.parse(line)
        if progress is not None:
            self._update_bounds(*progress)
            self._write_bounds_if_needed()

    def _write_final(self, solution):
        if solution["status"] != SATISFIABLE:
            self._write(f"no trail found (status {solution['status']})")
            return
        weight = self._format_weight(solution["total_weight"])
        self._write(f"weight >= {weight} | weight <= {weight} | gap 0.0% | OPTIMAL")
        self._write(f"optimal trail, weight {weight}")
        self._write_raw(format_trail(self._model.cipher, solution["components_values"]))

    def _write_new_trails(self, final=False):
        if self._improving_solutions is None:
            return
        for objective, solution_text in self._improving_solutions.read_new_solutions(final):
            self._update_bounds(None, objective, None)
            components_values = self._model._get_component_values(
                _get_variables_value(self._model.integer_variable, solution_text),
                _get_variables_value(self._model.binary_variable, solution_text),
            )
            self._write(f"new trail, weight {self._format_weight(round(objective) / 10**self._weight_precision)}")
            self._write_raw(format_trail(self._model.cipher, components_values))

    def _update_bounds(self, lower, upper, tree):
        # the dual bound is rounded down, so that a bound reported slightly above the optimum (e.g. 900.00002 for an
        # optimum of 900, because of the numerical tolerances of the solver) is not rounded up above the optimum
        if lower is not None and math.isfinite(lower):
            self._lower_bound = max(self._lower_bound, math.floor(lower + 1e-6))
        if upper is not None and math.isfinite(upper):
            upper = round(upper)
            self._upper_bound = upper if self._upper_bound is None else min(self._upper_bound, upper)
        # SCIP sometimes prints an unknown completion between two estimates: the last estimate is kept
        if tree is not None:
            self._tree = tree

    def _is_bounds_line_due(self, now):
        if self._written_bounds is None:
            return True
        written_lower_bound, written_upper_bound = self._written_bounds
        seconds_since_last_line = now - self._last_bounds_line_time
        if self._upper_bound != written_upper_bound or seconds_since_last_line >= PROGRESS_LOG_HEARTBEAT_SECONDS:
            return True
        lower_bound_improved = self._lower_bound != written_lower_bound
        return lower_bound_improved and seconds_since_last_line >= PROGRESS_LOG_MIN_SECONDS_BETWEEN_LOWER_BOUND_LINES

    def _write_bounds_if_needed(self):
        now = time.time()
        if not self._is_bounds_line_due(now):
            return
        self._written_bounds = (self._lower_bound, self._upper_bound)
        self._last_bounds_line_time = now
        precision = 10**self._weight_precision
        upper_bound = "inf" if self._upper_bound is None else self._format_weight(self._upper_bound / precision)
        tree = "n/a" if self._tree is None else f"{self._tree:.1f}%"
        self._write(
            f"weight >= {self._format_weight(self._lower_bound / precision)} | weight <= {upper_bound} | "
            f"gap {self._format_gap()} | tree {tree}"
        )

    def _format_gap(self):
        if self._upper_bound is None:
            return "n/a"
        if self._upper_bound == 0:
            return "0.0%"
        return f"{max(0, self._upper_bound - self._lower_bound) / self._upper_bound * 100:.1f}%"

    def _format_weight(self, weight):
        return f"{weight:.{self._weight_precision}f}"

    def _write(self, message):
        elapsed = datetime.timedelta(seconds=round(time.time() - self._start_time))
        self._write_raw(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} | {elapsed} | {message}")

    def _write_raw(self, line):
        with open(self.file_name, "a") as log_file:
            log_file.write(f"{line}\n")
