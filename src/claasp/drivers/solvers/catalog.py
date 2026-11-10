"""Discover supported solver adapters without importing optional solver packages."""

from dataclasses import dataclass
from importlib.util import find_spec
from shutil import which
from typing import TextIO


@dataclass(frozen=True, slots=True)
class SolverInfo:
    """One supported adapter and its optional local installation evidence.

    ``installed=None`` means detection was not requested. Detection checks the
    default executable on PATH or Python package discovery; it does not run a
    solve, validate a commercial license, or certify every model's compatibility.

    EXAMPLES::

        >>> item = solver_catalog().entries[0]
        >>> item.name, item.family, item.installed
        ('Kissat', 'SAT', None)
    """

    name: str
    family: str
    driver: str
    requirement: str
    installed: bool | None = None
    detail: str = "not checked"


@dataclass(frozen=True, slots=True)
class SolverCatalog:
    """Immutable solver catalogue with terminal and programmatic access.

    EXAMPLES::

        >>> catalog = solver_catalog()
        >>> len(catalog.entries), catalog.view
        (8, 'supported')
        >>> from io import StringIO
        >>> output = StringIO()
        >>> catalog.to_terminal(file=output)
        >>> 'KissatSolver' in output.getvalue()
        True
    """

    entries: tuple[SolverInfo, ...]
    view: str

    def to_terminal(self, *, file: TextIO | None = None) -> None:
        """Print supported adapters, locally installed adapters, or both.

        EXAMPLES::

            >>> from io import StringIO
            >>> stream = StringIO()
            >>> solver_catalog().to_terminal(file=stream)
            >>> 'Requirement' in stream.getvalue()
            True
        """
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        columns = [
            TableColumn(key, title)
            for key, title in (
                ("name", "Solver"),
                ("family", "Backend"),
                ("driver", "Driver"),
                ("requirement", "Requirement"),
            )
        ]
        checked = self.view != "supported"
        if checked:
            columns.extend(
                (TableColumn("installed", "Installed"), TableColumn("detail", "Detection"))
            )
        rows = tuple(
            TableRow.of(
                item.name,
                item.family,
                item.driver,
                item.requirement,
                *((("yes" if item.installed else "no"), item.detail) if checked else ()),
            )
            for item in self.entries
        )
        print(render_terminal_table(Table(tuple(columns), rows)), file=file)
        if checked:
            print(
                "Installation detection uses default executables on PATH or package discovery. "
                "It does not check solver configuration, licenses, or model compatibility.",
                file=file,
            )
        if not self.entries:
            print("No supported solver installation detected.", file=file)


# Explicit adapter inventory: no driver is instantiated during discovery.
_BACKENDS = (
    ("Kissat", "SAT", "KissatSolver", "kissat", "executable"),
    ("MiniSat", "SAT", "MinisatSolver", "minisat", "executable"),
    ("CryptoMiniSat", "SAT", "CryptoMiniSatSolver", "cryptominisat5", "executable"),
    ("Z3", "SMT / Boolean SAT", "Z3Solver", "z3", "executable"),
    ("GLPK", "MILP / Boolean SAT", "GLPKSolver", "glpsol", "executable"),
    ("HiGHS", "MILP / Boolean SAT", "HighsSolver", "scipy", "package"),
    ("MiniZinc", "CP / Boolean SAT", "MiniZincSolver", "minizinc", "executable"),
    ("Gurobi", "MILP", "GurobiSolver", "gurobipy", "package"),
)


def solver_catalog(view: str = "supported") -> SolverCatalog:
    """Return supported adapters (default), installed ones, or a comparison table.

    ``view='supported'`` performs no local detection and requires no optional
    dependencies. ``'available'`` filters to detected installations; ``'both'``
    retains every supported adapter and records installation evidence. Executable
    detection uses default driver names, not custom paths passed to a driver.
    MiniZinc still needs a configured solver, HiGHS uses SciPy's ``optimize.milp``,
    and Gurobi needs a valid license when solving. These are installation checks,
    not a claim that every trail model supports every backend.

    EXAMPLES::

        >>> from claasp import solver_catalog
        >>> tuple(item.name for item in solver_catalog().entries)
        ('Kissat', 'MiniSat', 'CryptoMiniSat', 'Z3', 'GLPK', 'HiGHS', 'MiniZinc', 'Gurobi')
        >>> # Display local installation evidence alongside every supported adapter:
        >>> solver_catalog('both').to_terminal()  # doctest: +SKIP
        >>> # Keep only installed backends, or inspect entries in Python:
        >>> installed = solver_catalog('available')
        >>> all(item.installed for item in installed.entries)
        True
        >>> solver_catalog('unknown')
        Traceback (most recent call last):
        ...
        ValueError: view must be 'supported', 'available', or 'both'
    """
    if view not in ("supported", "available", "both"):
        raise ValueError("view must be 'supported', 'available', or 'both'")
    entries = []
    for name, family, driver, requirement, detection in _BACKENDS:
        installed = None
        detail = "not checked"
        if view != "supported":
            if detection == "executable":
                location = which(requirement)
                installed = location is not None
                detail = location or "not found on PATH"
            else:
                try:
                    installed = find_spec(requirement) is not None
                except (ImportError, ValueError):
                    installed = False
                detail = "package found" if installed else "package not found"
            if name == "MiniZinc" and installed:
                detail += "; configured solver required (default: gecode)"
            if name == "HiGHS" and installed:
                detail += "; scipy.optimize.milp required"
            if name == "Gurobi" and installed:
                detail += "; license not checked"
        if view != "available" or installed:
            entries.append(SolverInfo(name, family, driver, requirement, installed, detail))
    return SolverCatalog(tuple(entries), view)
