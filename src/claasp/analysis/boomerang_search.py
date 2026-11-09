"""Solver-backed restoration of the legacy restricted ARX boomerang search."""

from dataclasses import dataclass, replace
from enum import Enum
from subprocess import TimeoutExpired

from claasp._result_presentation import PlotMixin as _PlotMixin
from claasp.drivers.solvers import Z3Solver
from claasp.representations.constraints.sat.boomerang import ARXBoomerangTrail, BoomerangSATModel


class BoomerangSearchStatus(str, Enum):
    """Include interrupted searches without extending the complete SAT contract.

    EXAMPLES::

        >>> BoomerangSearchStatus.UNKNOWN.value
        'unknown'
    """

    SATISFIABLE = "satisfiable"
    UNSATISFIABLE = "unsatisfiable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class BoomerangSearchResult(_PlotMixin):
    """Search completion within the explicitly restricted characteristic model.

    UNSAT means no characteristic in this model, not absence of a boomerang
    distinguisher. A minimum outer weight is not an exact full probability.

    EXAMPLES::

        >>> BoomerangSearchResult(BoomerangSearchStatus.UNKNOWN).is_optimal
        False

    Plotting
    ~~~~~~~~

    Outer weights exclude the switch; local switch probabilities are labelled separately.

    EXAMPLES::

        >>> result = BoomerangSearchResult(BoomerangSearchStatus.UNKNOWN)
        >>> artifact = result.plot(show=False)
        >>> artifact.kind
        'search_evidence'
        >>> import matplotlib.pyplot as plt
        >>> plt.close(artifact.figure)
    """

    status: BoomerangSearchStatus
    trail: ARXBoomerangTrail | None = None
    is_optimal: bool = False
    diagnostic: str | None = None

    def to_terminal(self, *, file=None):
        """Print the model result and the checked characteristic when available."""
        print(f"Boomerang search: {self.status.value}", file=file)
        print(f"Minimum outer weight proved within restricted model: {self.is_optimal}", file=file)
        if self.diagnostic:
            print(self.diagnostic, file=file)
        if self.trail is not None:
            self.trail.to_terminal(file=file)


def _search_status(status):
    value = status.value
    if value in {"satisfiable", "satisfied"}:
        return BoomerangSearchStatus.SATISFIABLE
    if value == "unsatisfiable":
        return BoomerangSearchStatus.UNSATISFIABLE
    return BoomerangSearchStatus.UNKNOWN


class BoomerangAnalysis:
    """Find checked upper/lower ARX characteristics with a large middle switch.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> analysis = BoomerangAnalysis(ToySpeck(3), switch_round=1)
        >>> analysis.model().switches
        ('modular_add_1_1',)
    """

    def __init__(
        self, primitive, *, switch_round=None, components=None, upper_window=None, lower_window=None
    ):
        self.primitive = primitive
        self.switch_round = switch_round
        self.components = components
        self.upper_window = upper_window
        self.lower_window = lower_window

    def model(self, *, input_difference=None, output_difference=None):
        """Build the restricted model without starting a solver."""
        return BoomerangSATModel(
            self.primitive,
            switch_round=self.switch_round,
            components=self.components,
            input_difference=input_difference,
            output_difference=output_difference,
            upper_window=self.upper_window,
            lower_window=self.lower_window,
        )

    def find_one_trail(
        self, *, input_difference=None, output_difference=None, maximum_weight=None, solver=None
    ):
        """Return a checked candidate, retaining unknown/incomplete solver status."""
        model = self.model(input_difference=input_difference, output_difference=output_difference)
        driver = solver or Z3Solver(timeout_seconds=30)
        formula = model.cnf_formula(maximum_weight=maximum_weight)
        try:
            solved = driver.solve(formula)
        except TimeoutExpired:
            return BoomerangSearchResult(
                BoomerangSearchStatus.UNKNOWN,
                diagnostic="solver timeout; no checked characteristic returned",
            )
        status = _search_status(solved.status)
        if solved.assignment is not None:
            trail = model.decode(solved.assignment)
            return BoomerangSearchResult(
                status,
                replace(trail, model_complete=status is BoomerangSearchStatus.SATISFIABLE),
            )
        return BoomerangSearchResult(_search_status(solved.status))

    def find_lowest_weight_trail(
        self, *, input_difference=None, output_difference=None, maximum_weight=None, solver=None
    ):
        """Minimize only the sum of upper and lower trail weights, as in legacy."""
        model = self.model(input_difference=input_difference, output_difference=output_difference)
        driver = solver or Z3Solver(timeout_seconds=30)
        formula = model.cnf_formula(maximum_weight=maximum_weight)
        best = None
        lower = 0
        bound = maximum_weight
        while True:
            try:
                solved = driver.solve(formula)
            except TimeoutExpired:
                return BoomerangSearchResult(
                    BoomerangSearchStatus.UNKNOWN, best, False, "solver timeout; minimum not proved"
                )
            if solved.assignment is not None:
                candidate = model.decode(solved.assignment)
                if best is None or candidate.outer_weight < best.outer_weight:
                    best = candidate
            status = _search_status(solved.status)
            if status is BoomerangSearchStatus.UNKNOWN:
                return BoomerangSearchResult(
                    BoomerangSearchStatus.UNKNOWN,
                    best,
                    False,
                    "solver incomplete; minimum not proved",
                )
            if status is BoomerangSearchStatus.UNSATISFIABLE:
                if best is None:
                    return BoomerangSearchResult(_search_status(solved.status))
                assert bound is not None
                lower = bound + 1
            else:
                if best is None:
                    raise RuntimeError("SAT solver returned no assignment")
            if best is not None and lower >= int(best.outer_weight):
                return BoomerangSearchResult(
                    BoomerangSearchStatus.SATISFIABLE, replace(best, model_complete=True), True
                )
            bound = (lower + int(best.outer_weight) - 1) // 2
            formula = model.cnf_formula(maximum_weight=bound)
