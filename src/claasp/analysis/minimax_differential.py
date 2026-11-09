"""Minimize the maximum key/data weight without changing the trail semantics."""

from dataclasses import dataclass
from subprocess import TimeoutExpired

from claasp._result_presentation import PlotMixin as _PlotMixin
from claasp.drivers.solvers import Z3Solver
from claasp.representations.constraints.sat.partitioned_differential import (
    KeyScheduleMinimaxSATModel,
    PartitionedDifferentialTrail,
)


@dataclass(frozen=True, slots=True)
class MinimaxDifferentialResult(_PlotMixin):
    """A checked candidate and explicit optimization completion status.

    EXAMPLES::

        >>> MinimaxDifferentialResult('unknown').is_optimal
        False

    Plotting
    ~~~~~~~~

    Key-schedule and data-path weights are shown separately; their maximum is the objective.

    EXAMPLES::

        >>> result = MinimaxDifferentialResult('unknown', diagnostic='solver timeout')
        >>> artifact = result.plot(show=False)
        >>> artifact.kind
        'search_evidence'
        >>> import matplotlib.pyplot as plt
        >>> plt.close(artifact.figure)
    """

    status: str
    trail: PartitionedDifferentialTrail | None = None
    is_optimal: bool = False
    diagnostic: str | None = None

    def to_terminal(self, *, file=None):
        """Report both group weights, the min-max objective and the ordinary sum."""
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = [
            TableRow.of("status", self.status),
            TableRow.of("proved minimum in model", self.is_optimal),
        ]
        if self.trail is not None:
            rows.extend(
                (
                    TableRow.of("key schedule weight", self.trail.key_schedule_weight),
                    TableRow.of("data path weight", self.trail.data_path_weight),
                    TableRow.of("min-max objective", self.trail.objective_weight),
                    TableRow.of("total characteristic weight", self.trail.total_weight),
                )
            )
        if self.diagnostic:
            rows.append(TableRow.of("diagnostic", self.diagnostic))
        print(
            render_terminal_table(
                Table((TableColumn("field", "Field"), TableColumn("value", "Value")), tuple(rows))
            ),
            file=file,
        )


class MinimaxDifferentialAnalysis:
    """Restore the separate legacy key-schedule/data-path min-max search.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> model = MinimaxDifferentialAnalysis(ToySpeck(2)).model()
        >>> (model.key_input_width, model.data_input_width)
        (16, 8)
    """

    def __init__(self, primitive):
        self.primitive = primitive

    def model(self, **constraints):
        """Construct a partitioned exact ARX model without invoking a solver."""
        return KeyScheduleMinimaxSATModel(self.primitive, **constraints)

    def find_lowest_weight_trail(
        self, *, solver=None, maximum_partition_weight=None, **constraints
    ):
        """Prove a min-max bound, retaining unknown status on interruption."""
        model = self.model(**constraints)
        driver = solver or Z3Solver(timeout_seconds=30)
        formula = model.cnf_formula(maximum_partition_weight=maximum_partition_weight)
        best = None
        lower = 0
        bound = maximum_partition_weight
        while True:
            try:
                solved = driver.solve(formula)
            except TimeoutExpired:
                return MinimaxDifferentialResult(
                    "unknown", best, False, "solver timeout; minimum not proved"
                )
            if solved.assignment is not None:
                candidate = model.decode(solved.assignment)
                if best is None or candidate.objective_weight < best.objective_weight:
                    best = candidate
            status = getattr(solved.status, "value", solved.status)
            if status == "unsatisfiable":
                if best is None:
                    return MinimaxDifferentialResult("unsatisfiable")
                assert bound is not None
                lower = bound + 1
            elif status not in ("satisfiable", "satisfied"):
                return MinimaxDifferentialResult(
                    "unknown", best, False, "solver incomplete; minimum not proved"
                )
            elif best is None:
                raise RuntimeError("SAT solver returned no assignment")
            if lower >= best.objective_weight:
                return MinimaxDifferentialResult("satisfiable", best, True)
            bound = (lower + best.objective_weight - 1) // 2
            formula = model.cnf_formula(maximum_partition_weight=bound)


__all__ = ["MinimaxDifferentialAnalysis", "MinimaxDifferentialResult"]
