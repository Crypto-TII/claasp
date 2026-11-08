"""Portable wordwise active-S-box lower bounds, including grouped bit graphs."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActiveSBoxResult:
    """A wordwise relaxation objective, with a lower bound only after optimality.

    EXAMPLES::

        >>> ActiveSBoxResult('feasible', 7, False).lower_bound is None
        True
        >>> ActiveSBoxResult('optimal', 5, True).lower_bound
        5
    """

    status: str
    model_objective: int | None
    complete: bool
    branch_numbers: tuple[tuple[str, int], ...] = ()

    def __post_init__(self):
        if self.model_objective is not None and (
            not isinstance(self.model_objective, int)
            or isinstance(self.model_objective, bool)
            or self.model_objective < 0
        ):
            raise ValueError("model objective must be a nonnegative integer")
        if self.complete and (self.status != "optimal" or self.model_objective is None):
            raise ValueError("a lower bound requires completed optimal model solving")

    @property
    def lower_bound(self):
        """Return the proved lower bound, or None for an incomplete solve."""
        return self.model_objective if self.complete else None

    def to_terminal(self, *, file=None):
        """Report the relaxation bound without claiming an exact differential."""
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = (
            TableRow.of("status", self.status),
            TableRow.of("model", "wordwise branch-number relaxation"),
            TableRow.of(
                "proved active-S-box lower bound",
                self.lower_bound if self.lower_bound is not None else "-",
            ),
            TableRow.of(
                "candidate model objective",
                self.model_objective if self.model_objective is not None else "-",
            ),
        )
        print(
            render_terminal_table(
                Table((TableColumn("field", "Field"), TableColumn("value", "Value")), rows)
            ),
            file=file,
        )

    def plot(self, *, show=True, save_to=None):
        """Plot retained evidence without rerunning a solver.

        An incomplete relaxation shows a candidate objective, never a proved lower bound.

        Requires the optional ``presentation`` extra. ``show=False`` suppresses
        display; ``save_to`` writes a file. Returns a ``FigureArtifact`` with
        the figure and plotted numeric series. Empty searches show their status.

        EXAMPLES::

            >>> result = ActiveSBoxResult('feasible', 5, False)
            >>> artifact = result.plot(show=False)
            >>> artifact.kind
            'search_evidence'
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._search_results import _plot

        return _plot(self, show=show, save_to=save_to)


class WordwiseActivityAnalysis:
    """Compute a branch-number activity relaxation with explicit word grouping.

    Large binary linear layers use an optional exact branch-number driver.
    Those optimizations are cached by matrix and word size within this object.
    They must finish before the outer model may use their branch numbers.

    EXAMPLES::

        >>> from claasp.primitives import Ublock
        >>> analysis = WordwiseActivityAnalysis(Ublock(number_of_rounds=1))
        >>> analysis.model().milp_model().objective_sense.value
        'minimize'
    """

    def __init__(self, primitive):
        self.primitive = primitive
        self._branches = {}

    def model(
        self, *, active_input=None, zero_difference_inputs=None, word_size=None, branch_driver=None
    ):
        """Resolve exact branch properties, then build the portable activity model."""
        from claasp.analysis.component_properties import (
            ComponentProperty,
            PropertyClaim,
            PropertyDomain,
            PropertyRequest,
        )
        from claasp.components import BitVectorSBox, LinearMap
        from claasp.drivers.analysis import MiniZincBranchNumberDriver
        from claasp.representations.constraints.milp import (
            WordwiseBranchNumberActiveSBoxesMILPModel,
        )
        from claasp.representations.constraints.milp._word_activity import word_size_for_graph
        from claasp.unit_types import Bit

        graph = self.primitive.graph
        if active_input is None:
            active_input = next(
                (name for name in graph.input_arrays if name not in graph.secret_inputs), None
            )
        if active_input not in graph.input_arrays:
            raise ValueError("active_input must name a primitive input")
        if zero_difference_inputs is None:
            zero_difference_inputs = tuple(
                name for name in graph.input_arrays if name != active_input
            )
        if any(
            name == active_input or name not in graph.input_arrays
            for name in zero_difference_inputs
        ):
            raise ValueError("zero_difference_inputs must name other primitive inputs")
        certificates = {}
        if any(isinstance(c, BitVectorSBox) for c in graph.components):
            size = word_size_for_graph(self.primitive)
            if word_size is not None and (
                not isinstance(word_size, int) or isinstance(word_size, bool) or word_size != size
            ):
                raise ValueError("word_size must match the S-box input size")
            driver = branch_driver or MiniZincBranchNumberDriver(timeout_seconds=60)
            request = PropertyRequest(
                ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
                PropertyDomain.WORD_LINEAR,
                (("word_size", size),),
            )
            for component in graph.components:
                if not isinstance(component, LinearMap) or not isinstance(
                    component.output_type.unit_type, Bit
                ):
                    continue
                key = (component.matrix, size)
                if key not in self._branches:
                    result = driver.analyze(component, request)
                    if result.claim is not PropertyClaim.EXACT or not result.complete:
                        raise RuntimeError(
                            f"exact word branch number unavailable: {result.diagnostic}"
                        )
                    self._branches[key] = result
                certificates[component.component_id] = self._branches[key]
        return WordwiseBranchNumberActiveSBoxesMILPModel(
            self.primitive,
            active_input=active_input,
            zero_difference_inputs=tuple(zero_difference_inputs),
            word_size=word_size,
            branch_numbers=certificates,
        )

    def find_lowest_number_of_active_sboxes(self, *, solver=None, **options):
        """Optimize the relaxation; incomplete candidates are not lower bounds."""
        from subprocess import TimeoutExpired

        from claasp.drivers.solvers import GLPKSolver, MILPStatus

        model = self.model(**options)
        driver = solver or GLPKSolver(timeout_seconds=60)
        try:
            solved = driver.solve(model.milp_model())
        except TimeoutExpired:
            return ActiveSBoxResult("unknown", None, False)
        value = None
        if solved.assignment is not None:
            value = model.decode_activity(solved.assignment).active_sboxes
        complete = solved.status is MILPStatus.OPTIMAL
        branches = tuple(
            sorted((name, result.value) for name, result in model.branch_numbers.items())
        )
        return ActiveSBoxResult(solved.status.value, value, complete, branches)


__all__ = ["WordwiseActivityAnalysis", "ActiveSBoxResult"]
