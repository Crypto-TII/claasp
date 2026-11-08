"""General circle characteristic search using the ordinary XOR solver engine."""

from dataclasses import dataclass

from claasp.analysis._circle_coordinates import CircleCoordinateGraph, circle_coordinate_graph
from claasp.semantics.cryptanalysis import TrailKind, TrailSearchResult


@dataclass(frozen=True)
class CircleTrailSearchResult:
    """A solver optimum in a retained, explicitly conjugated component graph.

    Internal patterns refer to ``coordinates.primitive``. Endpoint linear
    patterns are circle character labels; differential patterns are converted
    back to original packed circle differences. The component probability or
    correlation product is not a measured endpoint probability or correlation.
    All auxiliary inputs, including keys, have explicit concrete values.

    EXAMPLES::

        >>> result = _example_result()
        >>> result.input_pattern, result.output_pattern, result.weight
        (1, 1, 0.0)
        >>> result.is_optimal
        True
    """

    coordinates: CircleCoordinateGraph
    search_result: TrailSearchResult

    @property
    def input_pattern(self):
        """Return the circle input difference or character label.

        EXAMPLES::

            >>> _example_result().input_pattern
            1
        """
        value = self.search_result.trail.input_pattern.value
        if self.search_result.trail.kind is TrailKind.XOR_DIFFERENTIAL:
            return self.coordinates.input_basis.theta(value)
        return value

    @property
    def output_pattern(self):
        """Return the circle output difference or character label.

        EXAMPLES::

            >>> _example_result().output_pattern
            1
        """
        value = self.search_result.trail.output_pattern.value
        if self.search_result.trail.kind is TrailKind.XOR_DIFFERENTIAL:
            return self.coordinates.output_basis.theta(value)
        return value

    @property
    def weight(self):
        """Return minus log2 of the probability or absolute correlation product.

        EXAMPLES::

            >>> _example_result().weight
            0.0
        """
        return self.search_result.trail.total_weight

    @property
    def is_optimal(self):
        """Return whether the solver proved optimality within the derived graph.

        EXAMPLES::

            >>> _example_result().is_optimal
            True
        """
        return self.search_result.is_optimal

    @property
    def scope(self):
        """State the optimization domain without claiming endpoint optimality.

        EXAMPLES::

            >>> 'component graph' in _example_result().scope
            True
        """
        return "fixed-input characteristic in the circle-coordinate component graph"

    def to_terminal(self, *, details=False, file=None):
        """Use the shared trail presentation and identify the coordinate graph.

        EXAMPLES::

            >>> from io import StringIO
            >>> output = StringIO()
            >>> _example_result().to_terminal(file=output)
            >>> 'Proved optimal' in output.getvalue()
            True
        """
        print(f"Circle trail search: {self.scope}", file=file)
        print(f"Circle endpoints: {self.input_pattern:#x} -> {self.output_pattern:#x}", file=file)
        print(f"Fixed inputs: {dict(self.coordinates.fixed_inputs)}", file=file)
        self.search_result.to_terminal(details=details, file=file)

    def plot(self, *, show=True, save_to=None):
        """Plot component contributions with the shared XOR trail renderer.

        EXAMPLES::

            >>> callable(_example_result().plot)
            True
        """
        from claasp.drivers.renderers.presentation import _plot_trail

        kind = (
            "differential"
            if self.search_result.trail.kind is TrailKind.XOR_DIFFERENTIAL
            else "linear"
        )
        return _plot_trail(
            self.search_result,
            show=show,
            save_to=save_to,
            title=f"Circle {kind} characteristic weight (coordinate graph)",
        )

    def evaluate_endpoint(self, *, maximum_inputs=1 << 16, samples=None, seed=0):
        """Measure the selected endpoints on the original primitive.

        With ``samples=None`` enumerate the complete varying-input domain,
        respecting ``maximum_inputs``. Otherwise use fresh uniform samples
        and the existing confidence intervals. This checks the full endpoint
        event, including all internal trails, at the retained fixed key.
        Linear exact evaluation returns a signed Fraction; sampled linear
        evaluation and both differential modes retain their evidence objects.

        EXAMPLES::

            >>> result = _example_result()
            >>> result.evaluate_endpoint().probability
            Fraction(1, 1)
            >>> result.evaluate_endpoint(samples=32, seed=7).complete
            False
        """
        graph = self.coordinates
        options = dict(
            input_name=graph.input_name,
            input_basis=graph.input_basis,
            output_basis=graph.output_basis,
        )
        fixed = dict(graph.fixed_inputs)
        differential = self.search_result.trail.kind is TrailKind.XOR_DIFFERENTIAL
        analysis = (
            graph.source.analysis.circle_differential(**options)
            if differential
            else graph.source.analysis.circle_linear(**options)
        )
        if samples is not None:
            method = (
                analysis.estimate_probability if differential else analysis.estimate_correlation
            )
            return method(
                self.input_pattern,
                self.output_pattern,
                fixed_inputs=fixed,
                samples=samples,
                seed=seed,
            )
        method = analysis.probability if differential else analysis.correlation
        return method(
            self.input_pattern,
            self.output_pattern,
            fixed_inputs=fixed,
            maximum_inputs=maximum_inputs,
        )


def find_circle_characteristic(
    primitive,
    kind,
    *,
    bibrace=None,
    input_basis=None,
    output_basis=None,
    input_name="plaintext",
    fixed_inputs=None,
    input_pattern=None,
    output_pattern=None,
    backend="sat",
    solver=None,
):
    """Optimize a general circle characteristic with existing solver rules.

    Unlike the specialized perfect-subgroup SPN search this does not assume
    uniform rounds, cell diffusion or an affine key schedule. Non-perfect S-box
    transitions are included. Backend capability checks remain those of XOR
    search; unsupported components are reported explicitly.

    EXAMPLES::

        >>> from claasp.primitives import BitVectorSBox
        >>> from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace
        >>> p = BitVectorSBox(4, tuple(range(16)))
        >>> result = find_circle_characteristic(p, TrailKind.XOR_DIFFERENTIAL,
        ...     bibrace=BinaryBibrace(4), input_name='input', input_pattern=1)
        >>> result.input_pattern, result.output_pattern, result.weight, result.is_optimal
        (1, 1, 0.0, True)
    """
    if kind not in (TrailKind.XOR_LINEAR, TrailKind.XOR_DIFFERENTIAL):
        raise ValueError("circle characteristic kind must be XOR_LINEAR or XOR_DIFFERENTIAL")
    graph = circle_coordinate_graph(
        primitive,
        bibrace=bibrace,
        input_basis=input_basis,
        output_basis=output_basis,
        input_name=input_name,
        fixed_inputs=fixed_inputs,
    )
    options = {}
    if input_pattern is not None:
        value = input_pattern
        if kind is TrailKind.XOR_DIFFERENTIAL:
            value = graph.input_basis.theta(value)
        options[
            "fixed_input_differences" if kind is TrailKind.XOR_DIFFERENTIAL else "fixed_input_masks"
        ] = {input_name: value}
    if output_pattern is not None:
        if kind is not TrailKind.XOR_DIFFERENTIAL:
            raise ValueError("an output_pattern constraint currently requires differential search")
        from claasp.analysis.trail_search import optimize_word_characteristic

        result = optimize_word_characteristic(
            graph.primitive,
            kind,
            backend=backend,
            solver=solver,
            nonzero_input=input_name,
            output_difference=graph.output_basis.theta(output_pattern),
            **options,
        )
    else:
        result = graph.primitive.analysis.find_optimal_trail(
            kind,
            backend=backend,
            solver=solver,
            nonzero_input=input_name,
            **options,
        )
    return CircleTrailSearchResult(graph, result)


def _example_result():
    from claasp.primitives import BitVectorSBox

    return find_circle_characteristic(
        BitVectorSBox(2, (0, 1, 2, 3)),
        TrailKind.XOR_DIFFERENTIAL,
        input_name="input",
        input_pattern=1,
    )


__all__ = ["CircleTrailSearchResult", "find_circle_characteristic"]
