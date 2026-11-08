"""Search the legacy continuous ARX differential-correlation heuristic."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite, log2, prod
from subprocess import TimeoutExpired
from types import MappingProxyType

from claasp.analysis.datasets import packed_bit_width
from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.drivers.solvers.minizinc import CPResult, _parse_output
from claasp.representations.constraints.cp.continuous_differential import (
    ContinuousDifferentialCPModel,
)
from claasp.representations.execution import ContinuousXorDifferentialExecutionDriver


@dataclass(frozen=True, slots=True)
class ContinuousCorrelationResult:
    """A checked heuristic correlation and the inputs/mask that produced it.

    Model completion is never a proof of a primitive's cryptographic security.

    EXAMPLES::

        >>> result = ContinuousCorrelationResult({"state": (-1.,)}, (0.5,), 1, True, 'analytic')
        >>> (result.correlation, result.weight, result.claim_kind)
        (0.5, 1.0, 'heuristic')
    """

    inputs: Mapping[str, tuple[float, ...]]
    output_values: tuple[float, ...]
    output_mask: int
    model_complete: bool
    solver: str
    claim_kind: str = "heuristic"

    def __post_init__(self):
        if self.claim_kind != "heuristic":
            raise ValueError("continuous correlations are heuristic, not proof statuses")
        output = tuple(self.output_values)
        if not output or any(not isfinite(value) or abs(value) > 1.0000000001 for value in output):
            raise ValueError("output correlations must be finite values in [-1,1]")
        if (
            not isinstance(self.output_mask, int)
            or isinstance(self.output_mask, bool)
            or not 0 < self.output_mask < 1 << len(output)
        ):
            raise ValueError("output mask must be nonzero and fit the output")
        object.__setattr__(
            self, "output_values", tuple(max(-1.0, min(1.0, value)) for value in output)
        )
        object.__setattr__(
            self,
            "inputs",
            MappingProxyType({name: tuple(values) for name, values in self.inputs.items()}),
        )

    @property
    def correlation(self):
        """Return the model's absolute product over selected output bits."""
        width = len(self.output_values)
        return prod(
            abs(value)
            for bit, value in enumerate(self.output_values)
            if self.output_mask & (1 << (width - 1 - bit))
        )

    @property
    def weight(self):
        """Return -log2 of the heuristic correlation, or infinity for zero."""
        return -log2(self.correlation) if self.correlation else float("inf")

    def to_terminal(self, *, file=None):
        """Report the selected mask, correlation and conditional model completion.

        EXAMPLES::

            >>> from io import StringIO
            >>> stream = StringIO()
            >>> ContinuousCorrelationResult({}, (0.5,), 1, True, 'analytic').to_terminal(file=stream)
            >>> 'heuristic' in stream.getvalue()
            True
        """
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = tuple(
            TableRow.of(name, value)
            for name, value in (
                ("evidence", self.claim_kind),
                ("correlation", self.correlation),
                ("weight", self.weight),
                ("output mask", hex(self.output_mask)),
                ("model complete", self.model_complete),
                ("solver", self.solver),
            )
        )
        print(
            render_terminal_table(
                Table((TableColumn("field", "Field"), TableColumn("value", "Value")), rows)
            ),
            file=file,
        )

    def plot(self, *, show=True, save_to=None):
        """Plot retained evidence without rerunning a solver.

        Signed output correlations and selected mask bits are shown in MSB-first order. These are heuristic values.

        Requires the optional ``presentation`` extra. ``show=False`` suppresses
        display; ``save_to`` writes a file. Returns a ``FigureArtifact`` with
        the figure and plotted numeric series. Empty searches show their status.

        EXAMPLES::

            >>> result = ContinuousCorrelationResult({}, (-0.5, 0.25), 2, False, 'analytic')
            >>> artifact = result.plot(show=False)
            >>> artifact.kind
            'search_evidence'
            >>> import matplotlib.pyplot as plt
            >>> plt.close(artifact.figure)
        """
        from claasp.drivers.renderers._search_results import _plot

        return _plot(self, show=show, save_to=save_to)


class ContinuousDifferentialAnalysis:
    """Evaluate or search the separate legacy continuous differential model.

    Fixed differences use ordinary packed integers. Patterns of 0/1/? allow
    free real correlations at ? positions, as in the legacy model. Such
    problems need an external nonlinear MiniZinc solver, for example Gecode.
    Fully fixed inputs need no solver: the best admissible mask is selected
    analytically and the model is evaluated directly.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> analysis = ContinuousDifferentialAnalysis(Speck(number_of_rounds=1))
        >>> result = analysis.find_best_correlation(1)
        >>> result.correlation >= 0 and result.output_mask != 0
        True
    """

    def __init__(self, primitive):
        self.primitive = primitive

    def model(
        self,
        input_difference=1,
        *,
        input_name=None,
        fixed_inputs=None,
        output_mask=None,
        maximize=True,
    ):
        """Build the continuous CP model, without invoking an optional solver.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> model = ContinuousDifferentialAnalysis(Speck(number_of_rounds=1)).model(1)
            >>> model.output_width
            32
        """
        if input_name is None:
            input_name = next(
                (
                    name
                    for name in self.primitive.graph.input_arrays
                    if name not in self.primitive.graph.secret_inputs
                ),
                None,
            )
        if input_name not in self.primitive.graph.input_arrays:
            raise ValueError("input_name must name a primitive input")
        selected = dict(fixed_inputs or {})
        if set(selected) - set(self.primitive.graph.input_arrays):
            raise ValueError("unknown fixed input")
        if input_name in selected:
            raise ValueError("input_difference and fixed_inputs cannot both specify input_name")
        selected[input_name] = input_difference
        inputs = {
            name: _correlations(selected.get(name, 0), packed_bit_width(self.primitive, name))
            for name in self.primitive.graph.input_arrays
        }
        return ContinuousDifferentialCPModel(
            self.primitive, inputs, output_mask=output_mask, maximize=maximize
        )

    def find_best_correlation(
        self,
        input_difference=1,
        *,
        input_name=None,
        fixed_inputs=None,
        output_mask=None,
        solver=None,
    ):
        """Maximize the heuristic correlation over free inputs and a nonzero mask.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> result = ContinuousDifferentialAnalysis(Speck(number_of_rounds=1)).find_best_correlation(1, output_mask=1)
            >>> result.solver
            'analytic_fixed_inputs'
        """
        model = self.model(
            input_difference,
            input_name=input_name,
            fixed_inputs=fixed_inputs,
            output_mask=output_mask,
        )
        return self._solve(model, solver)

    def find_one_correlation(
        self,
        input_difference=1,
        *,
        input_name=None,
        fixed_inputs=None,
        output_mask=None,
        solver=None,
    ):
        """Find one model witness without requesting a globally best correlation.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> ContinuousDifferentialAnalysis(Speck(number_of_rounds=1)).find_one_correlation(1).output_mask != 0
            True
        """
        model = self.model(
            input_difference,
            input_name=input_name,
            fixed_inputs=fixed_inputs,
            output_mask=output_mask,
            maximize=False,
        )
        return self._solve(model, solver)

    def _solve(self, model, solver):
        fixed = all(value is not None for values in model.inputs.values() for value in values)
        if fixed and solver is None:
            inputs = {
                name: tuple(float(value) for value in values)
                for name, values in model.inputs.items()
            }
            output = (
                ContinuousXorDifferentialExecutionDriver().evaluate(self.primitive, inputs).output
            )
            assert output is not None
            bits = [bool(value) if value is not None else False for value in model.output_mask]
            if not any(bits):
                free = [bit for bit, value in enumerate(model.output_mask) if value is None]
                best = max(free, key=lambda bit: abs(output[bit])) if model.maximize else free[0]
                bits[best] = True
            mask = sum(int(value) << (len(bits) - 1 - bit) for bit, value in enumerate(bits))
            return ContinuousCorrelationResult(inputs, output, mask, True, "analytic_fixed_inputs")
        encoded = model.minizinc_model()
        selected = MiniZincSolver(solver="gecode", timeout_seconds=30) if solver is None else solver
        try:
            solved = selected.solve(encoded)
        except TimeoutExpired as error:
            text = error.stdout or ""
            if isinstance(text, bytes):
                text = text.decode("utf-8")
            if "----------" not in text:
                raise RuntimeError(
                    "continuous search timed out before a complete candidate"
                ) from error
            completed = text.rsplit("----------", 1)[0] + "----------\n=====UNKNOWN====="
            status, values = _parse_output(completed)
            solved = CPResult(
                status,
                values,
                float(error.timeout),
                getattr(selected, "solver", "external"),
                completed,
                "time limit",
            )
        if solved.status is CPStatus.UNSATISFIABLE or solved.values is None:
            raise RuntimeError(
                f"continuous heuristic model has no checked witness: {solved.status.value}"
            )
        values = solved.values
        inputs = {}
        for name, variable in model.input_variables.items():
            observed = _solution_vector(values, variable)
            if len(observed) != len(model.inputs[name]) or any(
                not isfinite(value) or not -1.000001 <= value <= 1.000001 for value in observed
            ):
                raise RuntimeError("continuous solver returned invalid input correlations")
            if any(
                expected is not None and abs(value - expected) > 1e-6
                for value, expected in zip(observed, model.inputs[name])
            ):
                raise RuntimeError("continuous solver violated fixed input correlations")
            inputs[name] = tuple(max(-1.0, min(1.0, value)) for value in observed)
        output = ContinuousXorDifferentialExecutionDriver().evaluate(self.primitive, inputs).output
        assert output is not None
        reported = _solution_vector(values, "output_values")
        if len(output) != len(reported) or any(abs(a - b) > 1e-5 for a, b in zip(output, reported)):
            raise RuntimeError(
                "continuous solver output disagrees with independent graph evaluation"
            )
        selected_bits = _solution_vector(values, "output_mask")
        if (
            len(selected_bits) != model.output_width
            or any(value not in (False, True, 0, 1) for value in selected_bits)
            or not any(selected_bits)
        ):
            raise RuntimeError("continuous solver returned an invalid output mask")
        if any(
            expected is not None and bool(value) != bool(expected)
            for value, expected in zip(selected_bits, model.output_mask)
        ):
            raise RuntimeError("continuous solver violated the fixed output mask")
        mask = sum(
            int(value) << (len(selected_bits) - 1 - bit) for bit, value in enumerate(selected_bits)
        )
        complete = "==========" in solved.stdout and solved.status is not CPStatus.UNKNOWN
        result = ContinuousCorrelationResult(inputs, output, mask, complete, solved.solver)
        if abs(result.correlation - _solution_number(values["correlation"])) > 1e-5:
            raise RuntimeError("continuous solver correlation disagrees with its selected mask")
        return result


def _solution_number(value):
    if not isinstance(value, (int, float)) or not isfinite(value):
        raise RuntimeError("continuous solver returned a non-finite numerical value")
    return float(value)


def _solution_vector(values, name):
    raw = values.get(name)
    if not isinstance(raw, (tuple, list)):
        raise RuntimeError(f"continuous solver omitted its {name} vector")
    return tuple(_solution_number(value) for value in raw)


def _correlations(value, width):
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 <= value < 1 << width:
            raise ValueError("input difference does not fit its input")
        return tuple(float(2 * ((value >> shift) & 1) - 1) for shift in reversed(range(width)))
    if isinstance(value, str):
        if len(value) != width or any(bit not in "01?" for bit in value):
            raise ValueError("input pattern must fit its input and use 0, 1 or ?")
        return tuple(None if bit == "?" else float(2 * int(bit) - 1) for bit in value)
    values = tuple(value)
    if len(values) != width or any(
        item is not None and (not isfinite(item) or not -1 <= item <= 1) for item in values
    ):
        raise ValueError("input correlations must fit their input and lie in [-1,1]")
    return values


__all__ = ["ContinuousCorrelationResult", "ContinuousDifferentialAnalysis"]
