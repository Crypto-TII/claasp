"""Explicit exact-prefix / sound-truncated-suffix differential composition."""

from dataclasses import dataclass

from claasp.drivers.solvers import CPStatus
from claasp.representations.constraints.cp import SpeckDifferentialCPModel
from claasp.semantics import XOR_DIFFERENTIAL
from claasp.semantics.cryptanalysis import (
    ModularAddTransitionSemantics,
    PropagationProblem,
    Trail,
    TrailKind,
    TruncatedXorDifference,
    propagate_two_word_speck_round,
)


@dataclass(frozen=True, slots=True)
class HybridDifferentialResult:
    """A feasible exact prefix followed by sound, non-weighted abstractions.

    Unknown suffix bits are not feasible exact witnesses and suffixes carry
    neither exact probabilities nor optimization claims.


    EXAMPLES::

        >>> from dataclasses import fields
        >>> (HybridDifferentialResult.__dataclass_params__.frozen, tuple(field.name for field in fields(HybridDifferentialResult)))
        (True, ('exact_prefix', 'truncated_boundaries', 'runtime_seconds'))
    """

    exact_prefix: Trail
    truncated_boundaries: tuple[TruncatedXorDifference, ...]
    runtime_seconds: float


class SpeckHybridDifferentialProblem:
    """Select an exact data-path prefix followed by truncated round semantics.

    EXAMPLES::

        >>> try:
        ...     SpeckHybridDifferentialProblem()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive, *, exact_rounds, input_difference, maximum_prefix_weight=45):
        if (
            not isinstance(exact_rounds, int)
            or isinstance(exact_rounds, bool)
            or not 1 <= exact_rounds < len(primitive.rounds)
        ):
            raise ValueError("exact_rounds must leave a nonempty truncated suffix")
        self.primitive = primitive
        self.exact_rounds = exact_rounds
        self.prefix_model = SpeckDifferentialCPModel(
            PropagationProblem(
                primitive,
                XOR_DIFFERENTIAL,
                maximum_weight=maximum_prefix_weight,
                provenance=("explicit exact/truncated Speck semantic composition",),
            ),
            input_difference=input_difference,
            round_count=exact_rounds,
        )

    def solve(self, solver):
        """Execute only the exact search; suffix propagation stays solver-independent."""
        solved = solver.solve(self.prefix_model.cp_model())
        if solved.status is CPStatus.UNSATISFIABLE:
            return None
        if solved.status is not CPStatus.SATISFIED:
            raise RuntimeError("exact hybrid prefix did not complete with a feasible result")
        prefix = self.prefix_model.decode_trail(solved.assignment)
        boundaries = [TruncatedXorDifference.parse(f"{prefix.output_pattern.value:032b}")]
        for round_number in range(self.exact_rounds, len(self.primitive.rounds)):
            boundaries.append(
                propagate_two_word_speck_round(self.primitive, boundaries[-1], round_number)
            )
        result = HybridDifferentialResult(prefix, tuple(boundaries), solved.runtime_seconds)
        if not self.check(result):
            raise ValueError("invalid exact/truncated composition")
        return result

    def check(self, result):
        """Independently recount exact transitions and check every abstraction boundary."""
        prefix = result.exact_prefix
        if (
            prefix.kind is not TrailKind.XOR_DIFFERENTIAL
            or len(prefix.steps) != self.exact_rounds
            or prefix.input_pattern.value != self.prefix_model.input_difference
            or prefix.total_weight > self.prefix_model.problem.maximum_weight
        ):
            return False
        left, right = divmod(prefix.input_pattern.value, 1 << 16)
        semantics = ModularAddTransitionSemantics(16)
        for r, step in enumerate(prefix.steps):
            operations = self.primitive.round_operations[r]
            alpha = operations["rotate_right"].amount
            beta = operations["rotate_left"].amount
            rotated_left = ((left >> alpha) | (left << (16 - alpha))) & 0xFFFF
            if (
                step.component_id != operations["modular_add"].component_id
                or not semantics.check(step.transition)
                or step.transition.input_pattern.value != (rotated_left << 16) | right
            ):
                return False
            left = step.transition.output_pattern.value
            right = (((right << beta) | (right >> (16 - beta))) & 0xFFFF) ^ left
        if prefix.output_pattern.value != (left << 16) | right:
            return False
        expected = [TruncatedXorDifference.parse(f"{prefix.output_pattern.value:032b}")]
        for r in range(self.exact_rounds, len(self.primitive.rounds)):
            expected.append(propagate_two_word_speck_round(self.primitive, expected[-1], r))
        return result.truncated_boundaries == tuple(expected)
