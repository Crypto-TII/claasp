"""CP encoding of local modular-addition transition relations."""

from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.semantics.cryptanalysis import (
    ProbabilisticTruncatedModularAddTransition,
    TruncatedXorDifference,
    check_probabilistic_truncated_modular_add,
)


class ProbabilisticTruncatedModularAddCPModel:
    """Native CP representation of one counter-based partial addition.

    EXAMPLES::

        >>> left = TruncatedXorDifference.parse("0000")
        >>> right = TruncatedXorDifference.parse("0001")
        >>> output = TruncatedXorDifference.parse("000?")
        >>> model = ProbabilisticTruncatedModularAddCPModel(left, right, output)
        >>> query = model.cp_model()
        >>> "counter_based_probabilistic_truncated_modadd" in query.source()
        True
        >>> query.solve
        'solve minimize scaled_weight;'
    """

    def __init__(
        self,
        left: TruncatedXorDifference,
        right: TruncatedXorDifference,
        output: TruncatedXorDifference,
        carry_difference: TruncatedXorDifference | None = None,
    ) -> None:
        if not all(isinstance(item, TruncatedXorDifference) for item in (left, right, output)):
            raise TypeError("left, right, and output must be truncated differences")
        width = len(left.bits)
        if len(right.bits) != width or len(output.bits) != width:
            raise ValueError("probabilistic truncated operands must have equal widths")
        if carry_difference is not None and len(carry_difference.bits) != width:
            raise ValueError("carry difference must have the operand width")
        self.left = left
        self.right = right
        self.output = output
        self.carry_difference = carry_difference
        self.width = width

    def cp_model(self) -> MiniZincModel:
        """Fix the boundary patterns and minimize the legacy scaled cost."""

        last = self.width - 1
        declarations = (
            _PROBABILISTIC_TRUNCATED_MODADD_PREDICATE,
            f"array[0..{last}] of var 0..2: left;",
            f"array[0..{last}] of var 0..2: right;",
            f"array[0..{last}] of var 0..2: output_difference;",
            f"array[0..{last}] of var 0..2: carry_difference;",
            f"array[0..{last}] of var {{0,4,9,19,41,100}}: costs;",
            "var int: scaled_weight;",
        )
        constraints = [
            _fixed_array("left", self.left),
            _fixed_array("right", self.right),
            _fixed_array("output_difference", self.output),
        ]
        if self.carry_difference is not None:
            constraints.append(_fixed_array("carry_difference", self.carry_difference))
        constraints.extend(
            (
                "constraint counter_based_probabilistic_truncated_modadd(left, right, "
                "output_difference, carry_difference, costs, scaled_weight);",
                "constraint costs[" + str(last) + "] = 0;",
            )
        )
        return MiniZincModel(
            declarations,
            tuple(constraints),
            solve="solve minimize scaled_weight;",
            provenance=("legacy counter_based_modadd_semideterministic fixture",),
        )

    def decode_transition(self, assignment) -> ProbabilisticTruncatedModularAddTransition:
        """Project and independently check the optimized partial transition."""

        transition = ProbabilisticTruncatedModularAddTransition(
            self.left,
            self.right,
            self.output,
            _decode_truncated(assignment["carry_difference"]),
            tuple(int(value) for value in assignment["costs"]),
        )
        if transition.scaled_weight != int(assignment["scaled_weight"]):
            raise ValueError("MiniZinc returned an inconsistent scaled weight")
        if not check_probabilistic_truncated_modular_add(transition):
            raise ValueError("MiniZinc returned an invalid probabilistic truncated transition")
        return transition


def _fixed_array(name, pattern):
    return (
        "constraint "
        + " /\\ ".join(f"{name}[{index}] = {bit.encoded}" for index, bit in enumerate(pattern.bits))
        + ";"
    )


def _decode_truncated(values):
    symbols = {0: "0", 1: "1", 2: "?"}
    return TruncatedXorDifference.parse("".join(symbols[int(value)] for value in values))


_PROBABILISTIC_TRUNCATED_MODADD_PREDICATE = r"""
function var 0..2: truncated_xor2(var 0..2: a, var 0..2: b) =
    if a < 2 /\ b < 2 then (a + b) mod 2 else 2 endif;

function array[int] of var 0..2: truncated_xor3(
    array[int] of var 0..2: a,
    array[int] of var 0..2: b,
    array[int] of var 0..2: carry
) = array1d(index_set(a), [
    if a[j] < 2 /\ b[j] < 2 /\ carry[j] < 2
    then (a[j] + b[j] + carry[j]) mod 2 else 2 endif
    | j in index_set(a)
]);

predicate counter_based_probabilistic_truncated_modadd(
    array[int] of var 0..2: a,
    array[int] of var 0..2: b,
    array[int] of var 0..2: c,
    array[int] of var 0..2: carry,
    array[int] of var {0,4,9,19,41,100}: costs,
    var int: probability
) = let {
    int: n = length(a),
    array[0..n-1] of var 0..n: run_length
} in
    c = truncated_xor3(a, b, carry) /\
    carry[n-1] = 0 /\ run_length[n-1] = 0 /\
    forall(i in 0..n-2)(
        run_length[i] = if a[i+1] + b[i+1] = 0 /\ carry[i+1] = 2
                        then run_length[i+1] + 1 else 0 endif
    ) /\
    forall(i in 0..n-2)(
        if a[i+1] = 0 /\ b[i+1] = 0 /\ c[i+1] = 0 then
            carry[i] = 0 /\ costs[i] = 0
        elseif a[i+1] = 1 /\ b[i+1] = 1 /\ c[i+1] = 1 then
            carry[i] = 1 /\ costs[i] = 0
        else
            (carry[i] = 2 /\ costs[i] = 0) \/
            (run_length[i] = 0 /\ costs[i] = 100 /\ (carry[i] = 0 \/ carry[i] = 1)) \/
            (run_length[i] = 1 /\ costs[i] = 41 /\ carry[i] = 0) \/
            (run_length[i] = 2 /\ costs[i] = 19 /\ carry[i] = 0) \/
            (run_length[i] = 3 /\ costs[i] = 9 /\ carry[i] = 0) \/
            (run_length[i] = 4 /\ costs[i] = 4 /\ carry[i] = 0) \/
            (run_length[i] > 4 /\ costs[i] = 0 /\ carry[i] = 0)
        endif
    ) /\ probability = sum(costs);
""".strip()
