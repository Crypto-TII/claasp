"""CP encoding of local modular-addition transition relations."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _unaudited_model,
)
from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.semantics.cryptanalysis import (
    ModularAddBoomerangAutomaton,
    ProbabilisticTruncatedModularAddTransition,
    TruncatedXorDifference,
    check_probabilistic_truncated_modular_add,
)


class ModularAddBoomerangCPModel:
    """Exact feasibility automaton for one modular-add boomerang switch.

    EXAMPLES::

        >>> model = ModularAddBoomerangCPModel(
        ...     4, delta_left=1, delta_right=0,
        ...     nabla_output=1, nabla_right=0,
        ... )
        >>> query = model.cp_model()
        >>> (len(query.declarations), query.includes)
        (7, ('include "table.mzn";',))
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "ModularAddBoomerangCPModel",
        "boomerang",
        "exact carry/borrow-state feasibility automaton for modular addition",
        "The automaton is verified against exhaustive quartet counting without a literature claim.",
    )

    def __init__(
        self,
        width: int,
        *,
        delta_left=None,
        delta_right=None,
        nabla_output=None,
        nabla_right=None,
    ) -> None:
        if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 64:
            raise ValueError("width must be an integer from 1 through 64")
        self.width = width
        self.boundaries = (delta_left, delta_right, nabla_output, nabla_right)
        for name, value in zip(
            ("delta_left", "delta_right", "nabla_output", "nabla_right"),
            self.boundaries,
        ):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width
            ):
                raise ValueError(f"{name} must fit the word width")
        self._query: MiniZincModel | None = None

    @staticmethod
    def _transition_rows():
        rows = set()
        for state in range(16):
            carry = (state >> 3) & 1
            paired_carry = (state >> 2) & 1
            borrow = (state >> 1) & 1
            paired_borrow = state & 1
            for delta_left in (0, 1):
                for delta_right in (0, 1):
                    for nabla_output in (0, 1):
                        for nabla_right in (0, 1):
                            for left in (0, 1):
                                for right in (0, 1):
                                    top = left + right + carry
                                    paired_top = (
                                        (left ^ delta_left) + (right ^ delta_right) + paired_carry
                                    )
                                    lower = (
                                        ((top & 1) ^ nabla_output) - (right ^ nabla_right) - borrow
                                    )
                                    paired_lower = (
                                        ((paired_top & 1) ^ nabla_output)
                                        - ((right ^ delta_right) ^ nabla_right)
                                        - paired_borrow
                                    )
                                    if ((lower & 1) ^ (paired_lower & 1)) != delta_left:
                                        continue
                                    following = (
                                        ((top >> 1) << 3)
                                        | ((paired_top >> 1) << 2)
                                        | (int(lower < 0) << 1)
                                        | int(paired_lower < 0)
                                    )
                                    rows.add(
                                        (
                                            delta_left,
                                            delta_right,
                                            nabla_output,
                                            nabla_right,
                                            state,
                                            following,
                                        )
                                    )
        return tuple(sorted(rows))

    def cp_model(self) -> MiniZincModel:
        """Return an exact switch-feasibility query with optional boundaries."""

        rows = self._transition_rows()
        flattened = ", ".join(str(value) for row in rows for value in row)
        last = self.width - 1
        declarations = (
            f"array[0..{last}] of var 0..1: delta_left;",
            f"array[0..{last}] of var 0..1: delta_right;",
            f"array[0..{last}] of var 0..1: nabla_output;",
            f"array[0..{last}] of var 0..1: nabla_right;",
            f"array[0..{self.width}] of var 0..15: state;",
            f"array[0..{len(rows) - 1}, 1..6] of int: transitions = "
            f"array2d(0..{len(rows) - 1}, 1..6, [{flattened}]);",
            "var bool: switch_possible;",
        )
        constraints = ["constraint state[0] = 0;", "constraint switch_possible;"]
        constraints.extend(
            "constraint table([delta_left[{0}], delta_right[{0}], nabla_output[{0}], "
            "nabla_right[{0}], state[{0}], state[{1}]], transitions);".format(bit, bit + 1)
            for bit in range(self.width)
        )
        for array, value in zip(
            ("delta_left", "delta_right", "nabla_output", "nabla_right"),
            self.boundaries,
        ):
            if value is not None:
                constraints.extend(
                    f"constraint {array}[{bit}] = {(value >> bit) & 1};"
                    for bit in range(self.width)
                )
        self._query = MiniZincModel(
            declarations,
            tuple(constraints),
            includes=('include "table.mzn";',),
            provenance=("exact modular-add boomerang feasibility automaton",),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_connectivity(self, assignment):
        """Decode fixed or selected differences and independently count quartets."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")

        def integer(name):
            return sum(int(value) << bit for bit, value in enumerate(assignment[name]))

        values = tuple(
            integer(name) for name in ("delta_left", "delta_right", "nabla_output", "nabla_right")
        )
        connectivity = ModularAddBoomerangAutomaton(self.width).connectivity(*values)
        if not connectivity.is_possible:
            raise ValueError("MiniZinc returned an impossible modular-add switch")
        return connectivity


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

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "ProbabilisticTruncatedModularAddCPModel",
        "probabilistic_truncated_xor",
        "counter-based partial-addition relation",
        "The exact correspondence with a primary-source construction has not been audited.",
    )

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
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
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
