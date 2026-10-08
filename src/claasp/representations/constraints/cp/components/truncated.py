"""Deterministic-truncated CP component encodings."""

from dataclasses import dataclass
from itertools import product

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.semantics.cryptanalysis import (
    SBoxTransitionSemantics,
    TruncatedBit,
    TruncatedXorDifference,
)


class ModularAddDeterministicTruncatedCPModel:
    """Expose the recovered paired-carry modular-add relation in MiniZinc.

    EXAMPLES::

        >>> model = ModularAddDeterministicTruncatedCPModel(4)
        >>> query = model.cp_model(
        ...     left_pattern="0001", right_pattern="0001", output_pattern="???0"
        ... )
        >>> (len(query.declarations), len(query.constraints))
        (32, 71)
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "ModularAddDeterministicTruncatedCPModel",
        "deterministic_truncated_xor",
        "MiniZinc translation of legacy two-bit paired-carry clauses",
        "The recovered Boolean clauses are translated exactly to MiniZinc.",
    )

    def __init__(self, width: int) -> None:
        from claasp.representations.constraints.sat.components.modular_add import (
            ModularAddDeterministicTruncatedSATModel,
        )

        self._sat_model = ModularAddDeterministicTruncatedSATModel(width)
        self.width = self._sat_model.width
        self._query: MiniZincModel | None = None

    def cp_model(self, *, left_pattern=None, right_pattern=None, output_pattern=None):
        """Return paired-carry constraints with optional fixed ternary patterns."""

        from claasp.representations.constraints.sat.model import CNFFormula

        formula = self._sat_model.cnf_formula()
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        clauses = list(formula.clauses)
        provenance = list(formula.provenance)
        for prefix, pattern in (
            ("left", left_pattern),
            ("right", right_pattern),
            ("output", output_pattern),
        ):
            if pattern is None:
                continue
            encoded = self._sat_model.encode_pattern(pattern)
            if len(encoded) != self.width:
                raise ValueError(f"patterns must contain {self.width} bits")
            for bit, pair in enumerate(encoded):
                for field, value in zip(("unknown", "value"), pair):
                    index = indices[f"{prefix}_{bit}_{field}"]
                    clauses.append(((index if value else -index),))
                    provenance.append(f"fixed_{prefix}")
        lowered = BooleanMiniZincLowerer().lower(
            CNFFormula(formula.variables, tuple(clauses), tuple(provenance))
        )
        self._query = MiniZincModel(
            lowered.declarations,
            lowered.constraints,
            lowered.solve,
            lowered.includes,
            lowered.outputs,
            lowered.provenance,
            lowered.name_mapping,
            (ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_transition(self, assignment):
        """Decode and independently validate one CP assignment."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        return self._sat_model.decode_transition(assignment)


@dataclass(frozen=True, slots=True)
class HybridImpossibleBoundaryResult:
    """Decoded bitwise or tagged-word contradiction at one middle boundary.

    EXAMPLES::

        >>> result = HybridImpossibleBoundaryResult((10, 10), (0, 0), (), (0,))
        >>> result.tagged_groups
        (0,)
    """

    forward: tuple[int, ...]
    backward: tuple[int, ...]
    bitwise_positions: tuple[int, ...]
    tagged_groups: tuple[int, ...]


class HybridImpossibleBoundaryCPModel:
    """Recover the legacy hybrid bitwise/tagged-word incompatibility rule.

    Values 0, 1, and 2 mean known zero, known one, and unknown. Positive
    multiples of ten identify all bits activated by the same nonlinear
    component. A boundary contradicts either at a known bit or when one side
    has one uniform nonlinear tag across a reviewed group and the other is
    zero across that group.

    EXAMPLES::

        >>> model = HybridImpossibleBoundaryCPModel(4, ((0, 1, 2, 3),))
        >>> query = model.cp_model(forward=(10, 10, 10, 10), backward=(0, 0, 0, 0))
        >>> (len(query.declarations), query.constraints[-1])
        (6, 'constraint exists(i in 0..4)(contradiction[i]);')
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "HybridImpossibleBoundaryCPModel",
        "hybrid_impossible_xor_differential",
        "legacy bitwise-or-tagged-nonlinear middle incompatibility",
        "Only the reviewed local boundary rule is recovered; complete graph propagation remains separate.",
    )

    def __init__(self, width: int, nonlinear_groups, *, maximum_tag: int = 800) -> None:
        groups = tuple(tuple(group) for group in nonlinear_groups)
        if not isinstance(width, int) or isinstance(width, bool) or width < 1:
            raise ValueError("width must be a positive integer")
        if maximum_tag < 10 or maximum_tag % 10:
            raise ValueError("maximum_tag must be a positive multiple of ten")
        if any(
            not group
            or len(set(group)) != len(group)
            or any(not isinstance(position, int) or not 0 <= position < width for position in group)
            for group in groups
        ):
            raise ValueError("nonlinear groups must contain unique in-range bit positions")
        self.width, self.nonlinear_groups, self.maximum_tag = width, groups, maximum_tag
        self._query: MiniZincModel | None = None

    def _pattern_constraints(self, name, pattern):
        if pattern is None:
            return ()
        if len(pattern) != self.width or any(
            value not in (0, 1, 2) and (value < 10 or value % 10 or value > self.maximum_tag)
            for value in pattern
        ):
            raise ValueError("hybrid patterns contain 0, 1, 2, or configured nonlinear tags")
        return tuple(
            f"constraint {name}[{position}] = {value};" for position, value in enumerate(pattern)
        )

    def cp_model(self, *, forward=None, backward=None):
        """Return the exact local hybrid incompatibility query."""

        group_count = len(self.nonlinear_groups)
        declarations = (
            f"set of int: HybridDomain = 0..2 union {{i | i in 10..{self.maximum_tag} where i mod 10 = 0}};",
            f"array[0..{self.width - 1}] of var HybridDomain: forward;",
            f"array[0..{self.width - 1}] of var HybridDomain: backward;",
            f"array[0..{self.width + group_count - 1}] of var bool: contradiction;",
            f"array[0..{max(group_count - 1, 0)}] of var HybridDomain: forward_group_tag;",
            f"array[0..{max(group_count - 1, 0)}] of var HybridDomain: backward_group_tag;",
        )
        constraints = [*self._pattern_constraints("forward", forward), *self._pattern_constraints("backward", backward)]
        constraints.extend(
            f"constraint contradiction[{position}] <-> (forward[{position}] + backward[{position}] = 1);"
            for position in range(self.width)
        )
        for number, group in enumerate(self.nonlinear_groups):
            positions = " /\\ ".join(
                f"forward[{position}] = forward_group_tag[{number}]" for position in group
            )
            inverse_positions = " /\\ ".join(
                f"backward[{position}] = backward_group_tag[{number}]" for position in group
            )
            backward_zero = " /\\ ".join(f"backward[{position}] = 0" for position in group)
            forward_zero = " /\\ ".join(f"forward[{position}] = 0" for position in group)
            constraints.append(
                f"constraint contradiction[{self.width + number}] <-> "
                f"(((forward_group_tag[{number}] > 2) /\\ {positions} /\\ {backward_zero}) \\/ "
                f"((backward_group_tag[{number}] > 2) /\\ {inverse_positions} /\\ {forward_zero}));"
            )
        constraints.append(
            f"constraint exists(i in 0..{self.width + group_count - 1})(contradiction[i]);"
        )
        self._query = MiniZincModel(
            declarations,
            tuple(constraints),
            provenance=("recovered legacy hybrid middle incompatibility",),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_boundary(self, assignment):
        """Decode and independently validate the selected contradictions."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        forward = tuple(int(value) for value in assignment["forward"])
        backward = tuple(int(value) for value in assignment["backward"])
        bitwise = tuple(
            position for position, values in enumerate(zip(forward, backward)) if sum(values) == 1
        )
        groups = tuple(
            number
            for number, group in enumerate(self.nonlinear_groups)
            if (
                len({forward[position] for position in group}) == 1
                and forward[group[0]] > 2
                and all(backward[position] == 0 for position in group)
            )
            or (
                len({backward[position] for position in group}) == 1
                and backward[group[0]] > 2
                and all(forward[position] == 0 for position in group)
            )
        )
        if not bitwise and not groups:
            raise ValueError("hybrid boundary contains no independently verified contradiction")
        return HybridImpossibleBoundaryResult(forward, backward, bitwise, groups)


class HybridXorCPModel:
    """Recover the legacy tagged deterministic-truncated XOR rule.

    EXAMPLES::

        >>> model = HybridXorCPModel(2)
        >>> query = model.cp_model(left=(10, 0), right=(0, 1), output=(10, 1))
        >>> query.solve
        'solve satisfy;'
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "HybridXorCPModel",
        "hybrid_impossible_xor_differential",
        "legacy tagged deterministic-truncated XOR propagation",
        "Zero preserves a nonlinear tag; other abstract combinations become unknown.",
    )

    def __init__(self, width: int, *, maximum_tag: int = 800) -> None:
        if width < 1 or maximum_tag < 10 or maximum_tag % 10:
            raise ValueError("width must be positive and maximum_tag a positive multiple of ten")
        self.width, self.maximum_tag = width, maximum_tag
        self._query: MiniZincModel | None = None

    @staticmethod
    def propagate(left: int, right: int) -> int:
        """Return the reviewed legacy result for two hybrid symbols."""

        if left < 2 and right < 2:
            return (left + right) % 2
        if right == 0:
            return left
        if left == 0:
            return right
        return 2

    def cp_model(self, *, left=None, right=None, output=None):
        """Return independent per-bit tagged-XOR constraints."""

        domain = f"0..2 union {{i | i in 10..{self.maximum_tag} where i mod 10 = 0}}"
        declarations = (f"set of int: HybridDomain = {domain};",) + tuple(
            f"array[0..{self.width - 1}] of var HybridDomain: {name};"
            for name in ("left", "right", "result")
        )
        constraints: list[str] = []
        for name, pattern in (("left", left), ("right", right), ("result", output)):
            if pattern is not None:
                if len(pattern) != self.width:
                    raise ValueError("hybrid XOR patterns must match the width")
                constraints.extend(
                    f"constraint {name}[{position}] = {value};"
                    for position, value in enumerate(pattern)
                )
        constraints.extend(
            f"constraint if left[{bit}] < 2 /\\ right[{bit}] < 2 then "
            f"result[{bit}] = (left[{bit}] + right[{bit}]) mod 2 "
            f"elseif right[{bit}] = 0 then result[{bit}] = left[{bit}] "
            f"elseif left[{bit}] = 0 then result[{bit}] = right[{bit}] "
            f"else result[{bit}] = 2 endif;"
            for bit in range(self.width)
        )
        self._query = MiniZincModel(
            declarations,
            tuple(constraints),
            provenance=("recovered legacy hybrid XOR propagation",),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_transition(self, assignment):
        """Decode and independently re-evaluate every bit."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        left, right, output = (
            tuple(int(value) for value in assignment[name])
            for name in ("left", "right", "result")
        )
        if tuple(self.propagate(a, b) for a, b in zip(left, right)) != output:
            raise ValueError("hybrid XOR output disagrees with recovered semantics")
        return left, right, output


class HybridSBoxCPModel:
    """Recover the legacy tagged S-box abstraction for one component.

    EXAMPLES::

        >>> from claasp.primitives.block_ciphers.present import PRESENT_SBOX
        >>> model = HybridSBoxCPModel(PRESENT_SBOX, output_tag=10)
        >>> "result[0] = 10" in model.cp_model(input_pattern=(1, 0, 0, 0)).constraints[-1]
        True
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.CP,
        "HybridSBoxCPModel",
        "hybrid_impossible_xor_differential",
        "legacy tagged S-box abstraction with exact undisturbed-bit alternative",
        "Active inputs may emit one component tag or an exact nontrivial ternary propagation.",
    )

    def __init__(self, table, *, output_tag: int, maximum_tag: int = 800) -> None:
        self.semantics = SBoxTransitionSemantics(table)
        if output_tag < 10 or output_tag % 10 or output_tag > maximum_tag:
            raise ValueError("output_tag must be a configured positive multiple of ten")
        self.output_tag, self.maximum_tag = output_tag, maximum_tag
        self._query: MiniZincModel | None = None

    def _exact_cases(self):
        symbols = (TruncatedBit.ZERO, TruncatedBit.ONE, TruncatedBit.UNKNOWN)
        cases = []
        for values in product(symbols, repeat=self.semantics.width):
            source = TruncatedXorDifference(values)
            target = self.semantics.truncated_xor_differential(source)
            encoded = tuple(bit.encoded for bit in target.bits)
            if encoded != (2,) * self.semantics.width:
                cases.append((tuple(bit.encoded for bit in source.bits), encoded))
        return tuple(cases)

    def cp_model(self, *, input_pattern=None, output_pattern=None):
        """Return the tagged S-box relation with optional fixed boundaries."""

        last = self.semantics.width - 1
        declarations = (
            f"set of int: HybridDomain = 0..2 union {{i | i in 10..{self.maximum_tag} where i mod 10 = 0}};",
            f"array[0..{last}] of var HybridDomain: input;",
            f"array[0..{last}] of var HybridDomain: result;",
        )
        constraints: list[str] = []
        for name, pattern in (("input", input_pattern), ("result", output_pattern)):
            if pattern is not None:
                if len(pattern) != self.semantics.width:
                    raise ValueError("hybrid S-box patterns must match the S-box width")
                constraints.extend(
                    f"constraint {name}[{position}] = {value};"
                    for position, value in enumerate(pattern)
                )
        zero = " /\\ ".join(f"input[{bit}] = 0" for bit in range(self.semantics.width))
        zero_output = " /\\ ".join(f"result[{bit}] = 0" for bit in range(self.semantics.width))
        active = " \\/ ".join(f"input[{bit}] = 1" for bit in range(self.semantics.width))
        tagged = " /\\ ".join(f"result[{bit}] = {self.output_tag}" for bit in range(self.semantics.width))
        same_tag = " /\\ ".join(
            [*(f"input[{bit}] > 2" for bit in range(self.semantics.width)), *(f"input[{bit}] = input[0]" for bit in range(1, self.semantics.width))]
        )
        unknown = " /\\ ".join(f"result[{bit}] = 2" for bit in range(self.semantics.width))
        exact = " \\/ ".join(
            "(" + " /\\ ".join(
                [
                    *(f"input[{i}] = {value}" for i, value in enumerate(source)),
                    *(f"result[{i}] = {value}" for i, value in enumerate(target)),
                ]
            ) + ")"
            for source, target in self._exact_cases()
        )
        constraints.append(
            f"constraint if {zero} then {zero_output} elseif ({active}) then (({tagged}) \\/ ({exact})) "
            f"elseif ({same_tag}) then {tagged} else {unknown} endif;"
        )
        self._query = MiniZincModel(
            declarations,
            tuple(constraints),
            provenance=("recovered legacy hybrid S-box propagation",),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._query

    def decode_transition(self, assignment):
        """Decode and independently verify one accepted legacy branch."""

        if self._query is None:
            raise ValueError("build the CP model before decoding")
        source = tuple(int(value) for value in assignment["input"])
        target = tuple(int(value) for value in assignment["result"])
        if all(value == 0 for value in source):
            expected = {(0,) * self.semantics.width}
        elif 1 in source:
            expected = {(self.output_tag,) * self.semantics.width}
            if all(value <= 2 for value in source):
                typed = TruncatedXorDifference(
                    tuple(TruncatedBit.UNKNOWN if value == 2 else TruncatedBit(str(value)) for value in source)
                )
                exact = tuple(bit.encoded for bit in self.semantics.truncated_xor_differential(typed).bits)
                if exact != (2,) * self.semantics.width:
                    expected.add(exact)
        elif all(value > 2 and value == source[0] for value in source):
            expected = {(self.output_tag,) * self.semantics.width}
        else:
            expected = {(2,) * self.semantics.width}
        if target not in expected:
            raise ValueError("hybrid S-box output disagrees with recovered semantics")
        return source, target


__all__ = [
    "HybridImpossibleBoundaryCPModel",
    "HybridImpossibleBoundaryResult",
    "HybridSBoxCPModel",
    "HybridXorCPModel",
    "ModularAddDeterministicTruncatedCPModel",
]
