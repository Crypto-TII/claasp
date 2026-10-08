"""Deterministic-truncated CP component encodings."""

from dataclasses import dataclass

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.cp.lowering import BooleanMiniZincLowerer
from claasp.representations.constraints.cp.model import MiniZincModel


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


__all__ = [
    "HybridImpossibleBoundaryCPModel",
    "HybridImpossibleBoundaryResult",
    "ModularAddDeterministicTruncatedCPModel",
]
