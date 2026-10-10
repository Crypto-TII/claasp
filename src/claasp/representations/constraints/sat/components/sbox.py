"""Functional SAT encoding for bit-vector S-boxes."""

from typing import ClassVar

from claasp.components import BitVectorSBox
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.sat.model import CNFFormula
from claasp.semantics.cryptanalysis import SBoxTransitionSemantics, TrailKind


class SBoxFunctionalSATModel:
    """Encode the exact input/output function of one bit-vector S-box.

    EXAMPLES::

        >>> from claasp.components import BitVectorSBox
        >>> from claasp.primitives import Present80
        >>> from claasp.representations.constraints.sat import BooleanCNFModel
        >>> primitive = Present80(number_of_rounds=1)
        >>> component = next(item for item in primitive.graph.components if isinstance(item, BitVectorSBox))
        >>> encoding = SBoxFunctionalSATModel(component)
        >>> formula = BooleanCNFModel(primitive).cnf_formula()
        >>> encoding.component.component_id in formula.provenance
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.SAT,
        "SBoxFunctionalSATModel",
        "functional",
        "exhaustive truth-table implication clauses",
        "The clauses are generated exhaustively from the supplied lookup table.",
    )

    def __init__(self, component) -> None:
        if not isinstance(component, BitVectorSBox):
            raise TypeError("component must be a BitVectorSBox")
        self.component = component

    def encode(self, context, outputs, selected) -> None:
        """Append the component's functional clauses to ``context``."""

        component = self.component
        label = component.component_id
        inputs = [group[0] for group in selected[0]]
        output_bits = [group[0] for group in outputs]
        input_width = len(inputs)
        output_width = len(output_bits)
        for input_value, output_value in enumerate(component.table):
            antecedent = tuple(
                -context.indices[name]
                if (input_value >> (input_width - 1 - i)) & 1
                else context.indices[name]
                for i, name in enumerate(inputs)
            )
            for i, output in enumerate(output_bits):
                expected = (output_value >> (output_width - 1 - i)) & 1
                literal = context.indices[output] if expected else -context.indices[output]
                context.add_clause(antecedent + (literal,), label)


class SBoxTransitionSATModel:
    """Encode exact S-box differential or linear support as CNF.

    Prefer the explicitly named differential and linear subclasses in new
    code.

    EXAMPLES::

        >>> model = SBoxTransitionSATModel((0, 1), TrailKind.XOR_DIFFERENTIAL)
        >>> formula = model.cnf_formula(input_pattern=1, output_pattern=1)
        >>> (formula.variables, formula.clause_count)
        (('input_0', 'output_0'), 4)
    """

    model_provenance_by_kind: ClassVar = {
        TrailKind.XOR_DIFFERENTIAL: _direct_model(
            ConstraintBackend.SAT,
            "SBoxXorDifferentialSATModel",
            "xor_differential",
            "exhaustive DDT forbidden assignments",
            "Support and weights are enumerated directly from the supplied S-box table.",
        ),
        TrailKind.XOR_LINEAR: _direct_model(
            ConstraintBackend.SAT,
            "SBoxXorLinearSATModel",
            "xor_linear",
            "exhaustive LAT forbidden assignments",
            "Support, weights, and signs are enumerated directly from the supplied S-box table.",
        ),
    }

    def __init__(self, table: tuple[int, ...] | list[int], kind: TrailKind) -> None:
        if kind not in (TrailKind.XOR_DIFFERENTIAL, TrailKind.XOR_LINEAR):
            raise ValueError("S-box SAT model requires differential or linear semantics")
        self.semantics = SBoxTransitionSemantics(table)
        self.kind = kind
        self.model_provenance = self.model_provenance_by_kind[kind]

    def cnf_formula(
        self, *, input_pattern: int | None = None, output_pattern: int | None = None
    ) -> CNFFormula:
        """Return exact transition support with optional fixed patterns."""

        width = self.semantics.width
        variables = tuple(f"input_{bit}" for bit in range(width)) + tuple(
            f"output_{bit}" for bit in range(width)
        )
        clauses = []
        provenance = []
        for source in range(1 << width):
            for target in range(1 << width):
                transition = self._transition(source, target)
                if transition.is_possible:
                    continue
                assignment = _bits(source, width) + _bits(target, width)
                clauses.append(
                    tuple(
                        -(position + 1) if value else position + 1
                        for position, value in enumerate(assignment)
                    )
                )
                provenance.append(f"{self.kind.value}_support")
        for prefix, value, offset in (
            ("input", input_pattern, 0),
            ("output", output_pattern, width),
        ):
            if value is None:
                continue
            self.semantics._validate_pattern(value)
            for bit, encoded in enumerate(_bits(value, width)):
                variable = offset + bit + 1
                clauses.append((variable if encoded else -variable,))
                provenance.append(f"fixed_{prefix}")
        return CNFFormula(
            variables,
            tuple(clauses),
            tuple(provenance),
            (ConstraintModelApplication(self.model_provenance),),
        )

    def decode_transition(self, assignment):
        """Validate and decode one complete SAT assignment."""

        formula = self.cnf_formula()
        if not formula.is_satisfied(assignment):
            raise ValueError("invalid S-box SAT witness")
        width = self.semantics.width
        source = _integer(tuple(assignment[f"input_{bit}"] for bit in range(width)))
        target = _integer(tuple(assignment[f"output_{bit}"] for bit in range(width)))
        transition = self._transition(source, target)
        if not transition.is_possible:
            raise ValueError("S-box SAT assignment encodes an impossible transition")
        return transition

    def _transition(self, source: int, target: int):
        return (
            self.semantics.xor_differential(source, target)
            if self.kind is TrailKind.XOR_DIFFERENTIAL
            else self.semantics.xor_linear(source, target)
        )


class SBoxXorDifferentialSATModel(SBoxTransitionSATModel):
    """Encode an exact S-box XOR-differential support relation.

    EXAMPLES::

        >>> model = SBoxXorDifferentialSATModel((0, 2, 3, 1))
        >>> transition = model.decode_transition(
        ...     {"input_0": 0, "input_1": 1, "output_0": 1, "output_1": 0}
        ... )
        >>> (transition.numerator, transition.denominator)
        (4, 4)
    """

    model_provenance = SBoxTransitionSATModel.model_provenance_by_kind[TrailKind.XOR_DIFFERENTIAL]

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        super().__init__(table, TrailKind.XOR_DIFFERENTIAL)
        self.model_provenance = type(self).model_provenance


class SBoxXorLinearSATModel(SBoxTransitionSATModel):
    """Encode an exact S-box XOR-linear support relation.

    EXAMPLES::

        >>> model = SBoxXorLinearSATModel((0, 1))
        >>> model.decode_transition({"input_0": 1, "output_0": 1}).sign
        1
    """

    model_provenance = SBoxTransitionSATModel.model_provenance_by_kind[TrailKind.XOR_LINEAR]

    def __init__(self, table: tuple[int, ...] | list[int]) -> None:
        super().__init__(table, TrailKind.XOR_LINEAR)
        self.model_provenance = type(self).model_provenance


def _bits(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> (width - 1 - bit)) & 1 for bit in range(width))


def _integer(bits: tuple[int, ...]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


__all__ = [
    "SBoxFunctionalSATModel",
    "SBoxTransitionSATModel",
    "SBoxXorDifferentialSATModel",
    "SBoxXorLinearSATModel",
]
