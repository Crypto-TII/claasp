"""Explicit inverse semantics for typed components."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from math import gcd
from types import MappingProxyType

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    FeedbackRegister,
    IDEAMultiply,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.domains import BinaryExtensionField, Bit, PrimeField
from claasp.graph import Component, PortLike, Selection, as_selection
from claasp.transformations.contracts import (
    TransformationError,
    TransformationFailureReason,
)
from claasp.utils import binary_field_multiply

InverseFactory = Callable[[Component, Selection, tuple[Selection, ...], int], Component]


@dataclass(frozen=True, slots=True)
class ComponentInverseSemantics:
    """One component family's explicit recovery contract.

    EXAMPLES::

        >>> from claasp.components import Rotate
        >>> from claasp.transformations import DEFAULT_INVERSE_REGISTRY
        >>> DEFAULT_INVERSE_REGISTRY.semantics[Rotate].supported
        True
    """

    component_type: type[Component]
    factory: InverseFactory | None
    failure_reason: TransformationFailureReason | None = None
    rationale: str = ""

    @property
    def supported(self) -> bool:
        """Return whether the semantics has a graph-native inverse factory."""

        return self.factory is not None


@dataclass(frozen=True, slots=True, init=False)
class ComponentInverseRegistry:
    """Immutable exact-type registry of component inverse semantics.

    Extensions construct a new registry instead of mutating process-global
    state.  A recovery names the predecessor to recover and supplies every
    other predecessor as an auxiliary value.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Word
        >>> from claasp.components import Rotate
        >>> graph = Primitive("rule", {"x": ArrayType(Word(8), (1,)), "y": ArrayType(Word(8), (1,))})
        >>> component = Rotate(graph.graph.input("x"), 3, "left")
        >>> inverse = DEFAULT_INVERSE_REGISTRY.invert(component, graph.graph.input("y"), recover_input=0)
        >>> (type(inverse).__name__, inverse.amount, inverse.direction)
        ('Rotate', 3, 'right')
    """

    _semantics: Mapping[type[Component], ComponentInverseSemantics]

    def __init__(self, semantics: Sequence[ComponentInverseSemantics]) -> None:
        records = tuple(semantics)
        if any(not isinstance(item, ComponentInverseSemantics) for item in records):
            raise TypeError("inverse semantics must be ComponentInverseSemantics records")
        types = tuple(item.component_type for item in records)
        if len(set(types)) != len(types):
            raise ValueError("component inverse semantics must have unique component types")
        object.__setattr__(
            self,
            "_semantics",
            MappingProxyType({item.component_type: item for item in records}),
        )

    @property
    def semantics(self) -> Mapping[type[Component], ComponentInverseSemantics]:
        """Return the immutable exact-type semantics map."""

        return self._semantics

    def with_semantics(self, *semantics: ComponentInverseSemantics) -> "ComponentInverseRegistry":
        """Return a registry with explicitly replaced or added semantics."""

        combined = dict(self._semantics)
        combined.update((item.component_type, item) for item in semantics)
        return ComponentInverseRegistry(tuple(combined.values()))

    def invert(
        self,
        component: Component,
        output: PortLike,
        *,
        recover_input: int | None = None,
        auxiliary_inputs: Mapping[int, PortLike] | None = None,
    ) -> Component:
        """Build a component recovering one input from an output and auxiliaries.

        ``auxiliary_inputs`` is keyed by the original zero-based component
        input index.  The returned component has no identifier; its destination
        graph assigns one.
        """

        if not isinstance(component, Component):
            raise TypeError("component must be a Component")
        output_selection = as_selection(output)
        if output_selection.array_type != component.output_type:
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "inverse output type does not match the component output",
                source_ids=_source_ids(component, output_selection),
            )
        supplied = dict(auxiliary_inputs or {})
        if any(not isinstance(index, int) or isinstance(index, bool) for index in supplied):
            raise TypeError("auxiliary input indices must be integers")
        invalid = tuple(
            str(index) for index in supplied if index not in range(len(component.inputs))
        )
        if invalid:
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "auxiliary input index is outside the component input range",
                source_ids=invalid,
            )
        if recover_input is None:
            missing = tuple(
                index for index in range(len(component.inputs)) if index not in supplied
            )
            if len(missing) != 1:
                reason = (
                    TransformationFailureReason.MULTIPLE_PREDECESSORS
                    if len(missing) > 1
                    else TransformationFailureReason.AMBIGUOUS_BOUNDARY
                )
                raise TransformationError(
                    reason,
                    "recovery requires exactly one unspecified predecessor",
                    source_ids=tuple(item.source.owner_id for item in component.inputs),
                )
            recover_input = missing[0]
        if not isinstance(recover_input, int) or isinstance(recover_input, bool):
            raise TypeError("recover_input must be an integer or None")
        if recover_input not in range(len(component.inputs)):
            raise TransformationError(
                TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                "recovered input index is outside the component input range",
            )
        supplied.pop(recover_input, None)
        missing_auxiliary = tuple(
            component.inputs[index].source.owner_id
            for index in range(len(component.inputs))
            if index != recover_input and index not in supplied
        )
        if missing_auxiliary:
            raise TransformationError(
                TransformationFailureReason.MISSING_AUXILIARY_VALUE,
                "inverse recovery requires every other component input",
                source_ids=missing_auxiliary,
            )
        auxiliaries = tuple(
            as_selection(supplied[index])
            for index in range(len(component.inputs))
            if index != recover_input
        )
        for original, replacement in zip(
            (item for index, item in enumerate(component.inputs) if index != recover_input),
            auxiliaries,
        ):
            if original.array_type != replacement.array_type:
                raise TransformationError(
                    TransformationFailureReason.AMBIGUOUS_BOUNDARY,
                    "auxiliary array type does not match its predecessor",
                    source_ids=(original.source.owner_id, replacement.source.owner_id),
                )
        semantics = self._semantics.get(type(component))
        if semantics is None:
            raise TransformationError(
                TransformationFailureReason.UNSUPPORTED_COMPONENT,
                f"no inverse semantics is registered for {type(component).__name__}",
                source_ids=_component_ids(component),
            )
        if semantics.factory is None:
            raise TransformationError(
                semantics.failure_reason or TransformationFailureReason.UNSUPPORTED_COMPONENT,
                semantics.rationale or f"{type(component).__name__} has no supported inverse",
                source_ids=_component_ids(component),
            )
        return semantics.factory(component, output_selection, auxiliaries, recover_input)


def _component_ids(component: Component) -> tuple[str, ...]:
    return (component.component_id,) if component.component_id else ()


def _source_ids(component: Component, output: Selection) -> tuple[str, ...]:
    return (*_component_ids(component), output.source.owner_id)


def _unary(factory: Callable[[Selection], Component]) -> InverseFactory:
    def create(component, output, auxiliaries, recover_input):
        if recover_input != 0:  # pragma: no cover - registry validation reaches this first
            raise AssertionError("unary recovery index must be zero")
        return factory(output)

    return create


def _inverse_permutation(component, output, auxiliaries, recover_input):
    mapping = [0] * len(component.mapping)
    for output_position, input_position in enumerate(component.mapping):
        mapping[input_position] = output_position
    return Permutation(output, mapping)


def _inverse_sbox(component, output, auxiliaries, recover_input):
    if len(component.table) != len(set(component.table)):
        raise TransformationError(
            TransformationFailureReason.INFORMATION_LOSS,
            f"{type(component).__name__} lookup table is not bijective",
            source_ids=_component_ids(component),
        )
    inverse = [0] * len(component.table)
    for source, target in enumerate(component.table):
        inverse[target] = source
    if isinstance(component, BitVectorSBox):
        if component.output_type.unit_count != component.inputs[0].array_type.unit_count:
            raise TransformationError(
                TransformationFailureReason.INFORMATION_LOSS,
                "bit-vector S-box changes width",
                source_ids=_component_ids(component),
            )
        return BitVectorSBox(output, inverse)
    return SBox(output, inverse)


def _domain_add(domain, left, right):
    if isinstance(domain, (Bit, BinaryExtensionField)):
        return left ^ right
    if isinstance(domain, PrimeField):
        return (left + right) % domain.modulus
    raise TypeError(f"matrix inversion does not support {type(domain).__name__}")


def _domain_multiply(domain, left, right):
    if isinstance(domain, Bit):
        return left & right
    if isinstance(domain, BinaryExtensionField):
        return binary_field_multiply(domain, left, right)
    if isinstance(domain, PrimeField):
        return (left * right) % domain.modulus
    raise TypeError(f"matrix inversion does not support {type(domain).__name__}")


def _domain_inverse(domain, value):
    if not value:
        raise ZeroDivisionError
    if isinstance(domain, Bit):
        return 1
    if isinstance(domain, BinaryExtensionField):
        result = 1
        base = value
        exponent = (1 << domain.degree) - 2
        while exponent:
            if exponent & 1:
                result = _domain_multiply(domain, result, base)
            base = _domain_multiply(domain, base, base)
            exponent >>= 1
        return result
    if isinstance(domain, PrimeField):
        return pow(value, domain.modulus - 2, domain.modulus)
    raise TypeError(f"matrix inversion does not support {type(domain).__name__}")


@lru_cache(maxsize=64)
def _inverse_matrix(matrix, domain):
    size = len(matrix)
    if size == 0 or any(len(row) != size for row in matrix):
        return None
    if isinstance(domain, Bit):
        augmented = [
            sum((coefficient & 1) << column for column, coefficient in enumerate(row))
            | (1 << (size + row_index))
            for row_index, row in enumerate(matrix)
        ]
        for column in range(size):
            pivot = next(
                (row for row in range(column, size) if augmented[row] & (1 << column)),
                None,
            )
            if pivot is None:
                return None
            augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
            for row in range(size):
                if row != column and augmented[row] & (1 << column):
                    augmented[row] ^= augmented[column]
        return tuple(
            tuple((row >> (size + column)) & 1 for column in range(size)) for row in augmented
        )
    augmented = [
        list(row) + [int(column == row_index) for column in range(size)]
        for row_index, row in enumerate(matrix)
    ]
    for column in range(size):
        pivot = next((row for row in range(column, size) if augmented[row][column]), None)
        if pivot is None:
            return None
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        scale = _domain_inverse(domain, augmented[column][column])
        augmented[column] = [_domain_multiply(domain, scale, value) for value in augmented[column]]
        for row in range(size):
            if row == column or not augmented[row][column]:
                continue
            factor = augmented[row][column]
            # Subtraction equals addition in characteristic two.  Prime fields
            # need the additive inverse of the elimination factor.
            if isinstance(domain, PrimeField):
                factor = (-factor) % domain.modulus
            augmented[row] = [
                _domain_add(domain, value, _domain_multiply(domain, factor, pivot_value))
                for value, pivot_value in zip(augmented[row], augmented[column])
            ]
    return tuple(tuple(row[size:]) for row in augmented)


def _inverse_linear_map(component, output, auxiliaries, recover_input):
    domain = component.inputs[0].array_type.domain
    inverse = _inverse_matrix(component.matrix, domain)
    if inverse is None:
        raise TransformationError(
            TransformationFailureReason.INFORMATION_LOSS,
            "linear map is not square and nonsingular",
            source_ids=_component_ids(component),
        )
    return LinearMap(output, inverse)


def _inverse_binary_affine_map(component, output, auxiliaries, recover_input):
    domain = component.inputs[0].array_type.domain
    inverse = _inverse_matrix(component.matrix, Bit())
    if inverse is None:
        raise TransformationError(
            TransformationFailureReason.INFORMATION_LOSS,
            "binary affine map has a singular matrix",
            source_ids=_component_ids(component),
        )
    bits = tuple(
        (component.offset >> (domain.degree - 1 - index)) & 1 for index in range(domain.degree)
    )
    transformed = tuple(
        sum(coefficient & value for coefficient, value in zip(row, bits)) & 1 for row in inverse
    )
    offset = sum(value << (domain.degree - 1 - index) for index, value in enumerate(transformed))
    return BinaryAffineMap(output, inverse, offset)


def _inverse_power(component, output, auxiliaries, recover_input):
    domain = component.output_type.domain
    if isinstance(domain, Bit):
        exponent = 1
    elif isinstance(domain, BinaryExtensionField):
        order = (1 << domain.degree) - 1
        if gcd(component.exponent, order) != 1:
            raise TransformationError(
                TransformationFailureReason.INFORMATION_LOSS,
                "power exponent is not coprime to the field multiplicative-group order",
                source_ids=_component_ids(component),
            )
        exponent = pow(component.exponent, -1, order)
    elif isinstance(domain, PrimeField):
        order = domain.modulus - 1
        if gcd(component.exponent, order) != 1:
            raise TransformationError(
                TransformationFailureReason.INFORMATION_LOSS,
                "power exponent is not coprime to the field multiplicative-group order",
                source_ids=_component_ids(component),
            )
        exponent = pow(component.exponent, -1, order)
    else:
        raise TransformationError(
            TransformationFailureReason.UNSUPPORTED_COMPONENT,
            f"power inversion is unavailable for {type(domain).__name__}",
            source_ids=_component_ids(component),
        )
    return Power(output, exponent)


def _recover_xor(component, output, auxiliaries, recover_input):
    return Xor((output, *auxiliaries))


def _recover_add(component, output, auxiliaries, recover_input):
    if isinstance(component.output_type.domain, (Bit, BinaryExtensionField)):
        return Add((output, *auxiliaries))
    raise TransformationError(
        TransformationFailureReason.UNSUPPORTED_COMPONENT,
        "prime-field additive recovery requires subtraction semantics",
        source_ids=_component_ids(component),
    )


def _recover_modular_add(component, output, auxiliaries, recover_input):
    modulus = 1 << component.output_type.domain.width
    if component.modulus not in (None, modulus):
        raise TransformationError(
            TransformationFailureReason.UNSUPPORTED_COMPONENT,
            "explicit non-power-of-two modular addition has no matching subtraction component",
            source_ids=_component_ids(component),
        )
    return ModularSubtract((output, *auxiliaries))


def _recover_modular_subtract(component, output, auxiliaries, recover_input):
    if recover_input == 0:
        return ModularAdd((output, *auxiliaries))
    original_auxiliaries = {
        index: auxiliary
        for index, auxiliary in zip(
            (index for index in range(len(component.inputs)) if index != recover_input),
            auxiliaries,
        )
    }
    return ModularSubtract(
        (
            original_auxiliaries[0],
            output,
            *(
                original_auxiliaries[index]
                for index in range(1, len(component.inputs))
                if index != recover_input
            ),
        )
    )


def _inverse_rotate(component, output, auxiliaries, recover_input):
    return Rotate(output, component.amount, "right" if component.direction == "left" else "left")


def _inverse_variable_rotate(component, output, auxiliaries, recover_input):
    if recover_input != 0:
        raise TransformationError(
            TransformationFailureReason.INFORMATION_LOSS,
            "a rotated value does not uniquely determine its rotation amount",
            source_ids=_component_ids(component),
        )
    return VariableRotate(
        output, auxiliaries[0], "right" if component.direction == "left" else "left"
    )


def _recover_idea_multiply(component, output, auxiliaries, recover_input):
    return IDEAMultiply((output, *auxiliaries), inverse_inputs=range(1, len(auxiliaries) + 1))


def _inverse_feedback_register(component, output, auxiliaries, recover_input):
    starts = []
    start = 0
    for register in component.registers:
        starts.append(start)
        start += register.length
    forbidden = set(starts)
    for register, start in zip(component.registers, starts):
        pivots = tuple(term for term in register.feedback if term.positions == (start,))
        if (
            register.clock is not None
            or len(pivots) != 1
            or not pivots[0].coefficient
            or any(
                forbidden.intersection(term.positions)
                for term in register.feedback
                if term is not pivots[0]
            )
        ):
            raise TransformationError(
                TransformationFailureReason.INFORMATION_LOSS,
                "feedback transition has no explicit reversible outgoing-unit pivot",
                source_ids=_component_ids(component),
            )
    direction = "inverse" if component.direction == "forward" else "forward"
    return FeedbackRegister(
        output,
        component.registers,
        component.clocks,
        direction=direction,
    )


def _unsupported(component_type, reason, rationale):
    return ComponentInverseSemantics(component_type, None, reason, rationale)


DEFAULT_INVERSE_REGISTRY = ComponentInverseRegistry(
    (
        ComponentInverseSemantics(Identity, _unary(Identity)),
        ComponentInverseSemantics(Permutation, _inverse_permutation),
        ComponentInverseSemantics(BitwiseNot, _unary(BitwiseNot)),
        ComponentInverseSemantics(Rotate, _inverse_rotate),
        ComponentInverseSemantics(VariableRotate, _inverse_variable_rotate),
        ComponentInverseSemantics(SBox, _inverse_sbox),
        ComponentInverseSemantics(BitVectorSBox, _inverse_sbox),
        ComponentInverseSemantics(LinearMap, _inverse_linear_map),
        ComponentInverseSemantics(BinaryAffineMap, _inverse_binary_affine_map),
        ComponentInverseSemantics(Power, _inverse_power),
        ComponentInverseSemantics(Xor, _recover_xor),
        ComponentInverseSemantics(Add, _recover_add),
        ComponentInverseSemantics(ModularAdd, _recover_modular_add),
        ComponentInverseSemantics(ModularSubtract, _recover_modular_subtract),
        _unsupported(
            Constant,
            TransformationFailureReason.AMBIGUOUS_BOUNDARY,
            "a constant has no predecessor to recover",
        ),
        _unsupported(
            Shift, TransformationFailureReason.INFORMATION_LOSS, "fixed shifts discard bits"
        ),
        _unsupported(
            VariableShift,
            TransformationFailureReason.INFORMATION_LOSS,
            "variable shifts can discard bits",
        ),
        _unsupported(
            BitwiseAnd,
            TransformationFailureReason.INFORMATION_LOSS,
            "bitwise AND is not bijective in an operand",
        ),
        _unsupported(
            BitwiseOr,
            TransformationFailureReason.INFORMATION_LOSS,
            "bitwise OR is not bijective in an operand",
        ),
        _unsupported(
            Multiply,
            TransformationFailureReason.INFORMATION_LOSS,
            "multiplication is not bijective when an auxiliary can be zero",
        ),
        _unsupported(
            ModularMultiply,
            TransformationFailureReason.INFORMATION_LOSS,
            "modular multiplication is not bijective for every auxiliary",
        ),
        ComponentInverseSemantics(IDEAMultiply, _recover_idea_multiply),
        ComponentInverseSemantics(FeedbackRegister, _inverse_feedback_register),
    )
)


def invert_component(
    component: Component,
    output: PortLike,
    *,
    recover_input: int | None = None,
    auxiliary_inputs: Mapping[int, PortLike] | None = None,
    registry: ComponentInverseRegistry = DEFAULT_INVERSE_REGISTRY,
) -> Component:
    """Build the semantic component that recovers one predecessor.

    This operation creates semantics only.  It neither mutates the source
    component nor inserts the result into a primitive graph.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Word
        >>> from claasp.components import Rotate
        >>> from claasp.transformations import invert_component
        >>> graph = Primitive("inverse", {"x": ArrayType(Word(8), (1,))})
        >>> inverse = invert_component(Rotate(graph.graph.input("x"), 2, "left"),
        ...     graph.graph.input("x"), recover_input=0)
        >>> (inverse.direction, inverse.amount)
        ('right', 2)
    """

    if not isinstance(registry, ComponentInverseRegistry):
        raise TypeError("registry must be a ComponentInverseRegistry")
    return registry.invert(
        component,
        output,
        recover_input=recover_input,
        auxiliary_inputs=auxiliary_inputs,
    )


__all__ = [
    "DEFAULT_INVERSE_REGISTRY",
    "ComponentInverseRegistry",
    "ComponentInverseSemantics",
    "invert_component",
]
