"""Scalable Boolean algebraic-degree upper bounds for typed graphs."""

from dataclasses import dataclass

from claasp.components import (
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    ModularAdd,
    Rotate,
    Xor,
)
from claasp.graph import Primitive
from claasp.unit_types import Bit, Word


@dataclass(frozen=True, slots=True)
class _Degree:
    value: int
    support: frozenset[int]


DegreeUnit = _Degree | tuple[_Degree, ...]


@dataclass(frozen=True, slots=True)
class BooleanDegreeResult:
    """Output degree upper bounds relative to one selected input.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (BooleanDegreeResult.__dataclass_params__.frozen, tuple(field.name for field in fields(BooleanDegreeResult)))
        (True, ('output_bounds', 'variable_input', 'sound', 'complete', 'method'))
    """

    output_bounds: tuple[int, ...]
    variable_input: str
    sound: bool = True
    complete: bool = False
    method: str = "degree_propagation"


class BooleanDegreeEvaluator:
    """Propagate degree bounds without constructing Boolean polynomials.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> from claasp.representations.execution import BooleanDegreeEvaluator
        >>> result = BooleanDegreeEvaluator().evaluate(Simon(number_of_rounds=1), "plaintext")
        >>> (max(result.output_bounds), result.sound, result.complete)
        (2, True, False)
    """

    def evaluate(self, primitive: Primitive, variable_input: str) -> BooleanDegreeResult:
        """Compute the evaluate for this public typed contract."""

        if variable_input not in primitive.graph.input_arrays:
            raise ValueError(f"unknown variable input: {variable_input}")
        capacity = primitive.graph.input_arrays[variable_input].array_type.encoded_bit_size
        assert capacity is not None
        values: dict[str, tuple[DegreeUnit, ...]] = {}
        for name, unit_array in primitive.graph.input_arrays.items():
            unit_type = unit_array.array_type.unit_type
            width = unit_type.width if isinstance(unit_type, Word) else 1
            bits = iter(range(capacity)) if name == variable_input else None

            def degree_bit(bits=bits):
                return (
                    _Degree(1, frozenset((next(bits),)))
                    if bits is not None
                    else _Degree(0, frozenset())
                )

            if isinstance(unit_type, Bit):
                values[name] = tuple(degree_bit() for _ in range(unit_array.array_type.unit_count))
            elif isinstance(unit_type, Word):
                values[name] = tuple(
                    tuple(degree_bit() for _ in range(width))
                    for _ in range(unit_array.array_type.unit_count)
                )
            else:
                raise NotImplementedError("Boolean degree evaluation supports Bit and Word domains")

        binding_cache = {}
        for component in primitive.graph.components:
            operands = tuple(
                primitive.graph.resolve_selection(selection, values, binding_cache)
                for selection in component.inputs
            )
            if isinstance(component, Constant):
                unit_type = component.output_type.unit_type
                if isinstance(unit_type, Bit):
                    values[component.component_id] = tuple(
                        _Degree(0 if value else -1, frozenset()) for value in component.values
                    )
                elif isinstance(unit_type, Word):
                    values[component.component_id] = tuple(
                        tuple(
                            _Degree(
                                0 if value & (1 << (unit_type.width - 1 - bit)) else -1, frozenset()
                            )
                            for bit in range(unit_type.width)
                        )
                        for value in component.values
                    )
                continue
            if isinstance(component, Rotate):
                values[component.component_id] = tuple(
                    self._rotate(unit, component.amount, component.direction)
                    for unit in operands[0]
                )
                continue
            if isinstance(component, BitwiseNot):
                values[component.component_id] = operands[0]
                continue
            if isinstance(component, (Xor, BitwiseAnd, BitwiseOr, ModularAdd)):
                result = list(operands[0])
                for operand in operands[1:]:
                    operation = self._xor if isinstance(component, Xor) else self._and
                    if isinstance(component, BitwiseOr):
                        operation = self._or
                    if isinstance(component, ModularAdd):
                        operation = self._add
                    result = [
                        operation(left, right, capacity) for left, right in zip(result, operand)
                    ]
                values[component.component_id] = tuple(result)
                continue
            raise NotImplementedError(
                f"Boolean degree evaluator does not support {type(component).__name__}"
            )

        if primitive.graph.output is None:
            return BooleanDegreeResult((), variable_input)
        selected = primitive.graph.resolve_selection(primitive.graph.output, values, binding_cache)
        flattened = tuple(
            degree.value
            for unit in selected
            for degree in ((unit,) if isinstance(unit, _Degree) else unit)
        )
        return BooleanDegreeResult(flattened, variable_input)

    @staticmethod
    def _rotate(word: DegreeUnit, amount: int, direction: str) -> DegreeUnit:
        if isinstance(word, _Degree):
            return word
        amount %= len(word)
        if not amount:
            return word
        return (
            word[amount:] + word[:amount]
            if direction == "left"
            else word[-amount:] + word[:-amount]
        )

    @classmethod
    def _xor(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        if isinstance(left, _Degree):
            return _Degree(max(left.value, right.value), left.support | right.support)
        return tuple(cls._xor(a, b, capacity) for a, b in zip(left, right))

    @classmethod
    def _and(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        if isinstance(left, _Degree):
            support = left.support | right.support
            value = (
                -1
                if left.value == -1 or right.value == -1
                else min(len(support), left.value + right.value)
            )
            return _Degree(value, support)
        return tuple(cls._and(a, b, capacity) for a, b in zip(left, right))

    @classmethod
    def _or(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        return cls._xor(cls._xor(left, right, capacity), cls._and(left, right, capacity), capacity)

    @classmethod
    def _add(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        if isinstance(left, _Degree):
            return cls._xor(left, right, capacity)
        output = [_Degree(-1, frozenset())] * len(left)
        carry = _Degree(-1, frozenset())
        for index in range(len(left) - 1, -1, -1):
            a, b = left[index], right[index]
            output[index] = cls._xor(cls._xor(a, b, capacity), carry, capacity)
            carry = cls._xor(
                cls._xor(cls._and(a, b, capacity), cls._and(a, carry, capacity), capacity),
                cls._and(b, carry, capacity),
                capacity,
            )
        return tuple(output)
