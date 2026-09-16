"""Scalable Boolean algebraic-degree upper bounds for typed graphs."""

from dataclasses import dataclass

from claasp_next.components import (
    BitwiseAnd, BitwiseNot, BitwiseOr, Concatenate, Constant, ModularAdd, Rotate, Xor,
)
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive


@dataclass(frozen=True, slots=True)
class _Degree:
    value: int
    support: frozenset[int]


DegreeUnit = _Degree | tuple[_Degree, ...]


@dataclass(frozen=True, slots=True)
class BooleanDegreeResult:
    """Output degree upper bounds relative to one selected input."""

    output_bounds: tuple[int, ...]
    variable_input: str
    sound: bool = True
    complete: bool = False
    method: str = "degree_propagation"


class BooleanDegreeEvaluator:
    """Propagate degree bounds without constructing Boolean polynomials."""

    def evaluate(self, primitive: Primitive, variable_input: str) -> BooleanDegreeResult:
        if variable_input not in primitive.inputs:
            raise ValueError(f"unknown variable input: {variable_input}")
        capacity = primitive.inputs[variable_input].value_type.encoded_bit_size
        assert capacity is not None
        values: dict[str, tuple[DegreeUnit, ...]] = {}
        for name, port in primitive.inputs.items():
            domain = port.value_type.domain
            width = domain.width if isinstance(domain, Word) else 1
            bits = iter(range(capacity)) if name == variable_input else None
            def degree_bit():
                return _Degree(1, frozenset((next(bits),))) if bits is not None else _Degree(0, frozenset())
            if isinstance(domain, Bit):
                values[name] = tuple(degree_bit() for _ in range(port.value_type.unit_count))
            elif isinstance(domain, Word):
                values[name] = tuple(tuple(degree_bit() for _ in range(width))
                                     for _ in range(port.value_type.unit_count))
            else:
                raise NotImplementedError("Boolean degree evaluation supports Bit and Word domains")

        for component in primitive.components:
            operands = tuple(
                tuple(values[selection.source.owner_id][position] for position in selection.positions)
                for selection in component.inputs
            )
            if isinstance(component, Constant):
                domain = component.output_type.domain
                if isinstance(domain, Bit):
                    values[component.component_id] = tuple(
                        _Degree(0 if value else -1, frozenset()) for value in component.values
                    )
                elif isinstance(domain, Word):
                    values[component.component_id] = tuple(
                        tuple(_Degree(0 if value & (1 << (domain.width - 1 - bit)) else -1,
                                      frozenset())
                              for bit in range(domain.width))
                        for value in component.values
                    )
                continue
            if isinstance(component, Concatenate):
                values[component.component_id] = tuple(unit for operand in operands for unit in operand)
                continue
            if isinstance(component, Rotate):
                values[component.component_id] = tuple(
                    self._rotate(unit, component.amount, component.direction) for unit in operands[0]
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
                    result = [operation(left, right, capacity) for left, right in zip(result, operand)]
                values[component.component_id] = tuple(result)
                continue
            raise NotImplementedError(
                f"Boolean degree evaluator does not support {type(component).__name__}"
            )

        if primitive.output is None:
            return BooleanDegreeResult((), variable_input)
        selected = tuple(
            values[primitive.output.source.owner_id][position] for position in primitive.output.positions
        )
        flattened = tuple(degree.value for unit in selected
                          for degree in ((unit,) if isinstance(unit, _Degree) else unit))
        return BooleanDegreeResult(flattened, variable_input)

    @staticmethod
    def _rotate(word: DegreeUnit, amount: int, direction: str) -> DegreeUnit:
        if isinstance(word, _Degree):
            return word
        amount %= len(word)
        if not amount:
            return word
        return word[amount:] + word[:amount] if direction == "left" else word[-amount:] + word[:-amount]

    @classmethod
    def _xor(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        if isinstance(left, _Degree):
            return _Degree(max(left.value, right.value), left.support | right.support)
        return tuple(cls._xor(a, b, capacity) for a, b in zip(left, right))

    @classmethod
    def _and(cls, left: DegreeUnit, right: DegreeUnit, capacity: int) -> DegreeUnit:
        if isinstance(left, _Degree):
            support = left.support | right.support
            value = -1 if left.value == -1 or right.value == -1 else min(
                len(support), left.value + right.value
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
                cls._and(b, carry, capacity), capacity,
            )
        return tuple(output)
