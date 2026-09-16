"""Symbolic Boolean execution of typed bit and word graphs."""

from collections.abc import Mapping
from dataclasses import dataclass

from claasp_next.components import (
    BitwiseAnd, BitwiseNot, BitwiseOr, Concatenate, Constant, ModularAdd, Rotate, Xor,
)
from claasp_next.domains import Bit, Word
from claasp_next.graph import Primitive
from claasp_next.representations.constraints.polynomial import BooleanPolynomial


SymbolicUnit = BooleanPolynomial | tuple[BooleanPolynomial, ...]


@dataclass(frozen=True, slots=True)
class BooleanSymbolicResult:
    """Flattened output ANFs and all graph source values."""

    output_anfs: tuple[BooleanPolynomial, ...]
    values: Mapping[str, tuple[SymbolicUnit, ...]]


class BooleanSymbolicEvaluator:
    """Evaluate supported typed graphs over sparse algebraic normal forms.

    Input variables are named with conventional prefixes (``p`` for
    plaintext, ``k`` for key) and use MSB-first flattened bit positions.
    """

    def evaluate(self, primitive: Primitive) -> BooleanSymbolicResult:
        """Return exact output ANFs for a supported Bit/Word primitive graph."""

        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a typed graph")
        values = {}
        for name, port in primitive.inputs.items():
            prefix = {"plaintext": "p", "key": "k", "state": "s"}.get(name, name[:1])
            domain = port.value_type.domain
            if isinstance(domain, Bit):
                values[name] = tuple(
                    BooleanPolynomial.variable(f"{prefix}{index}")
                    for index in range(port.value_type.unit_count)
                )
            elif isinstance(domain, Word):
                values[name] = tuple(
                    tuple(BooleanPolynomial.variable(
                        f"{prefix}{unit * domain.width + bit}"
                    ) for bit in range(domain.width))
                    for unit in range(port.value_type.unit_count)
                )
            else:
                raise NotImplementedError("Boolean symbolic evaluation supports Bit and Word domains")

        for component in primitive.components:
            inputs = tuple(
                tuple(values[selection.source.owner_id][position] for position in selection.positions)
                for selection in component.inputs
            )
            values[component.component_id] = self._component(component, inputs)
        if primitive.output is None:
            return BooleanSymbolicResult((), values)
        selected = tuple(
            values[primitive.output.source.owner_id][position]
            for position in primitive.output.positions
        )
        flattened = tuple(
            polynomial
            for unit in selected
            for polynomial in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
        )
        return BooleanSymbolicResult(flattened, values)

    def _component(self, component, inputs):
        if isinstance(component, Constant):
            domain = component.output_type.domain
            if isinstance(domain, Bit):
                return tuple(BooleanPolynomial.one() if value else BooleanPolynomial.zero()
                             for value in component.values)
            if isinstance(domain, Word):
                return tuple(tuple(
                    BooleanPolynomial.one() if value & (1 << (domain.width - 1 - bit))
                    else BooleanPolynomial.zero()
                    for bit in range(domain.width)
                ) for value in component.values)
        if isinstance(component, Concatenate):
            return tuple(unit for operand in inputs for unit in operand)
        if isinstance(component, Rotate):
            return tuple(self._rotate(unit, component.amount, component.direction) for unit in inputs[0])
        if isinstance(component, BitwiseNot):
            return tuple(self._word_not(unit) for unit in inputs[0])
        if isinstance(component, (Xor, BitwiseAnd, BitwiseOr, ModularAdd)):
            result = list(inputs[0])
            for operand in inputs[1:]:
                if isinstance(component, Xor):
                    result = [self._word_xor(left, right) for left, right in zip(result, operand)]
                elif isinstance(component, BitwiseAnd):
                    result = [self._word_and(left, right) for left, right in zip(result, operand)]
                elif isinstance(component, BitwiseOr):
                    result = [self._word_or(left, right) for left, right in zip(result, operand)]
                else:
                    result = [self._word_add(left, right) for left, right in zip(result, operand)]
            return tuple(result)
        raise NotImplementedError(f"Boolean symbolic evaluator does not support {type(component).__name__}")

    @staticmethod
    def _rotate(word, amount, direction):
        amount %= len(word)
        if not amount:
            return word
        return word[amount:] + word[:amount] if direction == "left" else word[-amount:] + word[:-amount]

    @staticmethod
    def _word_xor(left, right):
        if isinstance(left, BooleanPolynomial):
            return left + right
        return tuple(a + b for a, b in zip(left, right))

    @staticmethod
    def _word_and(left, right):
        if isinstance(left, BooleanPolynomial):
            return left * right
        return tuple(a * b for a, b in zip(left, right))

    @classmethod
    def _word_or(cls, left, right):
        return cls._word_xor(cls._word_xor(left, right), cls._word_and(left, right))

    @staticmethod
    def _word_not(word):
        one = BooleanPolynomial.one()
        if isinstance(word, BooleanPolynomial):
            return word + one
        return tuple(bit + one for bit in word)

    @staticmethod
    def _word_add(left, right):
        if isinstance(left, BooleanPolynomial):
            return left + right
        output = [BooleanPolynomial.zero()] * len(left)
        carry = BooleanPolynomial.zero()
        for index in range(len(left) - 1, -1, -1):
            a, b = left[index], right[index]
            output[index] = a + b + carry
            carry = a * b + a * carry + b * carry
        return tuple(output)
