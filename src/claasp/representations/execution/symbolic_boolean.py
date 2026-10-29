"""Symbolic Boolean execution of typed bit and word graphs."""

from collections.abc import Mapping
from dataclasses import dataclass

from claasp.components import (
    Add,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    ModularAdd,
    Multiply,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.graph import Primitive
from claasp.representations.constraints.polynomial import BooleanPolynomial, anf_from_truth_table
from claasp.unit_types import Bit, Word

SymbolicUnit = BooleanPolynomial | tuple[BooleanPolynomial, ...]


@dataclass(frozen=True, slots=True)
class BooleanSymbolicResult:
    """Flattened output ANFs and all graph source values.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (BooleanSymbolicResult.__dataclass_params__.frozen, tuple(field.name for field in fields(BooleanSymbolicResult)))
        (True, ('output_anfs', 'values'))
    """

    output_anfs: tuple[BooleanPolynomial, ...]
    values: Mapping[str, tuple[SymbolicUnit, ...]]


class BooleanSymbolicEvaluator:
    """Evaluate supported typed graphs over sparse algebraic normal forms.

    Input variables are named with conventional prefixes (``p`` for
    plaintext, ``k`` for key) and use MSB-first flattened bit positions.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> from claasp.representations.execution import BooleanSymbolicEvaluator
        >>> BooleanSymbolicEvaluator().evaluate(Simon(number_of_rounds=1)).output_anfs[0].degree
        2
    """

    def evaluate(self, primitive: Primitive) -> BooleanSymbolicResult:
        """Return exact output ANFs for a supported Bit/Word primitive graph."""

        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a typed graph")
        values: dict[str, tuple[SymbolicUnit, ...]] = {}
        for name, unit_array in primitive.graph.input_arrays.items():
            prefix = {"plaintext": "p", "key": "k", "state": "s"}.get(name, name[:1])
            unit_type = unit_array.array_type.unit_type
            if isinstance(unit_type, Bit):
                values[name] = tuple(
                    BooleanPolynomial.variable(f"{prefix}{index}")
                    for index in range(unit_array.array_type.unit_count)
                )
            elif isinstance(unit_type, Word):
                values[name] = tuple(
                    tuple(
                        BooleanPolynomial.variable(f"{prefix}{unit * unit_type.width + bit}")
                        for bit in range(unit_type.width)
                    )
                    for unit in range(unit_array.array_type.unit_count)
                )
            else:
                raise NotImplementedError(
                    "Boolean symbolic evaluation supports Bit and Word domains"
                )

        binding_cache: dict = {}
        for component in primitive.graph.components:
            inputs = tuple(
                primitive.graph.resolve_selection(selection, values, binding_cache)
                for selection in component.inputs
            )
            assert component.component_id is not None
            values[component.component_id] = self._component(component, inputs)
        if primitive.graph.output is None:
            return BooleanSymbolicResult((), values)
        selected = primitive.graph.resolve_selection(primitive.graph.output, values, binding_cache)
        flattened = tuple(
            polynomial
            for unit in selected
            for polynomial in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
        )
        return BooleanSymbolicResult(flattened, values)

    def component_anfs(self, component) -> tuple[BooleanPolynomial, ...]:
        """Return exact output ANFs for one supported Bit/Word component.

        Input names encode operand, logical unit, and MSB-first bit position;
        the result therefore describes the operation rather than a graph id.
        """

        symbolic_inputs: list[tuple[SymbolicUnit, ...]] = []
        for operand_index, selection in enumerate(component.inputs):
            unit_type = selection.array_type.unit_type
            if isinstance(unit_type, Bit):
                symbolic_inputs.append(
                    tuple(
                        BooleanPolynomial.variable(f"x{operand_index}_{unit_index}")
                        for unit_index in range(selection.array_type.unit_count)
                    )
                )
            elif isinstance(unit_type, Word):
                symbolic_inputs.append(
                    tuple(
                        tuple(
                            BooleanPolynomial.variable(f"x{operand_index}_{unit_index}_{bit_index}")
                            for bit_index in range(unit_type.width)
                        )
                        for unit_index in range(selection.array_type.unit_count)
                    )
                )
            else:
                raise NotImplementedError("component ANFs require Bit or Word domains")
        output = self._component(component, tuple(symbolic_inputs))
        return tuple(
            polynomial
            for unit in output
            for polynomial in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
        )

    def _component(self, component, inputs):
        if isinstance(component, Identity):
            return inputs[0]
        if isinstance(component, Permutation):
            return tuple(inputs[0][index] for index in component.mapping)
        if isinstance(component, (BitVectorSBox, SBox)):
            groups = (inputs[0],) if isinstance(component, BitVectorSBox) else inputs[0]
            if isinstance(component, BitVectorSBox):
                output_width = component.output_bit_size
            else:
                unit_type = component.output_type.unit_type
                if not isinstance(unit_type, Word):
                    raise NotImplementedError("symbolic S-box requires Word units")
                output_width = unit_type.width
            results = []
            for group in groups:
                anfs = []
                for bit in range(output_width):
                    local = anf_from_truth_table(
                        tuple((value >> (output_width - 1 - bit)) & 1 for value in component.table)
                    )
                    polynomial_result = BooleanPolynomial.zero()
                    for monomial in local.monomials:
                        term = BooleanPolynomial.one()
                        for variable in monomial.variables:
                            term *= group[int(variable[1:])]
                        polynomial_result += term
                    anfs.append(polynomial_result)
                results.append(tuple(anfs))
            return tuple(results[0]) if isinstance(component, BitVectorSBox) else tuple(results)
        if isinstance(component, (Add, Multiply)):
            if not isinstance(component.output_type.unit_type, Bit):
                raise NotImplementedError("Boolean symbolic Add/Multiply require Bit units")
            result = list(inputs[0])
            for operand in inputs[1:]:
                result = [
                    (a + b) if isinstance(component, Add) else (a * b)
                    for a, b in zip(result, operand)
                ]
            return tuple(result)
        if isinstance(component, Constant):
            unit_type = component.output_type.unit_type
            if isinstance(unit_type, Bit):
                return tuple(
                    BooleanPolynomial.one() if value else BooleanPolynomial.zero()
                    for value in component.values
                )
            if isinstance(unit_type, Word):
                return tuple(
                    tuple(
                        BooleanPolynomial.one()
                        if value & (1 << (unit_type.width - 1 - bit))
                        else BooleanPolynomial.zero()
                        for bit in range(unit_type.width)
                    )
                    for value in component.values
                )
        if isinstance(component, Rotate):
            return tuple(
                self._rotate(unit, component.amount, component.direction) for unit in inputs[0]
            )
        if isinstance(component, Shift):
            return tuple(
                self._shift(unit, component.amount, component.direction) for unit in inputs[0]
            )
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
        raise NotImplementedError(
            f"Boolean symbolic evaluator does not support {type(component).__name__}"
        )

    @staticmethod
    def _rotate(word, amount, direction):
        amount %= len(word)
        if not amount:
            return word
        return (
            word[amount:] + word[:amount]
            if direction == "left"
            else word[-amount:] + word[:-amount]
        )

    @staticmethod
    def _shift(word, amount, direction):
        if isinstance(word, BooleanPolynomial):
            return BooleanPolynomial.zero() if amount else word
        if amount >= len(word):
            return (BooleanPolynomial.zero(),) * len(word)
        if not amount:
            return word
        zeros = (BooleanPolynomial.zero(),) * amount
        return word[amount:] + zeros if direction == "left" else zeros + word[:-amount]

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
