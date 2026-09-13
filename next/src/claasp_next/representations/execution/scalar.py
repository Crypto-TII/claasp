"""Direct scalar representation and Python execution driver."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from claasp_next.annotations import ExecutionTrace, GraphAnnotation
from claasp_next.components.algebraic import Add, LinearMap, Multiply, Power
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import ModularAdd, Rotate, Xor
from claasp_next.core.cipher import Cipher
from claasp_next.core.component import Component
from claasp_next.interpretations import CONCRETE

RuntimeValue = tuple[int, ...]
Handler = Callable[[Component, tuple[RuntimeValue, ...]], RuntimeValue]


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Values produced for cipher inputs and component outputs."""

    values: Mapping[str, RuntimeValue]
    output: RuntimeValue | None
    trace: ExecutionTrace

    def value_of(self, source_id: str) -> RuntimeValue:
        try:
            return self.values[source_id]
        except KeyError as error:
            raise KeyError(f"evaluation source {source_id!r} does not exist") from error


class ScalarExecutionDriver:
    """Correctness-first evaluator using ordinary Python scalar values.

    EXAMPLES::

        >>> from claasp_next.ciphers import MiMCPermutation
        >>> cipher = MiMCPermutation(17, 3, (1, 2, 4))
        >>> ScalarEvaluator().evaluate(cipher, {"state": (5,)}).output
        (5,)
    """

    def __init__(self) -> None:
        self._handlers: dict[type[Component], Handler] = {
            Constant: self._evaluate_constant,
            Identity: self._evaluate_identity,
            Permutation: self._evaluate_permutation,
            Concatenate: self._evaluate_concatenate,
            Add: self._evaluate_add,
            Multiply: self._evaluate_multiply,
            Power: self._evaluate_power,
            LinearMap: self._evaluate_linear_map,
            ModularAdd: self._evaluate_modular_add,
            Rotate: self._evaluate_rotate,
            Xor: self._evaluate_xor,
            SBox: self._evaluate_sbox,
            BitVectorSBox: self._evaluate_bit_vector_sbox,
        }

    def register(self, component_type: type[Component], handler: Handler) -> None:
        """Register or replace an exact component-type handler."""

        if not isinstance(component_type, type) or not issubclass(component_type, Component):
            raise TypeError("component_type must be a Component subclass")
        if not callable(handler):
            raise TypeError("handler must be callable")
        self._handlers[component_type] = handler

    def evaluate(self, cipher: Cipher, inputs: Mapping[str, Sequence[int]]) -> EvaluationResult:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        expected_names = set(cipher.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"cipher inputs do not match: missing={missing}, unexpected={unexpected}")

        values: dict[str, RuntimeValue] = {}
        for name, port in cipher.inputs.items():
            value = tuple(inputs[name])
            self._validate_value(name, value, port.value_type.unit_count, port.value_type.domain)
            values[name] = value

        for component in cipher.components:
            selected_inputs = tuple(
                tuple(values[item.source.owner_id][position] for position in item.positions)
                for item in component.inputs
            )
            try:
                handler = self._handlers[type(component)]
            except KeyError as error:
                raise NotImplementedError(
                    f"ScalarEvaluator does not support {type(component).__name__}"
                ) from error
            output = tuple(handler(component, selected_inputs))
            self._validate_value(
                component.component_id,
                output,
                component.output_type.unit_count,
                component.output_type.domain,
            )
            values[component.component_id] = output

        output = None
        if cipher.output is not None:
            output = tuple(
                values[cipher.output.source.owner_id][position]
                for position in cipher.output.positions
            )
        annotation = GraphAnnotation.from_values(
            cipher, CONCRETE, values, output=output
        )
        return EvaluationResult(dict(values), output, ExecutionTrace(annotation))

    @staticmethod
    def _validate_value(source_id: str, value: RuntimeValue, size: int, domain: object) -> None:
        if len(value) != size:
            raise ValueError(f"{source_id!r} requires {size} logical units, got {len(value)}")
        for scalar in value:
            domain.validate(scalar)

    @staticmethod
    def _evaluate_constant(component: Constant, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return component.values

    @staticmethod
    def _evaluate_identity(component: Identity, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return inputs[0]

    @staticmethod
    def _evaluate_permutation(component: Permutation, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return tuple(inputs[0][position] for position in component.mapping)

    @staticmethod
    def _evaluate_concatenate(component: Concatenate, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return tuple(scalar for component_input in inputs for scalar in component_input)

    @staticmethod
    def _add_scalar(domain: object, left: int, right: int) -> int:
        from claasp_next.domains import BinaryExtensionField, Bit, PrimeField

        if isinstance(domain, (Bit, BinaryExtensionField)):
            return left ^ right
        if isinstance(domain, PrimeField):
            return (left + right) % domain.modulus
        raise NotImplementedError(f"addition is not implemented for {type(domain).__name__}")

    @staticmethod
    def _multiply_scalar(domain: object, left: int, right: int) -> int:
        from claasp_next.domains import BinaryExtensionField, Bit, PrimeField

        if isinstance(domain, Bit):
            return left & right
        if isinstance(domain, PrimeField):
            return (left * right) % domain.modulus
        if isinstance(domain, BinaryExtensionField):
            from claasp_next.utils import binary_field_multiply

            return binary_field_multiply(domain, left, right)
        raise NotImplementedError(f"multiplication is not implemented for {type(domain).__name__}")

    @classmethod
    def _power_scalar(cls, domain: object, value: int, exponent: int) -> int:
        result = 1
        base = value
        remaining = exponent
        while remaining:
            if remaining & 1:
                result = cls._multiply_scalar(domain, result, base)
            base = cls._multiply_scalar(domain, base, base)
            remaining >>= 1
        return result

    @classmethod
    def _evaluate_add(cls, component: Add, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        domain = component.output_type.domain
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [cls._add_scalar(domain, left, right) for left, right in zip(output, operand)]
        return tuple(output)

    @classmethod
    def _evaluate_multiply(cls, component: Multiply, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        domain = component.output_type.domain
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [cls._multiply_scalar(domain, left, right) for left, right in zip(output, operand)]
        return tuple(output)

    @classmethod
    def _evaluate_power(cls, component: Power, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        domain = component.output_type.domain
        return tuple(cls._power_scalar(domain, value, component.exponent) for value in inputs[0])

    @classmethod
    def _evaluate_linear_map(cls, component: LinearMap, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        domain = component.inputs[0].value_type.domain
        vector = inputs[0]
        output = []
        for row in component.matrix:
            products = [cls._multiply_scalar(domain, coefficient, value) for coefficient, value in zip(row, vector)]
            accumulator = products[0]
            for product in products[1:]:
                accumulator = cls._add_scalar(domain, accumulator, product)
            output.append(accumulator)
        return tuple(output)

    @staticmethod
    def _evaluate_modular_add(
        component: ModularAdd, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        mask = (1 << component.output_type.domain.width) - 1
        return tuple(sum(values) & mask for values in zip(*inputs))

    @staticmethod
    def _evaluate_xor(component: Xor, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [left ^ right for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_rotate(component: Rotate, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        width = component.output_type.domain.width
        amount = component.amount
        mask = (1 << width) - 1
        if amount == 0:
            return inputs[0]
        if component.direction == "left":
            return tuple(((value << amount) | (value >> (width - amount))) & mask for value in inputs[0])
        return tuple(((value >> amount) | (value << (width - amount))) & mask for value in inputs[0])

    @staticmethod
    def _evaluate_sbox(component: SBox, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return tuple(component.table[value] for value in inputs[0])

    @staticmethod
    def _evaluate_bit_vector_sbox(
        component: BitVectorSBox, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        value = 0
        for bit in inputs[0]:
            value = (value << 1) | bit
        substituted = component.table[value]
        width = component.output_type.unit_count
        return tuple((substituted >> position) & 1 for position in range(width - 1, -1, -1))


# Transitional spelling for code written during the early v5 milestones.
ScalarEvaluator = ScalarExecutionDriver
