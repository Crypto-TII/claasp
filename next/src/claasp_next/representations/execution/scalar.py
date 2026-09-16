"""Direct scalar representation and Python execution driver."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from claasp_next.annotations import ExecutionTrace, GraphAnnotation
from claasp_next.components.algebraic import Add, BinaryAffineMap, LinearMap, Multiply, Power
from claasp_next.components.conversion import PackBits, UnpackBits
from claasp_next.components.feedback import FeedbackRegister, FeedbackTerm
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import (
    BitwiseAnd, BitwiseNot, BitwiseOr, IDEAMultiply, ModularAdd, ModularMultiply,
    ModularSubtract, Rotate, Shift, VariableRotate, VariableShift, Xor,
)
from claasp_next.graph.primitive import Primitive
from claasp_next.graph.component import Component
from claasp_next.semantics import CONCRETE

RuntimeValue = tuple[int, ...]
Handler = Callable[[Component, tuple[RuntimeValue, ...]], RuntimeValue]


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Values produced for primitive inputs and component outputs."""

    values: Mapping[str, RuntimeValue]
    output: RuntimeValue | None
    trace: ExecutionTrace

    def value_of(self, source_id: str) -> RuntimeValue:
        try:
            return self.values[source_id]
        except KeyError as error:
            raise KeyError(f"evaluation source {source_id!r} does not exist") from error

    @property
    def realization(self):
        """Realization metadata retained by the evaluated graph, when declared."""

        return getattr(self.trace.annotation.primitive, "realization", None)


class ScalarExecutionDriver:
    """Correctness-first evaluator using ordinary Python scalar values.

    EXAMPLES::

        >>> from claasp_next.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1, 2, 4))
        >>> ScalarEvaluator().evaluate(primitive, {"state": (5,)}).output
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
            BinaryAffineMap: self._evaluate_binary_affine_map,
            BitwiseAnd: self._evaluate_bitwise_and,
            BitwiseNot: self._evaluate_bitwise_not,
            BitwiseOr: self._evaluate_bitwise_or,
            IDEAMultiply: self._evaluate_idea_multiply,
            ModularAdd: self._evaluate_modular_add,
            ModularMultiply: self._evaluate_modular_multiply,
            ModularSubtract: self._evaluate_modular_subtract,
            Rotate: self._evaluate_rotate,
            Shift: self._evaluate_shift,
            VariableRotate: self._evaluate_variable_rotate,
            VariableShift: self._evaluate_variable_shift,
            Xor: self._evaluate_xor,
            SBox: self._evaluate_sbox,
            BitVectorSBox: self._evaluate_bit_vector_sbox,
            PackBits: self._evaluate_pack_bits,
            UnpackBits: self._evaluate_unpack_bits,
            FeedbackRegister: self._evaluate_feedback_register,
        }

    def register(self, component_type: type[Component], handler: Handler) -> None:
        """Register or replace an exact component-type handler."""

        if not isinstance(component_type, type) or not issubclass(component_type, Component):
            raise TypeError("component_type must be a Component subclass")
        if not callable(handler):
            raise TypeError("handler must be callable")
        self._handlers[component_type] = handler

    def evaluate(self, primitive: Primitive, inputs: Mapping[str, Sequence[int]]) -> EvaluationResult:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        expected_names = set(primitive.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"primitive inputs do not match: missing={missing}, unexpected={unexpected}")

        values: dict[str, RuntimeValue] = {}
        for name, port in primitive.inputs.items():
            value = tuple(inputs[name])
            self._validate_value(name, value, port.value_type.unit_count, port.value_type.domain)
            values[name] = value

        for component in primitive.components:
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
        if primitive.output is not None:
            output = tuple(
                values[primitive.output.source.owner_id][position]
                for position in primitive.output.positions
            )
        annotation = GraphAnnotation.from_values(
            primitive, CONCRETE, values, output=output
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
        modulus = component.modulus
        if modulus is None:
            mask = (1 << component.output_type.domain.width) - 1
            return tuple(sum(values) & mask for values in zip(*inputs))
        return tuple(sum(values) % modulus for values in zip(*inputs))

    @staticmethod
    def _evaluate_modular_subtract(
        component: ModularSubtract, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        mask = (1 << component.output_type.domain.width) - 1
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [(left - right) & mask for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_modular_multiply(
        component: ModularMultiply, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [(left * right) % component.modulus for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_idea_multiply(
        component: IDEAMultiply, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        encoded_zero = 1 << component.output_type.domain.width
        modulus = encoded_zero + 1
        output = [encoded_zero if value == 0 else value for value in inputs[0]]
        for operand in inputs[1:]:
            output = [
                (left * (encoded_zero if right == 0 else right)) % modulus
                for left, right in zip(output, operand)
            ]
        return tuple(0 if value == encoded_zero else value for value in output)

    @staticmethod
    def _evaluate_xor(component: Xor, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [left ^ right for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_bitwise_and(
        component: BitwiseAnd, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [left & right for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_bitwise_or(
        component: BitwiseOr, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        output = list(inputs[0])
        for operand in inputs[1:]:
            output = [left | right for left, right in zip(output, operand)]
        return tuple(output)

    @staticmethod
    def _evaluate_bitwise_not(
        component: BitwiseNot, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        mask = (1 << component.output_type.domain.width) - 1
        return tuple((~value) & mask for value in inputs[0])

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
    def _shift_values(values: RuntimeValue, width: int, amount: int, direction: str) -> RuntimeValue:
        if amount >= width:
            return (0,) * len(values)
        mask = (1 << width) - 1
        if direction == "left":
            return tuple((value << amount) & mask for value in values)
        return tuple(value >> amount for value in values)

    @classmethod
    def _evaluate_shift(cls, component: Shift, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return cls._shift_values(
            inputs[0], component.output_type.domain.width, component.amount, component.direction
        )

    @classmethod
    def _evaluate_variable_shift(
        cls, component: VariableShift, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        width = component.output_type.domain.width
        return cls._shift_values(
            inputs[0], width, inputs[1][0] % width, component.direction
        )

    @staticmethod
    def _evaluate_variable_rotate(
        component: VariableRotate, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        width = component.output_type.domain.width
        amount = inputs[1][0] % width
        if amount == 0:
            return inputs[0]
        mask = (1 << width) - 1
        if component.direction == "left":
            return tuple(((value << amount) | (value >> (width - amount))) & mask for value in inputs[0])
        return tuple(((value >> amount) | (value << (width - amount))) & mask for value in inputs[0])

    @classmethod
    def _evaluate_feedback_term(cls, domain, term: FeedbackTerm, state: RuntimeValue) -> int:
        value = term.coefficient
        for position in term.positions:
            value = cls._multiply_scalar(domain, value, state[position])
        return value

    @classmethod
    def _evaluate_feedback_polynomial(cls, domain, terms, state: RuntimeValue) -> int:
        value = 0
        for term in terms:
            value = cls._add_scalar(domain, value, cls._evaluate_feedback_term(domain, term, state))
        return value

    @classmethod
    def _evaluate_feedback_register(
        cls, component: FeedbackRegister, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        domain = component.output_type.domain
        state = inputs[0]
        for _ in range(component.clocks):
            previous = state
            updated = list(previous)
            start = 0
            for register in component.registers:
                stop = start + register.length
                clock = 1 if register.clock is None else cls._evaluate_feedback_polynomial(
                    domain, register.clock, previous
                )
                if clock:
                    feedback = cls._evaluate_feedback_polynomial(domain, register.feedback, previous)
                    updated[start:stop] = previous[start + 1:stop] + (feedback,)
                start = stop
            state = tuple(updated)
        return state

    @staticmethod
    def _evaluate_sbox(component: SBox, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return tuple(component.table[value] for value in inputs[0])

    @staticmethod
    def _evaluate_binary_affine_map(
        component: BinaryAffineMap, inputs: tuple[RuntimeValue, ...]
    ) -> RuntimeValue:
        width = component.output_type.domain.degree
        output = []
        for value in inputs[0]:
            transformed = component.offset
            for row, coefficients in enumerate(component.matrix):
                bit = 0
                for column, coefficient in enumerate(coefficients):
                    bit ^= coefficient & ((value >> (width - 1 - column)) & 1)
                transformed ^= bit << (width - 1 - row)
            output.append(transformed)
        return tuple(output)

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

    @staticmethod
    def _evaluate_pack_bits(component: PackBits, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        bits = inputs[0]
        output = []
        for start in range(0, len(bits), component.word_width):
            word = 0
            for bit in bits[start : start + component.word_width]:
                word = (word << 1) | bit
            output.append(word)
        return tuple(output)

    @staticmethod
    def _evaluate_unpack_bits(component: UnpackBits, inputs: tuple[RuntimeValue, ...]) -> RuntimeValue:
        return tuple(
            (word >> position) & 1
            for word in inputs[0]
            for position in range(component.word_width - 1, -1, -1)
        )


# Transitional spelling for code written during the early v5 milestones.
ScalarEvaluator = ScalarExecutionDriver
