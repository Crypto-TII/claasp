"""Direct batch representations and Python execution drivers."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp_next.graph import Primitive
from claasp_next.components.algebraic import Add, BinaryAffineMap, LinearMap, Multiply, Power
from claasp_next.components.conversion import PackBits, UnpackBits
from claasp_next.components.feedback import FeedbackRegister
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import (
    BitwiseAnd, BitwiseNot, BitwiseOr, IDEAMultiply, ModularAdd, ModularMultiply,
    ModularSubtract, Rotate, Shift, VariableRotate, VariableShift, Xor,
)
from claasp_next.representations.execution.scalar import EvaluationResult, RuntimeValue, ScalarExecutionDriver


@dataclass(frozen=True, slots=True)
class BatchEvaluationResult:
    """One scalar evaluation result for every item in a batch."""

    items: tuple[EvaluationResult, ...]

    @property
    def outputs(self) -> tuple[RuntimeValue | None, ...]:
        """Return declared primitive outputs in batch order.

        EXAMPLES::

            >>> from claasp_next.primitives import MiMC
            >>> from claasp_next.representations.execution import BatchEvaluator
            >>> primitive = MiMC(17, 3, (1, 2, 4))
            >>> BatchEvaluator().evaluate(primitive, {"state": ((5,), (7,))}).outputs
            ((5,), (0,))
        """

        return tuple(item.output for item in self.items)

    def values_of(self, source_id: str) -> tuple[RuntimeValue, ...]:
        """Return one internal source value per batch item."""

        return tuple(item.value_of(source_id) for item in self.items)


class BatchExecutionDriver:
    """Evaluate multiple inputs with exactly the scalar backend semantics.

    This evaluator establishes the public batch contract and is the reference
    against which optimized backends are tested. It intentionally favors
    correctness over throughput.

    EXAMPLES::

        >>> from claasp_next.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1,))
        >>> BatchEvaluator().evaluate(primitive, {"state": ((0,), (1,), (2,))}).outputs
        ((1,), (8,), (10,))
    """

    def __init__(self, scalar_evaluator: ScalarExecutionDriver | None = None) -> None:
        self._scalar_evaluator = scalar_evaluator or ScalarExecutionDriver()

    def evaluate(
        self,
        primitive: Primitive,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")

        expected_names = set(primitive.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"primitive inputs do not match: missing={missing}, unexpected={unexpected}")

        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every primitive input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        results = []
        for item_index in range(batch_size):
            item_inputs = {name: inputs[name][item_index] for name in primitive.inputs}
            results.append(self._scalar_evaluator.evaluate(primitive, item_inputs))
        return BatchEvaluationResult(tuple(results))


class TransposedBatchExecutionDriver(BatchExecutionDriver):
    """Evaluate a batch in one graph traversal using dependency-free tuples.

    The backend keeps arbitrary-size field elements as Python integers, so it
    is suitable for fields such as BN254 without a NumPy dependency or
    machine-word truncation. Its result is identical to :class:`BatchEvaluator`.

    EXAMPLES::

        >>> from claasp_next.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1,))
        >>> TransposedBatchEvaluator().evaluate(
        ...     primitive, {"state": ((0,), (1,), (2,))}
        ... ).outputs
        ((1,), (8,), (10,))
    """

    def evaluate(
        self,
        primitive: Primitive,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        expected_names = set(primitive.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"primitive inputs do not match: missing={missing}, unexpected={unexpected}")
        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every primitive input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        values: dict[str, tuple[RuntimeValue, ...]] = {}
        for name, port in primitive.inputs.items():
            batch = tuple(tuple(item) for item in inputs[name])
            for item in batch:
                self._scalar_evaluator._validate_value(
                    name, item, port.value_type.unit_count, port.value_type.domain
                )
            values[name] = batch

        for component in primitive.components:
            selected = tuple(
                tuple(
                    tuple(values[item.source.owner_id][lane][position] for position in item.positions)
                    for lane in range(batch_size)
                )
                for item in component.inputs
            )
            output = self._evaluate_component(component, selected, batch_size)
            for item in output:
                self._scalar_evaluator._validate_value(
                    component.component_id,
                    item,
                    component.output_type.unit_count,
                    component.output_type.domain,
                )
            values[component.component_id] = output

        results = []
        for lane in range(batch_size):
            lane_values = {source_id: batch[lane] for source_id, batch in values.items()}
            output = None
            if primitive.output is not None:
                output = tuple(
                    lane_values[primitive.output.source.owner_id][position]
                    for position in primitive.output.positions
                )
            from claasp_next.annotations import ExecutionTrace, GraphAnnotation
            from claasp_next.semantics import CONCRETE

            annotation = GraphAnnotation.from_values(primitive, CONCRETE, lane_values, output=output)
            results.append(EvaluationResult(lane_values, output, ExecutionTrace(annotation)))
        return BatchEvaluationResult(tuple(results))

    def _evaluate_component(self, component, inputs, batch_size):
        scalar = self._scalar_evaluator
        if isinstance(component, Constant):
            return (component.values,) * batch_size
        handlers = {
            Identity: scalar._evaluate_identity,
            Permutation: scalar._evaluate_permutation,
            Concatenate: scalar._evaluate_concatenate,
            Add: scalar._evaluate_add,
            Multiply: scalar._evaluate_multiply,
            Power: scalar._evaluate_power,
            LinearMap: scalar._evaluate_linear_map,
            BinaryAffineMap: scalar._evaluate_binary_affine_map,
            BitwiseAnd: scalar._evaluate_bitwise_and,
            BitwiseNot: scalar._evaluate_bitwise_not,
            BitwiseOr: scalar._evaluate_bitwise_or,
            IDEAMultiply: scalar._evaluate_idea_multiply,
            ModularAdd: scalar._evaluate_modular_add,
            ModularMultiply: scalar._evaluate_modular_multiply,
            ModularSubtract: scalar._evaluate_modular_subtract,
            Rotate: scalar._evaluate_rotate,
            Shift: scalar._evaluate_shift,
            VariableRotate: scalar._evaluate_variable_rotate,
            VariableShift: scalar._evaluate_variable_shift,
            Xor: scalar._evaluate_xor,
            SBox: scalar._evaluate_sbox,
            BitVectorSBox: scalar._evaluate_bit_vector_sbox,
            PackBits: scalar._evaluate_pack_bits,
            UnpackBits: scalar._evaluate_unpack_bits,
            FeedbackRegister: scalar._evaluate_feedback_register,
        }
        try:
            handler = handlers[type(component)]
        except KeyError as error:
            raise NotImplementedError(
                f"TransposedBatchEvaluator does not support {type(component).__name__}"
            ) from error
        return tuple(
            tuple(handler(component, tuple(operand[lane] for operand in inputs)))
            for lane in range(batch_size)
        )


# Transitional spellings for code written during the early v5 milestones.
BatchEvaluator = BatchExecutionDriver
TransposedBatchEvaluator = TransposedBatchExecutionDriver
