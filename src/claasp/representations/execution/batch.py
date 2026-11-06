"""Direct batch representations and Python execution drivers."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp.graph import GraphPropagation, Primitive
from claasp.provenance import DriverIdentity, DriverKind, ResultProvenance
from claasp.representations.execution.scalar import (
    EvaluationResult,
    RuntimeValue,
    ScalarExecutionDriver,
)


@dataclass(frozen=True, slots=True)
class BatchEvaluationResult:
    """One scalar evaluation result for every item in a batch.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (BatchEvaluationResult.__dataclass_params__.frozen, tuple(field.name for field in fields(BatchEvaluationResult)))
        (True, ('items', 'provenance'))
    """

    items: tuple[EvaluationResult, ...]
    provenance: ResultProvenance

    @property
    def realization(self):
        """Return the realization for this public typed contract."""

        return self.provenance.realization

    @property
    def execution_engine(self) -> DriverIdentity:
        """Return the execution engine for this public typed contract."""

        return self.provenance.driver

    @property
    def outputs(self) -> tuple[RuntimeValue | None, ...]:
        """Return declared primitive outputs in batch order.

        EXAMPLES::

            >>> from claasp.primitives import MiMC
            >>> from claasp.representations.execution import BatchEvaluator
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

        >>> from claasp.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1,))
        >>> BatchEvaluator().evaluate(primitive, {"state": ((0,), (1,), (2,))}).outputs
        ((1,), (8,), (10,))
    """

    identity = DriverIdentity("python_batch", DriverKind.EXECUTION_ENGINE)

    def __init__(self, scalar_evaluator: ScalarExecutionDriver | None = None) -> None:
        self._scalar_evaluator = scalar_evaluator or ScalarExecutionDriver()

    def evaluate(
        self,
        primitive: Primitive,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        """Compute the evaluate for this public typed contract."""

        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")

        expected_names = set(primitive.graph.input_arrays)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(
                f"primitive inputs do not match: missing={missing}, unexpected={unexpected}"
            )

        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every primitive input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        results = []
        for item_index in range(batch_size):
            item_inputs = {name: inputs[name][item_index] for name in primitive.graph.input_arrays}
            results.append(self._scalar_evaluator.evaluate(primitive, item_inputs))
        return BatchEvaluationResult(
            tuple(results), ResultProvenance.for_primitive(primitive, self.identity)
        )


class TransposedBatchExecutionDriver(BatchExecutionDriver):
    """Evaluate a batch in one graph traversal using dependency-free tuples.

    The backend keeps arbitrary-size field elements as Python integers, so it
    is suitable for fields such as BN254 without a NumPy dependency or
    machine-word truncation. Its result is identical to :class:`BatchEvaluator`.

    EXAMPLES::

        >>> from claasp.primitives import MiMC
        >>> primitive = MiMC(17, 3, (1,))
        >>> TransposedBatchEvaluator().evaluate(
        ...     primitive, {"state": ((0,), (1,), (2,))}
        ... ).outputs
        ((1,), (8,), (10,))
    """

    identity = DriverIdentity("python_transposed_batch", DriverKind.EXECUTION_ENGINE)

    def evaluate(
        self,
        primitive: Primitive,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        """Compute the evaluate for this public typed contract."""

        if not isinstance(primitive, Primitive):
            raise TypeError("primitive must be a Primitive")
        expected_names = set(primitive.graph.input_arrays)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(
                f"primitive inputs do not match: missing={missing}, unexpected={unexpected}"
            )
        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every primitive input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        values: dict[str, tuple[RuntimeValue, ...]] = {}
        for name in primitive.graph.input_arrays:
            batch = tuple(tuple(item) for item in inputs[name])
            values[name] = batch

        binding_caches = [{} for _ in range(batch_size)]

        def select(selection, current, cache):
            return tuple(
                primitive.graph.resolve_selection(
                    selection,
                    {source_id: batch[lane] for source_id, batch in current.items()},
                    binding_caches[lane],
                )
                for lane in range(batch_size)
            )

        def validate(name, batch, array_type):
            for item in batch:
                self._scalar_evaluator._validate_value(
                    name, item, array_type.unit_count, array_type.unit_type
                )

        propagated = GraphPropagation(primitive).run(
            values,
            lambda component, operands: self._evaluate_component(component, operands, batch_size),
            select=select,
            validate=validate,
        )
        values = propagated.values

        results = []
        for lane in range(batch_size):
            lane_values = {source_id: batch[lane] for source_id, batch in values.items()}
            output = None
            if primitive.graph.output is not None:
                output = primitive.graph.resolve_selection(
                    primitive.graph.output, lane_values, binding_caches[lane]
                )
            for binding in primitive.graph.bindings:
                primitive.graph.resolve_selection(
                    binding.output.select_all(), lane_values, binding_caches[lane]
                )
            from claasp.annotations import ExecutionTrace, GraphAnnotation
            from claasp.semantics import CONCRETE

            annotation = GraphAnnotation.from_values(
                primitive, CONCRETE, lane_values, output=output
            )
            provenance = ResultProvenance.for_primitive(primitive, self.identity)
            results.append(
                EvaluationResult(
                    lane_values | binding_caches[lane],
                    output,
                    ExecutionTrace(annotation),
                    provenance,
                )
            )
        return BatchEvaluationResult(
            tuple(results), ResultProvenance.for_primitive(primitive, self.identity)
        )

    def _evaluate_component(self, component, inputs, batch_size):
        scalar = self._scalar_evaluator
        try:
            handler = scalar._handlers[type(component)]
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
