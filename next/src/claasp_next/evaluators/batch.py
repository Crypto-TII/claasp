"""Correctness-first batch evaluation."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp_next.core import Cipher
from claasp_next.components.algebraic import Add, LinearMap, Multiply, Power
from claasp_next.components.structural import Concatenate, Constant, Identity, Permutation
from claasp_next.components.substitution import BitVectorSBox, SBox
from claasp_next.components.word import ModularAdd, Rotate, Xor
from claasp_next.evaluators.scalar import EvaluationResult, RuntimeValue, ScalarEvaluator


@dataclass(frozen=True, slots=True)
class BatchEvaluationResult:
    """One scalar evaluation result for every item in a batch."""

    items: tuple[EvaluationResult, ...]

    @property
    def outputs(self) -> tuple[RuntimeValue | None, ...]:
        """Return declared cipher outputs in batch order.

        EXAMPLES::

            >>> from claasp_next.ciphers import MiMCPermutation
            >>> from claasp_next.evaluators import BatchEvaluator
            >>> cipher = MiMCPermutation(17, 3, (1, 2, 4))
            >>> BatchEvaluator().evaluate(cipher, {"state": ((5,), (7,))}).outputs
            ((5,), (0,))
        """

        return tuple(item.output for item in self.items)

    def values_of(self, source_id: str) -> tuple[RuntimeValue, ...]:
        """Return one internal source value per batch item."""

        return tuple(item.value_of(source_id) for item in self.items)


class BatchEvaluator:
    """Evaluate multiple inputs with exactly the scalar backend semantics.

    This evaluator establishes the public batch contract and is the reference
    against which optimized backends are tested. It intentionally favors
    correctness over throughput.

    EXAMPLES::

        >>> from claasp_next.ciphers import MiMCPermutation
        >>> cipher = MiMCPermutation(17, 3, (1,))
        >>> BatchEvaluator().evaluate(cipher, {"state": ((0,), (1,), (2,))}).outputs
        ((1,), (8,), (10,))
    """

    def __init__(self, scalar_evaluator: ScalarEvaluator | None = None) -> None:
        self._scalar_evaluator = scalar_evaluator or ScalarEvaluator()

    def evaluate(
        self,
        cipher: Cipher,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")

        expected_names = set(cipher.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"cipher inputs do not match: missing={missing}, unexpected={unexpected}")

        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every cipher input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        results = []
        for item_index in range(batch_size):
            item_inputs = {name: inputs[name][item_index] for name in cipher.inputs}
            results.append(self._scalar_evaluator.evaluate(cipher, item_inputs))
        return BatchEvaluationResult(tuple(results))


class TransposedBatchEvaluator(BatchEvaluator):
    """Evaluate a batch in one graph traversal using dependency-free tuples.

    The backend keeps arbitrary-size field elements as Python integers, so it
    is suitable for fields such as BN254 without a NumPy dependency or
    machine-word truncation. Its result is identical to :class:`BatchEvaluator`.

    EXAMPLES::

        >>> from claasp_next.ciphers import MiMCPermutation
        >>> cipher = MiMCPermutation(17, 3, (1,))
        >>> TransposedBatchEvaluator().evaluate(
        ...     cipher, {"state": ((0,), (1,), (2,))}
        ... ).outputs
        ((1,), (8,), (10,))
    """

    def evaluate(
        self,
        cipher: Cipher,
        inputs: Mapping[str, Sequence[Sequence[int]]],
    ) -> BatchEvaluationResult:
        if not isinstance(cipher, Cipher):
            raise TypeError("cipher must be a Cipher")
        expected_names = set(cipher.inputs)
        actual_names = set(inputs)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names)
            unexpected = sorted(actual_names - expected_names)
            raise ValueError(f"cipher inputs do not match: missing={missing}, unexpected={unexpected}")
        batch_sizes = {len(values) for values in inputs.values()}
        if len(batch_sizes) > 1:
            raise ValueError("every cipher input must contain the same number of batch items")
        batch_size = batch_sizes.pop() if batch_sizes else 0

        values: dict[str, tuple[RuntimeValue, ...]] = {}
        for name, port in cipher.inputs.items():
            batch = tuple(tuple(item) for item in inputs[name])
            for item in batch:
                self._scalar_evaluator._validate_value(
                    name, item, port.value_type.unit_count, port.value_type.domain
                )
            values[name] = batch

        for component in cipher.components:
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
            if cipher.output is not None:
                output = tuple(
                    lane_values[cipher.output.source.owner_id][position]
                    for position in cipher.output.positions
                )
            results.append(EvaluationResult(lane_values, output))
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
            ModularAdd: scalar._evaluate_modular_add,
            Rotate: scalar._evaluate_rotate,
            Xor: scalar._evaluate_xor,
            SBox: scalar._evaluate_sbox,
            BitVectorSBox: scalar._evaluate_bit_vector_sbox,
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
