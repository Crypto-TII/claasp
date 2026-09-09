"""Correctness-first batch evaluation."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp_next.core import Cipher
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
