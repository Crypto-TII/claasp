"""Execution backends for typed CLAASP graphs."""

from claasp_next.evaluators.batch import BatchEvaluationResult, BatchEvaluator, TransposedBatchEvaluator
from claasp_next.evaluators.scalar import EvaluationResult, ScalarEvaluator

__all__ = [
    "BatchEvaluationResult",
    "BatchEvaluator",
    "EvaluationResult",
    "ScalarEvaluator",
    "TransposedBatchEvaluator",
]
