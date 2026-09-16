"""Sage-independent typed core for the next major CLAASP release."""

from claasp_next.graph import (
    CompositeBuilder, CompositeDefinition, CompositeInstance, Primitive, Component,
    Port, Round, Selection, ValueType,
)
from claasp_next.domains import BinaryExtensionField, Bit, PrimeField, Word
from claasp_next.representations.execution import (
    BatchEvaluationResult,
    BatchEvaluator,
    BatchExecutionDriver,
    EvaluationResult,
    ScalarEvaluator,
    ScalarExecutionDriver,
    TransposedBatchEvaluator,
    TransposedBatchExecutionDriver,
)
from claasp_next.encoding import bits_from_int, int_from_bits, int_from_units, units_from_int
from claasp_next.composites import ChaChaQuarterRound, ParallelSBoxLayer

__all__ = [
    "BinaryExtensionField",
    "Bit",
    "BatchEvaluationResult",
    "BatchEvaluator",
    "BatchExecutionDriver",
    "CompositeBuilder",
    "CompositeDefinition",
    "CompositeInstance",
    "ChaChaQuarterRound",
    "Primitive",
    "Component",
    "EvaluationResult",
    "Port",
    "ParallelSBoxLayer",
    "PrimeField",
    "Round",
    "ScalarEvaluator",
    "ScalarExecutionDriver",
    "Selection",
    "TransposedBatchEvaluator",
    "TransposedBatchExecutionDriver",
    "ValueType",
    "Word",
    "bits_from_int",
    "int_from_bits",
    "int_from_units",
    "units_from_int",
]
