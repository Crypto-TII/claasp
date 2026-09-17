"""Sage-independent typed core for the next major CLAASP release."""

from claasp_next.graph import (
    CompositeBuilder, CompositeDefinition, CompositeInstance, CompositeOutputs,
    Primitive, Component,
    InputVisibility, Port, PrimitiveInput, PrimitiveKind, Round, Selection,
    ValueType, public_input, secret_input,
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
from claasp_next.composites import (
    AESKeySchedule, AESRound, AESSubstitutionLayer, ChaChaQuarterRound, ParallelSBoxLayer,
)
from claasp_next.provenance import DriverIdentity, DriverKind, ResultProvenance

__all__ = [
    "BinaryExtensionField",
    "Bit",
    "BatchEvaluationResult",
    "BatchEvaluator",
    "BatchExecutionDriver",
    "AESKeySchedule",
    "AESRound",
    "AESSubstitutionLayer",
    "CompositeBuilder",
    "CompositeDefinition",
    "CompositeInstance",
    "CompositeOutputs",
    "ChaChaQuarterRound",
    "Primitive",
    "Component",
    "EvaluationResult",
    "DriverIdentity",
    "DriverKind",
    "InputVisibility",
    "Port",
    "ParallelSBoxLayer",
    "PrimitiveInput",
    "PrimitiveKind",
    "PrimeField",
    "Round",
    "ResultProvenance",
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
    "public_input",
    "secret_input",
]
