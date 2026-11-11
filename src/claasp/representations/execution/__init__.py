"""Direct concrete execution representations and Python drivers."""

from claasp._catalogue_metadata import _entry
from claasp.representations.execution.batch import (
    BatchEvaluationResult,
    BatchEvaluator,
    BatchExecutionDriver,
    TransposedBatchEvaluator,
    TransposedBatchExecutionDriver,
)
from claasp.representations.execution.boolean_degree import (
    BooleanDegreeEvaluator,
    BooleanDegreeResult,
)
from claasp.representations.execution.continuous import (
    ContinuousEvaluationResult,
    ContinuousExecutionDriver,
    ContinuousXorDifferentialExecutionDriver,
)
from claasp.representations.execution.scalar import (
    EvaluationResult,
    ScalarEvaluator,
    ScalarExecutionDriver,
)
from claasp.representations.execution.symbolic_boolean import (
    BooleanSymbolicEvaluator,
    BooleanSymbolicResult,
)

__all__ = [
    "BatchEvaluationResult",
    "BatchEvaluator",
    "BatchExecutionDriver",
    "BooleanDegreeEvaluator",
    "BooleanDegreeResult",
    "BooleanSymbolicEvaluator",
    "BooleanSymbolicResult",
    "ContinuousEvaluationResult",
    "ContinuousExecutionDriver",
    "ContinuousXorDifferentialExecutionDriver",
    "EvaluationResult",
    "ScalarEvaluator",
    "ScalarExecutionDriver",
    "TransposedBatchEvaluator",
    "TransposedBatchExecutionDriver",
]


__catalogue__ = (
    _entry(
        "driver",
        ScalarExecutionDriver,
        name="python_scalar",
        kind="execution_engine",
        availability="builtin",
    ),
    _entry(
        "driver",
        BatchExecutionDriver,
        name="python_batch",
        kind="execution_engine",
        availability="builtin",
    ),
    _entry(
        "driver",
        TransposedBatchExecutionDriver,
        name="python_transposed_batch",
        kind="execution_engine",
        availability="builtin",
    ),
    _entry(
        "representation",
        BooleanDegreeEvaluator,
        name="boolean_degree_bounds",
        kind="analysis",
        components=(
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "ModularAdd",
            "Rotate",
            "Xor",
        ),
        domains=("Bit", "Word"),
        drivers=(),
        scope="generic_graph",
    ),
    _entry(
        "representation",
        BooleanSymbolicEvaluator,
        name="boolean_symbolic_anf",
        kind="analysis",
        components=(
            "BitwiseAnd",
            "BitwiseNot",
            "BitwiseOr",
            "Constant",
            "ModularAdd",
            "Rotate",
            "Xor",
        ),
        domains=("Bit", "Word"),
        drivers=(),
        scope="generic_graph",
    ),
)
