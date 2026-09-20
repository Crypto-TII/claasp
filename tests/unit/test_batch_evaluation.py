import pytest

from claasp import (
    BatchEvaluator,
    Bit,
    Primitive,
    ScalarEvaluator,
    TransposedBatchEvaluator,
    ValueType,
)
from claasp.primitives import MiMC, Poseidon


def test_mimc_batch_matches_individual_scalar_evaluations():
    primitive = MiMC(17, 3, (1, 2, 4))
    states = ((0,), (1,), (5,), (16,))

    batch_result = BatchEvaluator().evaluate(primitive, {"state": states})
    scalar_outputs = tuple(
        ScalarEvaluator().evaluate(primitive, {"state": state}).output for state in states
    )

    assert batch_result.outputs == scalar_outputs
    assert batch_result.values_of("power_0_2") == tuple(
        ScalarEvaluator().evaluate(primitive, {"state": state}).value_of("power_0_2")
        for state in states
    )
    assert batch_result.realization is primitive.realization
    assert batch_result.execution_engine.name == "python_batch"


def test_poseidon_batch_matches_scalar_evaluation():
    primitive = Poseidon(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    states = ((0, 1), (2, 3), (16, 16))

    result = BatchEvaluator().evaluate(primitive, {"state": states})

    assert result.outputs == tuple(
        ScalarEvaluator().evaluate(primitive, {"state": state}).output for state in states
    )


def test_batch_inputs_must_have_equal_lengths():
    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("two_inputs", {"left": value_type, "right": value_type})

    with pytest.raises(ValueError, match="same number"):
        BatchEvaluator().evaluate(
            primitive,
            {"left": ((0,), (1,)), "right": ((0,),)},
        )


def test_empty_batch_is_supported():
    primitive = MiMC(17, 3, (1,))

    result = BatchEvaluator().evaluate(primitive, {"state": ()})

    assert result.items == ()
    assert result.outputs == ()


@pytest.mark.parametrize("evaluator", [BatchEvaluator(), TransposedBatchEvaluator()])
def test_batch_backends_have_identical_poseidon_values(evaluator):
    primitive = Poseidon(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    states = ((0, 1), (2, 3), (16, 16))
    reference = BatchEvaluator().evaluate(primitive, {"state": states})
    result = evaluator.evaluate(primitive, {"state": states})

    assert result.outputs == reference.outputs
    assert result.values_of("linear_map_2_4") == reference.values_of("linear_map_2_4")
    expected_engine = (
        "python_transposed_batch"
        if isinstance(evaluator, TransposedBatchEvaluator)
        else "python_batch"
    )
    assert result.execution_engine.name == expected_engine


def test_transposed_backend_supports_empty_batches():
    primitive = MiMC(17, 3, (1,))
    assert TransposedBatchEvaluator().evaluate(primitive, {"state": ()}).items == ()
