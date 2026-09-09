import pytest

from claasp_next import (
    BatchEvaluator,
    Bit,
    Cipher,
    ScalarEvaluator,
    TransposedBatchEvaluator,
    ValueType,
)
from claasp_next.ciphers import MiMCPermutation, PoseidonPermutation


def test_mimc_batch_matches_individual_scalar_evaluations():
    cipher = MiMCPermutation(17, 3, (1, 2, 4))
    states = ((0,), (1,), (5,), (16,))

    batch_result = BatchEvaluator().evaluate(cipher, {"state": states})
    scalar_outputs = tuple(
        ScalarEvaluator().evaluate(cipher, {"state": state}).output
        for state in states
    )

    assert batch_result.outputs == scalar_outputs
    assert batch_result.values_of("power_0_2") == tuple(
        ScalarEvaluator().evaluate(cipher, {"state": state}).value_of("power_0_2")
        for state in states
    )


def test_poseidon_batch_matches_scalar_evaluation():
    cipher = PoseidonPermutation(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    states = ((0, 1), (2, 3), (16, 16))

    result = BatchEvaluator().evaluate(cipher, {"state": states})

    assert result.outputs == tuple(
        ScalarEvaluator().evaluate(cipher, {"state": state}).output
        for state in states
    )


def test_batch_inputs_must_have_equal_lengths():
    value_type = ValueType(Bit(), (1,))
    cipher = Cipher("two_inputs", {"left": value_type, "right": value_type})

    with pytest.raises(ValueError, match="same number"):
        BatchEvaluator().evaluate(
            cipher,
            {"left": ((0,), (1,)), "right": ((0,),)},
        )


def test_empty_batch_is_supported():
    cipher = MiMCPermutation(17, 3, (1,))

    result = BatchEvaluator().evaluate(cipher, {"state": ()})

    assert result.items == ()
    assert result.outputs == ()


@pytest.mark.parametrize("evaluator", [BatchEvaluator(), TransposedBatchEvaluator()])
def test_batch_backends_have_identical_poseidon_values(evaluator):
    cipher = PoseidonPermutation(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1, 2), (3, 4), (5, 6)),
        linear_layer=((1, 1), (1, 2)),
    )
    states = ((0, 1), (2, 3), (16, 16))
    reference = BatchEvaluator().evaluate(cipher, {"state": states})
    result = evaluator.evaluate(cipher, {"state": states})

    assert result.outputs == reference.outputs
    assert result.values_of("linear_map_2_4") == reference.values_of("linear_map_2_4")


def test_transposed_backend_supports_empty_batches():
    cipher = MiMCPermutation(17, 3, (1,))
    assert TransposedBatchEvaluator().evaluate(cipher, {"state": ()}).items == ()
