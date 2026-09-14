import pytest

from claasp_next import bits_from_int, int_from_bits
from claasp_next.primitives import Present80
from claasp_next.representations.execution import BatchEvaluator, ScalarEvaluator, TransposedBatchEvaluator


@pytest.mark.parametrize(
    ("plaintext", "key", "ciphertext"),
    [
        (0x0000000000000000, 0x00000000000000000000, 0x5579C1387B228445),
        (0x0000000000000000, 0xFFFFFFFFFFFFFFFFFFFF, 0xE72C46C0F5945049),
        (0xFFFFFFFFFFFFFFFF, 0x00000000000000000000, 0xA112FFC72F68417B),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFF, 0x3333DCD3213210D2),
    ],
)
def test_present80_matches_designers_test_vectors(plaintext, key, ciphertext):
    primitive = Present80()
    result = ScalarEvaluator().evaluate(
        primitive,
        {"plaintext": bits_from_int(plaintext, 64), "key": bits_from_int(key, 80)},
    )
    assert int_from_bits(result.output) == ciphertext
    assert len(primitive.rounds) == 31


def test_present80_batch_backends_match_scalar_reference():
    primitive = Present80(number_of_rounds=2)
    inputs = {
        "plaintext": (bits_from_int(0, 64), bits_from_int((1 << 64) - 1, 64)),
        "key": (bits_from_int(0, 80), bits_from_int((1 << 80) - 1, 80)),
    }
    expected = tuple(
        ScalarEvaluator().evaluate(
            primitive,
            {"plaintext": inputs["plaintext"][lane], "key": inputs["key"][lane]},
        ).output
        for lane in range(2)
    )
    assert BatchEvaluator().evaluate(primitive, inputs).outputs == expected
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected
