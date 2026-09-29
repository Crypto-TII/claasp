import pytest

from claasp.primitives import Speck
from claasp.representations.execution import (
    BatchEvaluator,
    ScalarEvaluator,
    TransposedBatchEvaluator,
)

PLAINTEXT = (0x3B726574, 0x7475432D)
KEY = (0x1B1A1918, 0x13121110, 0x0B0A0908, 0x03020100)
CIPHERTEXT = (0x8C6FA548, 0x454E028B)


def test_speck64_128_matches_designers_known_answer_vector():
    result = ScalarEvaluator().evaluate(
        Speck(block_bit_size=64, key_bit_size=128),
        {"plaintext": PLAINTEXT, "key": KEY},
    )
    assert result.output == CIPHERTEXT


def test_speck_reduced_round_matches_first_published_intermediate_state():
    result = ScalarEvaluator().evaluate(
        Speck(block_bit_size=64, key_bit_size=128, number_of_rounds=1),
        {"plaintext": PLAINTEXT, "key": KEY},
    )
    assert result.output == (0xEBB2B492, 0x4818ADF9)


def test_speck_batch_backends_match_scalar_reference():
    primitive = Speck(block_bit_size=64, key_bit_size=128, number_of_rounds=3)
    inputs = {"plaintext": (PLAINTEXT, (0, 0)), "key": (KEY, KEY)}
    expected = tuple(
        ScalarEvaluator()
        .evaluate(primitive, {"plaintext": inputs["plaintext"][lane], "key": inputs["key"][lane]})
        .output
        for lane in range(2)
    )
    assert BatchEvaluator().evaluate(primitive, inputs).outputs == expected
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected


@pytest.mark.parametrize(
    "block_size,key_size,plaintext,key,ciphertext",
    (
        (32, 64, 0x6574694C, 0x1918111009080100, 0xA86842F2),
        (64, 96, 0x74614620736E6165, 0x131211100B0A090803020100, 0x9F7952EC4175946C),
    ),
)
def test_speck_preserves_legacy_catalogue_vectors(block_size, key_size, plaintext, key, ciphertext):
    assert Speck(block_size, key_size).evaluate(plaintext, key) == ciphertext
