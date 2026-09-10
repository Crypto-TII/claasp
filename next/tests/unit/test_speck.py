from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.evaluators import BatchEvaluator, ScalarEvaluator, TransposedBatchEvaluator


PLAINTEXT = (0x3B726574, 0x7475432D)
KEY = (0x1B1A1918, 0x13121110, 0x0B0A0908, 0x03020100)
CIPHERTEXT = (0x8C6FA548, 0x454E028B)


def test_speck64_128_matches_designers_known_answer_vector():
    result = ScalarEvaluator().evaluate(
        SpeckBlockCipher(), {"plaintext": PLAINTEXT, "key": KEY}
    )
    assert result.output == CIPHERTEXT


def test_speck_reduced_round_matches_first_published_intermediate_state():
    result = ScalarEvaluator().evaluate(
        SpeckBlockCipher(number_of_rounds=1), {"plaintext": PLAINTEXT, "key": KEY}
    )
    assert result.output == (0xEBB2B492, 0x4818ADF9)


def test_speck_batch_backends_match_scalar_reference():
    cipher = SpeckBlockCipher(number_of_rounds=3)
    inputs = {"plaintext": (PLAINTEXT, (0, 0)), "key": (KEY, KEY)}
    expected = tuple(
        ScalarEvaluator().evaluate(cipher, {
            "plaintext": inputs["plaintext"][lane], "key": inputs["key"][lane]
        }).output
        for lane in range(2)
    )
    assert BatchEvaluator().evaluate(cipher, inputs).outputs == expected
    assert TransposedBatchEvaluator().evaluate(cipher, inputs).outputs == expected
