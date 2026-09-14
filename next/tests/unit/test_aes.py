from claasp_next.primitives import AES128
from claasp_next.domains import BinaryExtensionField
from claasp_next.representations.execution import BatchEvaluator, ScalarEvaluator, TransposedBatchEvaluator


PLAINTEXT = tuple(bytes.fromhex("00112233445566778899aabbccddeeff"))
KEY = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
CIPHERTEXT = tuple(bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))


def test_aes128_matches_fips_197_known_answer_vector_and_uses_field_bytes():
    primitive = AES128()
    result = ScalarEvaluator().evaluate(primitive, {"plaintext": PLAINTEXT, "key": KEY})

    assert result.output == CIPHERTEXT
    assert primitive.input("plaintext").value_type.domain == BinaryExtensionField(8, 0x11B)
    assert primitive.input("plaintext").value_type.unit_count == 16


def test_aes128_matches_fips_first_round_intermediate_values():
    result = ScalarEvaluator().evaluate(
        AES128(number_of_rounds=1), {"plaintext": PLAINTEXT, "key": KEY}
    )

    assert bytes(result.value_of("initial_add_round_key")).hex() == "00102030405060708090a0b0c0d0e0f0"
    assert bytes(result.value_of("sub_bytes_1")).hex() == "63cab7040953d051cd60e0e7ba70e18c"
    assert bytes(result.value_of("shift_rows_1")).hex() == "6353e08c0960e104cd70b751bacad0e7"
    assert bytes(result.value_of("mix_columns_1")).hex() == "5f72641557f5bc92f7be3b291db9f91a"
    assert bytes(result.value_of("round_key_1")).hex() == "d6aa74fdd2af72fadaa678f1d6ab76fe"
    assert bytes(result.output).hex() == "89d810e8855ace682d1843d8cb128fe4"


def test_aes128_batch_backends_match_scalar_reference():
    primitive = AES128(number_of_rounds=2)
    inputs = {
        "plaintext": (PLAINTEXT, (0,) * 16),
        "key": (KEY, tuple(reversed(KEY))),
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
