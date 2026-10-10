import pytest

from claasp.composites import AESKeySchedule, AESRound
from claasp.domains import BinaryExtensionField
from claasp.primitives import AES, AES128, CustomAES
from claasp.representations.execution import (
    BatchEvaluator,
    ScalarEvaluator,
    TransposedBatchEvaluator,
)

PLAINTEXT = tuple(bytes.fromhex("00112233445566778899aabbccddeeff"))
KEY = tuple(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
CIPHERTEXT = tuple(bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"))


def test_aes128_matches_fips_197_known_answer_vector_and_uses_field_bytes():
    primitive = AES128()
    result = ScalarEvaluator().evaluate(primitive, {"plaintext": PLAINTEXT, "key": KEY})

    assert result.output == CIPHERTEXT
    assert primitive.graph.input("plaintext").value_type.domain == BinaryExtensionField(8, 0x11B)
    assert primitive.graph.input("plaintext").value_type.unit_count == 16


def test_aes128_matches_fips_first_round_intermediate_values():
    primitive = AES128(number_of_rounds=1)
    result = ScalarEvaluator().evaluate(primitive, {"plaintext": PLAINTEXT, "key": KEY})

    def value(selection):
        selection = selection.select_all() if hasattr(selection, "select_all") else selection
        source = result.value_of(selection.source.owner_id)
        return tuple(source[position] for position in selection.positions)

    intermediates = primitive.graph.intermediate_outputs[0]
    assert bytes(value(primitive._initial_state)).hex() == "00102030405060708090a0b0c0d0e0f0"
    assert bytes(value(intermediates["sub_bytes"])).hex() == "63cab7040953d051cd60e0e7ba70e18c"
    assert bytes(value(intermediates["shift_rows"])).hex() == "6353e08c0960e104cd70b751bacad0e7"
    assert bytes(value(intermediates["mix_columns"])).hex() == "5f72641557f5bc92f7be3b291db9f91a"
    assert bytes(value(primitive.graph.round_keys[1])).hex() == "d6aa74fdd2af72fadaa678f1d6ab76fe"
    assert bytes(result.output).hex() == "89d810e8855ace682d1843d8cb128fe4"


def test_aes128_batch_backends_match_scalar_reference():
    primitive = AES128(number_of_rounds=2)
    inputs = {
        "plaintext": (PLAINTEXT, (0,) * 16),
        "key": (KEY, tuple(reversed(KEY))),
    }
    expected = tuple(
        ScalarEvaluator()
        .evaluate(
            primitive,
            {"plaintext": inputs["plaintext"][lane], "key": inputs["key"][lane]},
        )
        .output
        for lane in range(2)
    )

    assert BatchEvaluator().evaluate(primitive, inputs).outputs == expected
    assert TransposedBatchEvaluator().evaluate(primitive, inputs).outputs == expected


def test_aes_key_schedule_and_round_are_independently_evaluable_blocks():
    schedule = AESKeySchedule(128, 1)
    round_key = schedule.evaluate(int.from_bytes(bytes(KEY), "big"), output="round_key_1")
    assert round_key == 0xD6AA74FDD2AF72FADAA678F1D6AB76FE

    round_block = AESRound(mix_columns=True)
    assert (
        round_block.evaluate(0x00102030405060708090A0B0C0D0E0F0, round_key)
        == 0x89D810E8855ACE682D1843D8CB128FE4
    )


def test_custom_aes_records_changes_and_supports_sbox_and_layer_studies():
    canonical = AES(number_of_rounds=2)
    identity_sbox = CustomAES(sbox_table=tuple(range(256)), number_of_rounds=2)
    no_mix = CustomAES(include_mix_columns=False, number_of_rounds=2)
    plaintext = int.from_bytes(bytes(PLAINTEXT), "big")
    key = int.from_bytes(bytes(KEY), "big")

    assert identity_sbox.evaluate(plaintext, key) != canonical.evaluate(plaintext, key)
    assert no_mix.evaluate(plaintext, key) != canonical.evaluate(plaintext, key)
    assert not any(type(component).__name__ == "LinearMap" for component in no_mix.graph.components)
    assert dict(identity_sbox.provenance) == {
        "derived_from": "AES",
        "modifications": "replaced AES S-box in rounds and key schedule",
    }


def test_aes_evaluate_many_accepts_shared_or_independent_keys():
    aes = AES()
    plaintexts = [0x00112233445566778899AABBCCDDEEFF, 0]
    keys = [0x000102030405060708090A0B0C0D0E0F, 0]

    shared_key = aes.evaluate_many(plaintext=plaintexts, key=keys[0])
    independent_keys = aes.evaluate_many(plaintext=plaintexts, key=keys)

    assert shared_key == (
        0x69C4E0D86A7B0430D8CDB78070B4C55A,
        0xC6A13B37878F5B826F4F8162A1C8D879,
    )
    assert independent_keys == (
        0x69C4E0D86A7B0430D8CDB78070B4C55A,
        0x66E94BD4EF8A2C3B884CFA59CA342B2E,
    )


def test_aes_evaluate_many_validates_named_batch_inputs():
    aes = AES()

    with pytest.raises(ValueError, match="same length"):
        aes.evaluate_many(plaintext=[0, 1], key=[0])
    with pytest.raises(ValueError, match="missing=.*key"):
        aes.evaluate_many(plaintext=[0, 1])
