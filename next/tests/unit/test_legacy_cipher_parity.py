"""Semantic ports of the legacy AES, PRESENT, and Speck regression tests."""

import pytest

from claasp_next import bits_from_int, int_from_bits
from claasp_next.components import Add, BinaryAffineMap, Power, Rotate, SBox
from claasp_next.domains import BinaryExtensionField, Bit, Word
from claasp_next.primitives import AES, Present, Speck
from claasp_next.representations.execution import BatchEvaluator, ScalarEvaluator

PRESENT_SBOX = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)


def _present_reference(plaintext, key, key_size, rounds):
    """Independent integer transcription of the PRESENT specification."""

    state = plaintext
    key_mask = (1 << key_size) - 1
    for round_number in range(1, rounds + 1):
        state ^= key >> (key_size - 64)
        state = sum(PRESENT_SBOX[(state >> (4 * i)) & 0xF] << (4 * i) for i in range(16))
        permuted = 0
        for input_position in range(64):
            output_position = 63 if input_position == 63 else 16 * input_position % 63
            permuted |= ((state >> input_position) & 1) << output_position
        state = permuted
        key = ((key << 61) & key_mask) | (key >> (key_size - 61))
        if key_size == 80:
            key = (key & ~(0xF << 76)) | (PRESENT_SBOX[key >> 76] << 76)
            key ^= round_number << 15
        else:
            key = (
                (key & ~((1 << 128) - (1 << 120)))
                | (PRESENT_SBOX[(key >> 124) & 0xF] << 124)
                | (PRESENT_SBOX[(key >> 120) & 0xF] << 120)
            )
            key ^= round_number << 62
    return state ^ (key >> (key_size - 64))


AES_VECTORS = (
    (
        128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        (
            ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
            ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
        ),
    ),
    (
        192,
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        (
            ("6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e"),
            ("f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e"),
        ),
    ),
    (
        256,
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        (
            ("6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
            ("ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"),
            ("30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"),
            ("f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"),
        ),
    ),
)


@pytest.mark.parametrize(("key_size", "key_hex", "vectors"), AES_VECTORS)
def test_aes_preserves_all_legacy_sp800_38a_vectors(key_size, key_hex, vectors):
    primitive = AES(key_size)
    evaluator = ScalarEvaluator()
    key = tuple(bytes.fromhex(key_hex))
    for plaintext_hex, ciphertext_hex in vectors:
        result = evaluator.evaluate(
            primitive, {"plaintext": tuple(bytes.fromhex(plaintext_hex)), "key": key}
        )
        assert bytes(result.output).hex() == ciphertext_hex


@pytest.mark.parametrize(("key_size", "key_hex", "vectors"), AES_VECTORS)
def test_aes_realizations_preserve_all_vectors_and_each_other(key_size, key_hex, vectors):
    lookup = AES(key_size, realization="lookup")
    algebraic = AES(key_size, realization="algebraic")
    key = int(key_hex, 16)
    for plaintext_hex, ciphertext_hex in vectors:
        plaintext = int(plaintext_hex, 16)
        expected = int(ciphertext_hex, 16)
        assert lookup.evaluate(plaintext, key) == expected
        assert algebraic.evaluate(plaintext, key) == expected
    assert any(isinstance(component, SBox) for component in lookup.components)
    assert not any(isinstance(component, Power) for component in lookup.components)
    assert any(isinstance(component, Power) for component in algebraic.components)
    assert any(isinstance(component, BinaryAffineMap) for component in algebraic.components)
    assert not any(isinstance(component, SBox) for component in algebraic.components)


def test_aes_capability_selection_is_explicit_and_deterministic():
    assert AES.for_capabilities({"sbox_semantics"}).realization.name == "lookup"
    assert AES.for_capabilities({"algebraic_semantics"}).realization.name == "algebraic"
    with pytest.raises(ValueError, match="no AES realization"):
        AES.for_capabilities({"cuda"})


def test_aes_batch_realizations_are_equivalent_and_results_record_them():
    plaintexts = tuple(
        tuple(bytes.fromhex(value))
        for value in (
            "00112233445566778899aabbccddeeff",
            "6bc1bee22e409f96e93d7e117393172a",
        )
    )
    keys = (tuple(range(16)),) * 2
    outputs = []
    for name in ("lookup", "algebraic"):
        result = BatchEvaluator().evaluate(
            AES(realization=name), {"plaintext": plaintexts, "key": keys}
        )
        assert all(item.realization.name == name for item in result.items)
        outputs.append(result.outputs)
    assert outputs[0] == outputs[1]


def test_aes_rejects_unknown_realization():
    with pytest.raises(ValueError, match="realization must be one of"):
        AES(realization="bitsliced")


@pytest.mark.parametrize(("key_size", "rounds", "nk"), ((128, 10, 4), (192, 12, 6), (256, 14, 8)))
def test_aes_preserves_legacy_configuration_semantics(key_size, rounds, nk):
    primitive = AES(key_size)
    assert primitive.family_name == "aes"
    # The v5 graph represents initial AddRoundKey as an explicit round zero.
    assert len(primitive.rounds) == rounds + 1
    assert primitive.Nk == nk
    assert primitive.Nr == rounds
    assert primitive.input("key").value_type.encoded_bit_size == key_size
    assert primitive.output.value_type.encoded_bit_size == 128
    assert primitive.input("plaintext").value_type.domain == BinaryExtensionField(8, 0x11B)
    assert isinstance(primitive.component(primitive.initial_state.owner_id), Add)
    assert len(primitive.round_keys) == rounds + 1


def test_aes_rejects_legacy_invalid_key_size():
    with pytest.raises(ValueError, match="unsupported primitive configuration"):
        AES(512)


def test_aes_retains_the_three_legacy_parameter_configurations():
    from claasp_next.primitives.block_ciphers.aes import PARAMETERS_CONFIGURATION_LIST

    assert PARAMETERS_CONFIGURATION_LIST == (
        {"key_bit_size": 128, "number_of_rounds": 10},
        {"key_bit_size": 192, "number_of_rounds": 12},
        {"key_bit_size": 256, "number_of_rounds": 14},
    )


@pytest.mark.parametrize(
    ("key_size", "plaintext", "key", "ciphertext"),
    (
        (80, 0x42C20FD3B586879E, 0x98EDEAFC899338C45FAD, 0xA1E546AE14C26565),
        (128, 0x42C20FD3B586879E, 0x687DED3B3C85B3F35B1009863E2A8CBF, 0x82F5B82CB02CD1B6),
    ),
)
def test_present_preserves_legacy_variants_and_exact_vectors(key_size, plaintext, key, ciphertext):
    primitive = Present(key_size)
    inputs = {"plaintext": bits_from_int(plaintext, 64), "key": bits_from_int(key, key_size)}
    scalar = ScalarEvaluator().evaluate(primitive, inputs)
    batch = BatchEvaluator().evaluate(primitive, {name: (value,) for name, value in inputs.items()})
    assert int_from_bits(scalar.output) == ciphertext
    assert batch.outputs == (scalar.output,)
    assert primitive.family_name == "present"
    assert len(primitive.rounds) == 31
    assert primitive.input("key").value_type.domain == Bit()
    assert primitive.input("key").value_type.encoded_bit_size == key_size
    assert isinstance(primitive.rounds[0].components[0], Add)


def test_present_preserves_reduced_round_configuration():
    primitive = Present(number_of_rounds=4)
    assert len(primitive.rounds) == 4
    assert primitive.rounds[3].components[0].component_id == "add_round_key_4"


@pytest.mark.parametrize(
    ("key_size", "plaintext", "key", "rounds"),
    (
        (80, 0x0123456789ABCDEF, 0x00112233445566778899, 2),
        (80, 0xFEDCBA9876543210, 0xFFEEDDCCBBAA99887766, 7),
        (128, 0x0123456789ABCDEF, 0x00112233445566778899AABBCCDDEEFF, 2),
        (128, 0xFEDCBA9876543210, 0xFFEEDDCCBBAA99887766554433221100, 7),
    ),
)
def test_present_matches_independent_reference_transcription(key_size, plaintext, key, rounds):
    result = ScalarEvaluator().evaluate(
        Present(key_size, rounds),
        {
            "plaintext": bits_from_int(plaintext, 64),
            "key": bits_from_int(key, key_size),
        },
    )
    assert int_from_bits(result.output) == _present_reference(plaintext, key, key_size, rounds)


@pytest.mark.parametrize(
    ("block_size", "key_size", "plaintext", "key", "ciphertext"),
    (
        (32, 64, 0x6574694C, 0x1918111009080100, 0xA86842F2),
        (64, 96, 0x74614620736E6165, 0x131211100B0A090803020100, 0x9F7952EC4175946C),
    ),
)
def test_speck_preserves_legacy_variants_and_exact_vectors(
    block_size, key_size, plaintext, key, ciphertext
):
    word_size = block_size // 2
    word_mask = (1 << word_size) - 1
    key_word_count = key_size // word_size
    inputs = {
        "plaintext": (plaintext >> word_size, plaintext & word_mask),
        "key": tuple(
            (key >> (word_size * (key_word_count - 1 - position))) & word_mask
            for position in range(key_word_count)
        ),
    }
    primitive = Speck(block_size, key_size)
    scalar = ScalarEvaluator().evaluate(primitive, inputs)
    batch = BatchEvaluator().evaluate(primitive, {name: (value,) for name, value in inputs.items()})
    assert (scalar.output[0] << word_size) | scalar.output[1] == ciphertext
    assert batch.outputs == (scalar.output,)
    assert primitive.family_name == "speck"
    assert primitive.input("plaintext").value_type.domain == Word(word_size)
    assert primitive.input("key").value_type.encoded_bit_size == key_size
    assert primitive.output.value_type.encoded_bit_size == block_size
    assert isinstance(primitive.rounds[0].components[0], Rotate)


def test_speck_preserves_legacy_defaults_and_reduced_rounds():
    default = Speck()
    reduced = Speck(number_of_rounds=4)
    assert len(default.rounds) == 22
    assert default.input("plaintext").value_type.encoded_bit_size == 32
    assert default.input("key").value_type.encoded_bit_size == 64
    assert len(reduced.rounds) == 4
