import numpy as np
import pytest

from claasp.cipher_modules.rotational_diffusion_tests import RotationalTests
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.ciphers.single_component_ciphers.identity_cipher import IdentityCipher


def test_rotate_selected_input_rotates_each_word_to_the_left():
    values = np.array([[0x81], [0x03]], dtype=np.uint8)
    rotated = RotationalTests._rotate_selected_input([values], 0, 16, 8, 1)[0]
    assert rotated.tolist() == [[0x03], [0x06]]


def test_unpack_output_drops_left_byte_padding():
    values = np.array([[0x01, 0xAA]], dtype=np.uint8)

    unpacked = RotationalTests._unpack_output(values, output_bit_size=9)

    assert unpacked.tolist() == [[1, 1, 0, 1, 0, 1, 0, 1, 0]]


def test_identity_cipher_has_exact_rotational_relation():
    identity = IdentityCipher(block_bit_size=16)
    report = RotationalTests(identity).rotational_tests(
        number_of_samples=16,
        word_size=8,
        rotations=[1, 7],
        seed=3,
        top=2,
        validation_samples=16,
        validation_seed=4,
    )

    assert report["tested_candidates"] == 32
    assert len(report["candidates"]) == 2
    for candidate in report["candidates"]:
        assert candidate["disagreement_frequency"] == 0
        assert candidate["event"] == 0
        assert candidate["validation"]["disagreement_frequency"] == 0


def test_keccak_four_round_instance_is_used_without_round_remapping():
    keccak = KeccakPermutation(number_of_rounds=4)
    report = RotationalTests(keccak).rotational_tests(
        number_of_samples=8,
        word_size=64,
        rotations=[1],
        seed=5,
        top=1,
    )

    assert report["cipher"] == "keccak_p1600_o1600_r4"
    assert report["output_tags"] == ["cipher_output"]
    assert report["tested_candidates"] == 1600
    assert report["candidates"][0]["round"] == 3


def test_round_search_reports_consecutive_validated_relations():
    keccak = KeccakPermutation(number_of_rounds=3)
    report = RotationalTests(keccak).rotational_rounds_tests(
        number_of_samples=32,
        word_size=64,
        rotations=[63],
        seed=5,
        top=1,
        validation_samples=64,
        validation_seed=6,
    )

    assert report["rounds"][0]["round"] == 1
    assert report["rounds"][0]["distinguisher_found"]
    assert all(
        current["round"] + 1 == following["round"]
        for current, following in zip(report["rounds"], report["rounds"][1:])
    )


def test_rotational_tests_reject_invalid_parameters():
    identity = RotationalTests(IdentityCipher(block_bit_size=16))
    with pytest.raises(ValueError, match="word_size must divide"):
        identity.rotational_tests(word_size=6)
    with pytest.raises(ValueError, match="rotations"):
        identity.rotational_tests(word_size=8, rotations=[0])
    with pytest.raises(ValueError, match="validation_seed"):
        identity.rotational_tests(word_size=8, seed=1, validation_samples=8, validation_seed=1)
