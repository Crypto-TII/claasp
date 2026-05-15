import io
from contextlib import redirect_stdout
from random import getrandbits

from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
from claasp.editor import get_component_reordering, is_fixed_rotate_component, replace_bit_reordering_components_as_direct_wiring
from claasp.name_mappings import LINEAR_LAYER, PERMUTATION, PERMUTATION_COMPONENT


def test_add_shift_rows_component():
    cipher = Cipher("cipher_name", PERMUTATION, ["input"], [32], 32)
    cipher.add_round()
    cipher.add_shift_rows_component(["input"], [list(range(32))], 1, 8, 4)
    assert cipher.rounds.rounds_as_python_dictionary() == [[{'id': 'shift_rows_0_0',
                                                             'type': 'word_operation',
                                                             'input_bit_size': 32,
                                                             'input_id_link': ['input'],
                                                             'input_bit_positions': [list(range(32))],
                                                             'output_bit_size': 32,
                                                             'description': ['ROTATE', 8]}]]


def test_add_variable_rotate_component():
    cipher = Cipher("cipher_name", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    cipher.add_variable_rotate_component(["input", "input"], [[0, 1, 2, 3], [4, 5, 6, 7]], 4, -1)
    assert cipher.rounds.rounds_as_python_dictionary() == [[{'id': 'var_rot_0_0',
                                                             'type': 'word_operation',
                                                             'input_bit_size': 8,
                                                             'input_id_link': ['input', 'input'],
                                                             'input_bit_positions': [[0, 1, 2, 3], [4, 5, 6, 7]],
                                                             'output_bit_size': 4,
                                                             'description': ['ROTATE_BY_VARIABLE_AMOUNT', -1]}]]


def test_remove_key_schedule():
    speck = SpeckBlockCipher(number_of_rounds=4)
    removed_key_speck = speck.remove_key_schedule()
    assert removed_key_speck.component_from(1, 0).as_python_dictionary() == {'id': 'rot_1_6',
                                                                             'type': 'word_operation',
                                                                             'input_bit_size': 16,
                                                                             'input_id_link': ['xor_0_2'],
                                                                             'input_bit_positions': [[0, 1, 2, 3, 4,
                                                                                                      5, 6, 7, 8, 9,
                                                                                                      10, 11, 12, 13,
                                                                                                      14, 15]],
                                                                             'output_bit_size': 16,
                                                                             'description': ['ROTATE', 7]}

    removed_key_speck = speck.remove_key_schedule(keep_round_key_injection=False)
    assert removed_key_speck.component_from(1, 0).as_python_dictionary() == {'id': 'rot_1_6',
                                                                             'type': 'word_operation',
                                                                             'input_bit_size': 16,
                                                                             'input_id_link': ['modadd_0_1'],
                                                                             'input_bit_positions': [[0, 1, 2, 3, 4,
                                                                                                      5, 6, 7, 8, 9,
                                                                                                      10, 11, 12, 13,
                                                                                                      14, 15]],
                                                                             'output_bit_size': 16,
                                                                             'description': ['ROTATE', 7]}


def test_remove_key_schedule_without_round_key_injection_evaluate():
    ublock = UblockBlockCipher(number_of_rounds=2)
    plaintext = 0x80000000000000000000000000000000

    removed_without_injection = ublock.remove_key_schedule(keep_round_key_injection=False)
    removed_with_injection = ublock.remove_key_schedule(keep_round_key_injection=True)

    assert removed_without_injection.inputs == ['plaintext']

    output_without_injection = removed_without_injection.evaluate([plaintext], intermediate_output=True)[0]
    zero_round_key_inputs = [plaintext] + [0] * (len(removed_with_injection.inputs) - 1)
    output_with_zero_injections = removed_with_injection.evaluate(zero_round_key_inputs, intermediate_output=True)[0]

    assert output_without_injection == output_with_zero_injections


def test_replace_bit_reordering_components_as_direct_wiring_for_permutations():
    present = PresentBlockCipher()
    present_without_explicit_permutations = replace_bit_reordering_components_as_direct_wiring(
        present,
        lambda component: component.type in {PERMUTATION_COMPONENT, LINEAR_LAYER},
    )
    plaintext = getrandbits(64)
    key = getrandbits(80)
    ciphertext = present.evaluate([plaintext, key])
    transformed_ciphertext = present_without_explicit_permutations.evaluate([plaintext, key])
    assert ciphertext == transformed_ciphertext


def test_replace_bit_reordering_components_as_direct_wiring_rewires_permutation_component():
    permutation_cipher = PermutationCipher(bit_size=8, permutation_description=[1, 0], word_size=4)
    permutation_cipher_without_explicit_permutations = replace_bit_reordering_components_as_direct_wiring(
        permutation_cipher,
        lambda component: component.type in {PERMUTATION_COMPONENT, LINEAR_LAYER},
    )

    assert permutation_cipher.evaluate([0xAB]) == permutation_cipher_without_explicit_permutations.evaluate([0xAB])
    assert not any(
        component.type == "permutation"
        for cipher_round in permutation_cipher_without_explicit_permutations.rounds_as_list
        for component in cipher_round.components
    )


def test_replace_bit_reordering_components_as_direct_wiring_for_rotations():
    speck = SpeckBlockCipher()
    speck_without_explicit_rotations = replace_bit_reordering_components_as_direct_wiring(
        speck,
        is_fixed_rotate_component,
    )
    plaintext = getrandbits(32)
    key = getrandbits(64)
    ciphertext = speck.evaluate([plaintext, key])
    transformed_ciphertext = speck_without_explicit_rotations.evaluate([plaintext, key])
    assert ciphertext == transformed_ciphertext


def test_replace_bit_reordering_components_as_direct_wiring_removes_only_reorder_only_components():
    cipher = Cipher("toy", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    cipher.add_permutation_component(["input"], [[0, 1, 2, 3]], 4, [1, 2, 3, 0])
    cipher.add_rotate_component(["permutation_0_0"], [[0, 1, 2, 3]], 4, 1)
    cipher.add_linear_layer_component(
        ["rot_0_1"],
        [[0, 1, 2, 3]],
        4,
        [[0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [1, 0, 0, 0]],
    )
    cipher.add_linear_layer_component(
        ["linear_layer_0_2"],
        [[0, 1, 2, 3]],
        4,
        [[1, 1, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]],
    )
    cipher.add_cipher_output_component(["linear_layer_0_3"], [[0, 1, 2, 3]], 4)

    simplified = replace_bit_reordering_components_as_direct_wiring(
        cipher,
        lambda component: component.type == PERMUTATION_COMPONENT
        or is_fixed_rotate_component(component)
        or component.type == LINEAR_LAYER,
    )

    remaining_candidates = [
        component
        for cipher_round in simplified.rounds_as_list
        for component in cipher_round.components
        if component.type == PERMUTATION_COMPONENT
        or is_fixed_rotate_component(component)
        or component.type == LINEAR_LAYER
    ]

    assert len(remaining_candidates) == 1
    assert remaining_candidates[0].id == "linear_layer_0_3"


def test_get_component_reordering_for_permutation_component():
    cipher = Cipher("toy", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    perm = cipher.add_permutation_component(["input"], [[0, 1, 2, 3]], 4, [3, 2, 1, 0])
    # [3,2,1,0] is its own inverse: output[i] = input[3-i]
    assert get_component_reordering(perm) == [3, 2, 1, 0]


def test_get_component_reordering_for_rotate_component():
    cipher = Cipher("toy", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    rot = cipher.add_rotate_component(["input"], [[0, 1, 2, 3]], 4, 1)
    # right-rotate by 1: output[i] = input[(i+1) % 4], so source indices are [3, 0, 1, 2]
    assert get_component_reordering(rot) == [3, 0, 1, 2]


def test_get_component_reordering_for_permutation_matrix_linear_layer():
    cipher = Cipher("toy", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    # identity permutation matrix
    ll = cipher.add_linear_layer_component(
        ["input"], [[0, 1, 2, 3]], 4,
        [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]],
    )
    assert get_component_reordering(ll) == [0, 1, 2, 3]


def test_get_component_reordering_returns_none_for_non_reorder_component():
    cipher = Cipher("toy", PERMUTATION, ["input"], [4], 4)
    cipher.add_round()
    # non-permutation linear layer
    non_perm_ll = cipher.add_linear_layer_component(
        ["input"], [[0, 1, 2, 3]], 4,
        [[1, 1, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]],
    )
    assert get_component_reordering(non_perm_ll) is None
    # XOR is not a reorder-only component either
    xor = cipher.add_xor_component(["input", "input"], [[0, 1], [2, 3]], 2)
    assert get_component_reordering(xor) is None


def test_add_fsr_component():
    cipher = Cipher("cipher_name", "fsr", ["input"], [12], 12)
    cipher.add_round()
    cipher.add_fsr_component(["input", "input"], [[0, 1, 2, 3, 4], [0, 1, 2, 3, 4, 5, 6]], 12,
                             [
                                 [
                                     [5, [[4], [5], [6, 7]]],  # Register_len:5,  feedback poly: x4 + x5 + x6*x7
                                     [7, [[0], [8], [1, 2]]]  # Register_len:7, feedback poly: x0 + x1*x2 + x8
                                 ],
                                 1])
    assert cipher.rounds.rounds_as_python_dictionary() == [[{'id': 'fsr_0_0',
                                                             'type': 'fsr',
                                                             'input_bit_size': 12,
                                                             'input_id_link': ['input', 'input'],
                                                             'input_bit_positions': [[0, 1, 2, 3, 4],
                                                                                     [0, 1, 2, 3, 4, 5, 6]],
                                                             'output_bit_size': 12,
                                                             'description': [
                                                                 [[5, [[4], [5], [6, 7]]], [7, [[0], [8], [1, 2]]]],
                                                                 1]}]]


def test_add_components_without_round_returns_none():
    cipher = Cipher("cipher_name", PERMUTATION, ["input"], [4], 4)
    stdout = io.StringIO()

    with redirect_stdout(stdout):
        assert cipher.add_and_component(["input"], [[0, 1]], 2) is None
        assert cipher.add_cipher_output_component(["input"], [[0, 1, 2, 3]], 4) is None

    assert "please run self.add_round()" in stdout.getvalue()
