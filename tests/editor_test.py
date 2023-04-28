from random import getrandbits

from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.editor import remove_permutations, remove_rotations


def test_add_shift_rows_component():
    cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
    cipher.add_round()
    cipher.add_shift_rows_component(["input"], [[0, 1, 2, 3]], 4, 2)
    assert cipher.rounds.rounds_as_python_dictionary() == [[{'id': 'shift_rows_0_0',
                                                             'type': 'word_operation',
                                                             'input_bit_size': 4,
                                                             'input_id_link': ['input'],
                                                             'input_bit_positions': [[0, 1, 2, 3]],
                                                             'output_bit_size': 4,
                                                             'description': ['ROTATE', 2]}]]


def test_add_variable_rotate_component():
    cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
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


def test_remove_permutations():
    present = PresentBlockCipher()
    present_no_permutations = remove_permutations(present)
    plaintext = getrandbits(64)
    key = getrandbits(80)
    ciphertext = present.evaluate([plaintext, key])
    ciphertext_no_permutations = present_no_permutations.evaluate([plaintext, key])
    assert ciphertext == ciphertext_no_permutations


def test_remove_rotations():
    speck = SpeckBlockCipher()
    speck_no_rotations = remove_rotations(speck)
    plaintext = getrandbits(32)
    key = getrandbits(64)
    ciphertext = speck.evaluate([plaintext, key])
    ciphertext_no_rotations = speck_no_rotations.evaluate([plaintext, key])
    assert ciphertext == ciphertext_no_rotations
