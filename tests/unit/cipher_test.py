import os
import sys
import pytest
import inspect
import os.path
import numpy as np
from io import StringIO
from decimal import Decimal

import claasp
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.permutations.keccak_invertible_permutation import KeccakInvertiblePermutation
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
from claasp.ciphers.permutations.ascon_sbox_sigma_permutation import AsconSboxSigmaPermutation
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
from claasp.ciphers.permutations.spongent_pi_permutation import SpongentPiPermutation
from claasp.ciphers.permutations.photon_permutation import PhotonPermutation
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.permutations.sparkle_permutation import SparklePermutation
from claasp.ciphers.permutations.xoodoo_invertible_permutation import XoodooInvertiblePermutation
from claasp.ciphers.permutations.gift_sbox_permutation import GiftSboxPermutation
from claasp.ciphers.block_ciphers.raiden_block_cipher import RaidenBlockCipher
from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher
from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from claasp.ciphers.permutations.salsa_permutation import SalsaPermutation
from claasp.ciphers.block_ciphers.bea1_block_cipher import BEA1BlockCipher
from claasp.ciphers.block_ciphers.qarmav2_with_mixcolumn_block_cipher import QARMAv2MixColumnBlockCipher
from claasp.ciphers.toys.toyspn1 import ToySPN1
from claasp.cipher_modules.algebraic_tests import AlgebraicTests

EVALUATION_PY = 'evaluation.py'
DICTIONARY_EXAMPLE_PY = "claasp/ciphers/dictionary_example.py"
BIT_BASED_C_FUNCTIONS_O_FILE = 'claasp/cipher_modules/generic_bit_based_c_functions.o'
FANCY_EVALUATE_O_FILE = 'claasp/cipher_modules/fancy_block_cipher_p24_k24_o24_r20_evaluate.o'
FANCY_EVALUATE_C_FILE = 'claasp/cipher_modules/fancy_block_cipher_p24_k24_o24_r20_evaluate.c'


def test_algebraic_tests():
    toyspn = ToySPN1(number_of_rounds=2)
    d = AlgebraicTests(toyspn).algebraic_tests(10)
    assert d == {
        'input_parameters': {'cipher.id': 'toyspn1_p6_k6_o6_r2', 'timeout': 10, 'test_name': 'algebraic_tests'},
        'test_results': {'number_of_variables': [66, 126],
                         'number_of_equations': [76, 158],
                         'number_of_monomials': [96, 186],
                         'max_degree_of_equations': [2, 2],
                         'test_passed': [False, True]}}

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=1)
    d = AlgebraicTests(speck).algebraic_tests(1)
    assert d == {'input_parameters': {'cipher.id': 'speck_p32_k64_o32_r1',
                                      'timeout': 1,
                                      'test_name': 'algebraic_tests'},
                 'test_results': {'number_of_variables': [320],
                                  'number_of_equations': [272],
                                  'number_of_monomials': [365],
                                  'max_degree_of_equations': [2],
                                  'test_passed': [True]}}

    aes = AESBlockCipher(word_size=4, state_size=2, number_of_rounds=1)
    d = AlgebraicTests(aes).algebraic_tests(5)
    compare_result = {'input_parameters': {'cipher.id': 'aes_block_cipher_k16_p16_o16_r1',
                                           'timeout': 5,
                                           'test_name': 'algebraic_tests'},
                      'test_results': {'number_of_variables': [320],
                                       'number_of_equations': [390],
                                       'number_of_monomials': [488],
                                       'max_degree_of_equations': [2],
                                       'test_passed': [False]}}

    assert d == compare_result


def test_delete_generated_evaluate_c_shared_library():
    file_c = open(FANCY_EVALUATE_C_FILE, 'a')
    file_o = open(FANCY_EVALUATE_O_FILE, 'a')
    file_generic = open(BIT_BASED_C_FUNCTIONS_O_FILE, 'a')
    file_c.close()
    file_o.close()
    file_generic.close()
    FancyBlockCipher().delete_generated_evaluate_c_shared_library()
    assert os.path.exists(FANCY_EVALUATE_C_FILE) is False
    assert os.path.exists(FANCY_EVALUATE_O_FILE) is False
    assert os.path.exists(BIT_BASED_C_FUNCTIONS_O_FILE) is False


def test_evaluate_using_c():
    assert FancyBlockCipher(number_of_rounds=2).evaluate_using_c([0x012345, 0x89ABCD], True) == {
        'round_key_output': [3502917, 73728],
        'round_output': [9834215],
        'cipher_output': [7457252]}


def test_evaluate_vectorized():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
    K = np.random.randint(256, size=(8, 2), dtype=np.uint8)
    X = np.random.randint(256, size=(4, 2), dtype=np.uint8)
    result = speck.evaluate_vectorized([X, K])
    K0Lib = int.from_bytes(K[:, 0].tobytes(), byteorder='big')
    K1Lib = int.from_bytes(K[:, 1].tobytes(), byteorder='big')
    X0Lib = int.from_bytes(X[:, 0].tobytes(), byteorder='big')
    X1Lib = int.from_bytes(X[:, 1].tobytes(), byteorder='big')
    C0Lib = speck.evaluate([X0Lib, K0Lib])
    C1Lib = speck.evaluate([X1Lib, K1Lib])
    assert int.from_bytes(result[-1][0].tobytes(), byteorder='big') == C0Lib

    assert int.from_bytes(result[-1][1].tobytes(), byteorder='big') == C1Lib

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    speck_inv = speck.cipher_inverse()
    K = np.random.randint(256, size=(8, 2), dtype=np.uint8)
    C = np.random.randint(256, size=(4, 2), dtype=np.uint8)
    result = speck_inv.evaluate_vectorized([C, K])
    K0Lib = int.from_bytes(K[:, 0].tobytes(), byteorder='big')
    K1Lib = int.from_bytes(K[:, 1].tobytes(), byteorder='big')
    C0Lib = int.from_bytes(C[:, 0].tobytes(), byteorder='big')
    C1Lib = int.from_bytes(C[:, 1].tobytes(), byteorder='big')
    P0Lib = speck_inv.evaluate([C0Lib, K0Lib])
    P1Lib = speck_inv.evaluate([C1Lib, K1Lib])

    assert int.from_bytes(result[-1][0].tobytes(), byteorder='big') == P0Lib
    assert int.from_bytes(result[-1][1].tobytes(), byteorder='big') == P1Lib


def test_evaluate_with_intermediate_outputs_continuous_diffusion_analysis():
    plaintext_input = [Decimal('1') for _ in range(32)]
    plaintext_input[10] = Decimal('0.802999073954890452142763024312444031238555908203125')
    key_input = [Decimal('-1') for _ in range(64)]
    cipher_inputs = [plaintext_input, key_input]
    output = SpeckBlockCipher(number_of_rounds=2).evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
        cipher_inputs, {}, {})
    assert output[0][0] == Decimal('-1.000000000')


def test_get_model():
    speck = SpeckBlockCipher(number_of_rounds=1)
    assert speck.get_model("cp", "xor_differential").__class__.__name__ == "CpXorDifferentialModel"
    assert speck.get_model("sat", "xor_differential").__class__.__name__ == "SatXorDifferentialModel"
    assert speck.get_model("smt", "xor_linear").__class__.__name__ == "SmtXorLinearModel"
    assert speck.get_model("milp", "xor_linear").__class__.__name__ == "MilpXorLinearModel"


def test_generate_bit_based_c_code():
    bit_based_c_code = FancyBlockCipher().generate_bit_based_c_code()
    assert bit_based_c_code[:8] == '#include'
    assert '\tprint_bitstring(output, 16);' in bit_based_c_code

    bit_based_c_code = SpeckBlockCipher().generate_bit_based_c_code(True, True)
    assert '\tprintf("\\nROUND 0\\n\\n");\n' in bit_based_c_code


def test_generate_word_based_c_code():
    word_based_c_code = SpeckBlockCipher().generate_word_based_c_code(20)
    assert word_based_c_code[:8] == '#include'

    word_based_c_code = SpeckBlockCipher().generate_word_based_c_code(20, True, True)
    assert '\tprintf("\\nROUND 0\\n\\n");\n' in word_based_c_code
    assert '\t\tprintf("\\"%s\\" : [", descriptions[i]);' in word_based_c_code


def test_get_component_from_id():
    fancy = FancyBlockCipher(number_of_rounds=2)
    component = fancy.get_component_from_id('sbox_0_0')
    assert component.description == [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]


def test_get_current_component_id():
    cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
    cipher.add_round()
    cipher.add_constant_component(4, 0xF)
    cipher.add_constant_component(4, 0xF)
    cipher.add_round()
    cipher.add_constant_component(4, 0xF)
    assert cipher.get_current_component_id() == 'constant_1_0'


def test_get_round_from_component_id():
    fancy = FancyBlockCipher(number_of_rounds=2)
    assert fancy.get_round_from_component_id('xor_1_14') == 1


def test_impossible_differential_search():
    speck6 = SpeckBlockCipher(number_of_rounds=6)
    # impossible_differentials = speck6.impossible_differential_search("smt", "yices-smt2")
    impossible_differentials = speck6.impossible_differential_search("cp", "chuffed")

    assert ((0x400000, 1) in impossible_differentials) and ((0x400000, 2) in impossible_differentials) and (
            (0x400000, 0x8000) in impossible_differentials)


def test_is_algebraically_secure():
    identity = IdentityBlockCipher()
    assert identity.is_algebraically_secure(120) is False


def test_is_andrx():
    midori = MidoriBlockCipher(number_of_rounds=20)
    assert midori.is_andrx() is False


def test_is_arx():
    midori = MidoriBlockCipher(number_of_rounds=20)
    assert midori.is_arx() is False


def test_is_power_of_2_word_based():
    assert XTeaBlockCipher(number_of_rounds=32).is_power_of_2_word_based() == 32

    assert MidoriBlockCipher(number_of_rounds=16).is_power_of_2_word_based() is False


def test_is_shift_arx():
    xtea = XTeaBlockCipher(number_of_rounds=32)
    assert xtea.is_shift_arx() is True


def test_is_spn():
    aes = AESBlockCipher(number_of_rounds=2)
    assert aes.is_spn() is True


def test_polynomial_system():
    assert str(IdentityBlockCipher().polynomial_system()) == 'Polynomial Sequence with 128 Polynomials in 256 Variables'


def test_polynomial_system_at_round():
    assert str(FancyBlockCipher(number_of_rounds=1).polynomial_system_at_round(0)) == \
           'Polynomial Sequence with 252 Polynomials in 288 Variables'


def test_print():
    old_stdout = sys.stdout
    cipher = Cipher("cipher_name", "permutation", ["input"], [32], 32)
    cipher.add_round()
    cipher.add_constant_component(16, 0xAB01)
    cipher.add_constant_component(16, 0xAB01)
    result = StringIO()
    sys.stdout = result
    cipher.print()
    sys.stdout = old_stdout
    assert result.getvalue() == """cipher_id = cipher_name_i32_o32_r1
cipher_type = permutation
cipher_inputs = ['input']
cipher_inputs_bit_size = [32]
cipher_output_bit_size = 32
cipher_number_of_rounds = 1

    # round = 0 - round component = 0
    id = constant_0_0
    type = constant
    input_bit_size = 0
    input_id_link = ['']
    input_bit_positions = [[]]
    output_bit_size = 16
    description = ['0xab01']

    # round = 0 - round component = 1
    id = constant_0_1
    type = constant
    input_bit_size = 0
    input_id_link = ['']
    input_bit_positions = [[]]
    output_bit_size = 16
    description = ['0xab01']
cipher_reference_code = None
"""


def test_print_as_python_dictionary_to_file():
    cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
    cipher.print_as_python_dictionary_to_file(DICTIONARY_EXAMPLE_PY)
    assert os.path.isfile(DICTIONARY_EXAMPLE_PY)
    os.remove(DICTIONARY_EXAMPLE_PY)


def test_print_evaluation_python_code():
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    IdentityBlockCipher().print_evaluation_python_code(verbosity=True)
    sys.stdout = old_stdout
    python_code = result.getvalue()

    assert ("components_io['concatenate_0_0'] = [component_input.uint, concatenate_0_0_output.uint]" in python_code) \
           is True
    assert ("components_io['intermediate_output_0_1'] = [component_input.uint, intermediate_output_0_1_output.uint]"
            in python_code) is True
    assert ("component_input = select_bits(concatenate_0_2_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,"
            " 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])" in python_code) is True


def test_print_evaluation_python_code_to_file():
    identity = IdentityBlockCipher()
    assert identity.file_name == 'identity_block_cipher_p32_k32_o32_r1.py'
    identity.print_evaluation_python_code_to_file(identity.id + EVALUATION_PY)
    assert os.path.isfile(identity.id + EVALUATION_PY)
    os.remove(identity.id + EVALUATION_PY)


def test_print_input_information():
    fancy = FancyBlockCipher()
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    fancy.print_input_information()
    sys.stdout = old_stdout
    assert result.getvalue() == """plaintext of bit size 24
key of bit size 24
"""


def test_print_as_python_dictionary():
    old_stdout = sys.stdout
    cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
    cipher.add_round()
    cipher.add_constant_component(16, 0xAB01)
    cipher.add_constant_component(16, 0xAB01)
    result = StringIO()
    sys.stdout = result
    cipher.print_as_python_dictionary()
    sys.stdout = old_stdout
    assert result.getvalue() == """cipher = {
'cipher_id': 'cipher_name_k32_p32_o32_r1',
'cipher_type': 'block_cipher',
'cipher_inputs': ['key', 'plaintext'],
'cipher_inputs_bit_size': [32, 32],
'cipher_output_bit_size': 32,
'cipher_number_of_rounds': 1,
'cipher_rounds' : [
  # round 0
  [
  {
    # round = 0 - round component = 0
    'id': 'constant_0_0',
    'type': 'constant',
    'input_bit_size': 0,
    'input_id_link': [''],
    'input_bit_positions': [[]],
    'output_bit_size': 16,
    'description': ['0xab01'],
  },
  {
    # round = 0 - round component = 1
    'id': 'constant_0_1',
    'type': 'constant',
    'input_bit_size': 0,
    'input_id_link': [''],
    'input_bit_positions': [[]],
    'output_bit_size': 16,
    'description': ['0xab01'],
  },
  ],
  ],
'cipher_reference_code': None,
}
"""


def test_inputs_size_to_dict():
    speck = SpeckBlockCipher(number_of_rounds=1, key_bit_size=64, block_bit_size=32)
    input_sizes = speck.inputs_size_to_dict()
    assert input_sizes['key'] == 64
    assert input_sizes['plaintext'] == 32


def test_vector_check():
    speck = SpeckBlockCipher(number_of_rounds=22)
    key1 = 0x1918111009080100
    plaintext1 = 0x6574694c
    ciphertext1 = 0xa86842f2
    key2 = 0x1918111009080100
    plaintext2 = 0x6574694d
    ciphertext2 = 0x2b5f25d6
    input_list = [[plaintext1, key1], [plaintext2, key2]]
    output_list = [ciphertext1, ciphertext2]
    assert speck.test_vector_check(input_list, output_list) is True

    input_list.append([0x11111111, 0x1111111111111111])
    output_list.append(0xFFFFFFFF)
    assert speck.test_vector_check(input_list, output_list) is False


def test_zero_correlation_linear_search():
    speck6 = SpeckBlockCipher(number_of_rounds=6)
    zero_correlation_linear_approximations = speck6.zero_correlation_linear_search("smt", "yices-smt2")
    assert len(zero_correlation_linear_approximations) > 0


def test_cipher_inverse():
    key = 0xabcdef01abcdef01
    plaintext = 0x01234567
    cipher = SpeckBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    cipher = AESBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([key, plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x0e2ddd5c5b4ca9d4
    plaintext = 0xb779ee0a
    cipher = TeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x98edeafc899338c45fad
    plaintext = 0x42c20fd3b586879e
    cipher = PresentBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    plaintext = 0
    cipher = AsconSboxSigmaPermutation(number_of_rounds=1)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    key = 0x1211100a09080201
    plaintext = 0x6120676e
    cipher = SimonBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x687ded3b3c85b3f35b1009863e2a8cbf
    plaintext = 0x42c20fd3b586879e
    cipher = MidoriBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0xffffeeee
    plaintext = 0x5778
    cipher = SkinnyBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    plaintext = 0x1234
    cipher = SpongentPiPermutation(number_of_rounds=1)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    key = 0x1de1c3c2c65880074c32dce537b22ab3
    plaintext = 0xbd7d764dff0ada1e
    cipher = XTeaBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    plaintext = 0x1234
    cipher = PhotonPermutation(number_of_rounds=1)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    key = 0x0f1e2d3c4b5a69788796a5b4c3d2e1f0
    plaintext = 0x101112131415161718191a1b1c1d1e1f
    cipher = LeaBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    plaintext = 0x1234
    cipher = SparklePermutation(number_of_steps=1)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    plaintext = 0x1234
    cipher = XoodooInvertiblePermutation(number_of_rounds=1)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    key = 0x000102030405060708090A0B0C0D0E0F
    plaintext = 0x000102030405060708090A0B0C0D0E0F
    cipher = GiftSboxPermutation(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x1de1c3c2c65880074c32dce537b22ab3
    plaintext = 0xbd7d764dff0ada1e
    cipher = RaidenBlockCipher(number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    key = 0x000000066770000000a0000000000001
    plaintext = 0x0011223344556677
    cipher = HightBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=2)
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    cipher = DESBlockCipher(number_of_rounds=4)
    key = 0x133457799BBCDFF1
    plaintext = 0x0123456789ABCDEF
    ciphertext = cipher.evaluate([key, plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    cipher = SalsaPermutation(number_of_rounds=2)
    plaintext = 0xffff
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    cipher = BEA1BlockCipher(number_of_rounds=2)
    key = 0x8cdd0f3459fb721e798655298d5c1
    plaintext = 0x47a57eff5d6475a68916
    ciphertext = cipher.evaluate([key, plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    plaintext = 0x1234
    cipher = KeccakInvertiblePermutation(number_of_rounds=2, word_size=8)
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    cipher = ChachaPermutation(number_of_rounds=3)
    plaintext = 0x0001
    ciphertext = cipher.evaluate([plaintext])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext]) == plaintext

    cipher = LBlockBlockCipher(number_of_rounds=2)
    key = 0x012345689abcdeffedc
    plaintext = 0x012345689abcdef
    ciphertext = cipher.evaluate([plaintext, key])
    cipher_inv = cipher.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, key]) == plaintext

    qarmav2 = QARMAv2MixColumnBlockCipher(number_of_rounds=2)
    key = 0x0123456789abcdeffedcba9876543210
    plaintext = 0x0000000000000000
    tweak = 0x7e5c3a18f6d4b2901eb852fc9630da74
    ciphertext = qarmav2.evaluate([key, plaintext, tweak])
    cipher_inv = qarmav2.cipher_inverse()
    assert cipher_inv.evaluate([ciphertext, tweak, key]) == plaintext
