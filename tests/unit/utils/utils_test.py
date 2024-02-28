import os
import sys
import inspect
from io import StringIO

import claasp
from claasp.utils.utils import point_pair
from claasp.utils.utils import get_k_th_bit
from claasp.utils.utils import sgn_function
from claasp.utils.utils import signed_distance
from claasp.utils.utils import pprint_dictionary
from claasp.utils.utils import pprint_dictionary_to_file
from claasp.utils.utils import bytes_positions_to_little_endian_for_32_bits
from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
from claasp.cipher_modules import avalanche_tests

def test_bytes_positions_to_little_endian_for_32_bits():
    lst = list(range(32))
    output_lst = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14, 15, 0,
                  1, 2, 3, 4, 5, 6, 7]
    assert bytes_positions_to_little_endian_for_32_bits(lst) == output_lst


def test_get_k_th_bit():
    assert get_k_th_bit(3, 0) == 1


def test_pprint_dictionary():
    tests_configuration = {"diffusion_tests": {"number_of_samples": 100,
                                               "run_avalanche_dependence": True,
                                               "run_avalanche_dependence_uniform": True,
                                               "run_avalanche_weight": True, "run_avalanche_entropy": True,
                                               "avalanche_dependence_uniform_bias": 0.2,
                                               "avalanche_dependence_criterion_threshold": 0,
                                               "avalanche_dependence_uniform_criterion_threshold": 0,
                                               "avalanche_weight_criterion_threshold": 0.1,
                                               "avalanche_entropy_criterion_threshold": 0.1}}
    cipher = IdentityBlockCipher()
    analysis= {'diffusion_tests': avalanche_tests.avalanche_tests(cipher, **tests_configuration["diffusion_tests"])}
    pprint_dictionary(analysis['diffusion_tests']['input_parameters'])
    result = analysis['diffusion_tests']['input_parameters']
    assert result == {'avalanche_dependence_criterion_threshold': 0,
                                 'avalanche_dependence_uniform_bias': 0.2,
                                 'avalanche_dependence_uniform_criterion_threshold': 0,
                                 'avalanche_entropy_criterion_threshold': 0.1,
                                 'avalanche_weight_criterion_threshold': 0.1,
                                 'cipher_output_avalanche_dependence_uniform_vectors_expected_value_per_bit': 1,
                                 'cipher_output_avalanche_dependence_uniform_vectors_expected_value_per_output_block': 32,
                                 'cipher_output_avalanche_dependence_uniform_vectors_input_bit_size': 32,
                                 'cipher_output_avalanche_dependence_uniform_vectors_max_possible_value_per_output_block': 32,
                                 'cipher_output_avalanche_dependence_uniform_vectors_min_possible_value_per_output_block': 0,
                                 'cipher_output_avalanche_dependence_uniform_vectors_output_bit_size': 32,
                                 'cipher_output_avalanche_dependence_vectors_expected_value_per_bit': 1,
                                 'cipher_output_avalanche_dependence_vectors_expected_value_per_output_block': 32,
                                 'cipher_output_avalanche_dependence_vectors_input_bit_size': 32,
                                 'cipher_output_avalanche_dependence_vectors_max_possible_value_per_output_block': 32,
                                 'cipher_output_avalanche_dependence_vectors_min_possible_value_per_output_block': 0,
                                 'cipher_output_avalanche_dependence_vectors_output_bit_size': 32,
                                 'cipher_output_avalanche_entropy_vectors_expected_value_per_bit': 1,
                                 'cipher_output_avalanche_entropy_vectors_expected_value_per_output_block': 32,
                                 'cipher_output_avalanche_entropy_vectors_input_bit_size': 32,
                                 'cipher_output_avalanche_entropy_vectors_max_possible_value_per_output_block': 32,
                                 'cipher_output_avalanche_entropy_vectors_min_possible_value_per_output_block': 0,
                                 'cipher_output_avalanche_entropy_vectors_output_bit_size': 32,
                                 'cipher_output_avalanche_weight_vectors_expected_value_per_bit': 0.5,
                                 'cipher_output_avalanche_weight_vectors_expected_value_per_output_block': 16.0,
                                 'cipher_output_avalanche_weight_vectors_input_bit_size': 32,
                                 'cipher_output_avalanche_weight_vectors_max_possible_value_per_output_block': 32,
                                 'cipher_output_avalanche_weight_vectors_min_possible_value_per_output_block': 0,
                                 'cipher_output_avalanche_weight_vectors_output_bit_size': 32,
                                 'number_of_samples': 100,
                                 'round_key_output_avalanche_dependence_uniform_vectors_expected_value_per_bit': 1,
                                 'round_key_output_avalanche_dependence_uniform_vectors_expected_value_per_output_block': 32,
                                 'round_key_output_avalanche_dependence_uniform_vectors_input_bit_size': 32,
                                 'round_key_output_avalanche_dependence_uniform_vectors_max_possible_value_per_output_block': 32,
                                 'round_key_output_avalanche_dependence_uniform_vectors_min_possible_value_per_output_block': 0,
                                 'round_key_output_avalanche_dependence_uniform_vectors_output_bit_size': 32,
                                 'round_key_output_avalanche_dependence_vectors_expected_value_per_bit': 1,
                                 'round_key_output_avalanche_dependence_vectors_expected_value_per_output_block': 32,
                                 'round_key_output_avalanche_dependence_vectors_input_bit_size': 32,
                                 'round_key_output_avalanche_dependence_vectors_max_possible_value_per_output_block': 32,
                                 'round_key_output_avalanche_dependence_vectors_min_possible_value_per_output_block': 0,
                                 'round_key_output_avalanche_dependence_vectors_output_bit_size': 32,
                                 'round_key_output_avalanche_entropy_vectors_expected_value_per_bit': 1,
                                 'round_key_output_avalanche_entropy_vectors_expected_value_per_output_block': 32,
                                 'round_key_output_avalanche_entropy_vectors_input_bit_size': 32,
                                 'round_key_output_avalanche_entropy_vectors_max_possible_value_per_output_block': 32,
                                 'round_key_output_avalanche_entropy_vectors_min_possible_value_per_output_block': 0,
                                 'round_key_output_avalanche_entropy_vectors_output_bit_size': 32,
                                 'round_key_output_avalanche_weight_vectors_expected_value_per_bit': 0.5,
                                 'round_key_output_avalanche_weight_vectors_expected_value_per_output_block': 16.0,
                                 'round_key_output_avalanche_weight_vectors_input_bit_size': 32,
                                 'round_key_output_avalanche_weight_vectors_max_possible_value_per_output_block': 32,
                                 'round_key_output_avalanche_weight_vectors_min_possible_value_per_output_block': 0,
                                 'round_key_output_avalanche_weight_vectors_output_bit_size': 32,
                                 'test_name': 'avalanche_tests'}


def test_pprint_dictionary_to_file():
    identity = IdentityBlockCipher()
    tests_configuration = {"diffusion_tests": {"number_of_samples": 100,
                                               "run_avalanche_dependence": True,
                                               "run_avalanche_dependence_uniform": True,
                                               "run_avalanche_weight": True,
                                               "run_avalanche_entropy": True,
                                               "avalanche_dependence_uniform_bias": 0.2,
                                               "avalanche_dependence_criterion_threshold": 0,
                                               "avalanche_dependence_uniform_criterion_threshold": 0,
                                               "avalanche_weight_criterion_threshold": 0.1,
                                               "avalanche_entropy_criterion_threshold": 0.1}}
    tii_path = inspect.getfile(claasp)
    tii_dir_path = os.path.dirname(tii_path)
    analysis = {'diffusion_tests': avalanche_tests.avalanche_tests(identity, **tests_configuration["diffusion_tests"])}
    pprint_dictionary_to_file(analysis['diffusion_tests']['input_parameters'], f"{tii_dir_path}/test_json")
    assert os.path.isfile(f"{tii_dir_path}/test_json") is True
    os.remove(f"{tii_dir_path}/test_json")


def test_sgn_function():
    assert sgn_function(-1) == -1


def test_signed_distance():
    lst_x = [0.001, -0.99]
    lst_y = [0.002, -0.90]
    assert signed_distance(lst_x, lst_y) == 0


def test_point_pair():
    result = point_pair(0.001, 1)
    assert str(type(result[0][0])) == "<class 'decimal.Decimal'>"
    assert str(type(result[1][0])) == "<class 'decimal.Decimal'>"