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


def test_bytes_positions_to_little_endian_for_32_bits():
    lst = list(range(32))
    output_lst = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14, 15, 0,
                  1, 2, 3, 4, 5, 6, 7]
    assert bytes_positions_to_little_endian_for_32_bits(lst) == output_lst


def test_get_k_th_bit():
    assert get_k_th_bit(3, 0) == 1


def test_pprint_dictionary():
    tests_configuration = {"diffusion_tests": {"run_tests": True,
                                               "number_of_samples": 100,
                                               "run_avalanche_dependence": True,
                                               "run_avalanche_dependence_uniform": True,
                                               "run_avalanche_weight": True, "run_avalanche_entropy": True,
                                               "avalanche_dependence_uniform_bias": 0.2,
                                               "avalanche_dependence_criterion_threshold": 0,
                                               "avalanche_dependence_uniform_criterion_threshold": 0,
                                               "avalanche_weight_criterion_threshold": 0.1,
                                               "avalanche_entropy_criterion_threshold": 0.1},
                           "component_analysis_tests": {"run_tests": True}}
    cipher = IdentityBlockCipher()
    analysis = cipher.analyze_cipher(tests_configuration)
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    pprint_dictionary(analysis['diffusion_tests']['input_parameters'])
    sys.stdout = old_stdout
    assert result.getvalue() == """{   'avalanche_dependence_criterion_threshold': 0,
    'avalanche_dependence_uniform_bias': 0.2,
    'avalanche_dependence_uniform_criterion_threshold': 0,
    'avalanche_entropy_criterion_threshold': 0.1,
    'avalanche_weight_criterion_threshold': 0.1,
    'number_of_samples': 100}
"""


def test_pprint_dictionary_to_file():
    identity = IdentityBlockCipher()
    tests_configuration = {"diffusion_tests": {"run_tests": True, "number_of_samples": 100,
                                               "run_avalanche_dependence": True,
                                               "run_avalanche_dependence_uniform": True,
                                               "run_avalanche_weight": True,
                                               "run_avalanche_entropy": True,
                                               "avalanche_dependence_uniform_bias": 0.2,
                                               "avalanche_dependence_criterion_threshold": 0,
                                               "avalanche_dependence_uniform_criterion_threshold": 0,
                                               "avalanche_weight_criterion_threshold": 0.1,
                                               "avalanche_entropy_criterion_threshold": 0.1},
                           "component_analysis_tests": {"run_tests": True}}
    tii_path = inspect.getfile(claasp)
    tii_dir_path = os.path.dirname(tii_path)
    analysis = identity.analyze_cipher(tests_configuration)
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
