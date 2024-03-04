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
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.avalanche_tests import AvalancheTests


def test_bytes_positions_to_little_endian_for_32_bits():
    lst = list(range(32))
    output_lst = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14, 15, 0,
                  1, 2, 3, 4, 5, 6, 7]
    assert bytes_positions_to_little_endian_for_32_bits(lst) == output_lst


def test_get_k_th_bit():
    assert get_k_th_bit(3, 0) == 1


def test_pprint_dictionary():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    test = AvalancheTests(speck)
    d = test.avalanche_tests(number_of_samples=100)
    pprint_dictionary(d["test_results"]["plaintext"]["round_output"]["avalanche_dependence_vectors"][0])
    result = d["test_results"]["plaintext"]["round_output"]["avalanche_dependence_vectors"][0]["input_difference_value"]
    assert result == "0x1"


def test_pprint_dictionary_to_file():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    test = AvalancheTests(speck)
    d = test.avalanche_tests(number_of_samples=100)
    tii_path = inspect.getfile(claasp)
    tii_dir_path = os.path.dirname(tii_path)
    pprint_dictionary_to_file(d["input_parameters"], f"{tii_dir_path}/test_json")
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