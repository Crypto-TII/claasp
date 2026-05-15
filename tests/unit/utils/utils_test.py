import os
import inspect

import claasp
from claasp.utils.utils import point_pair
from claasp.utils.utils import sgn_function
from claasp.utils.utils import signed_distance
from claasp.utils.utils import pprint_dictionary
from claasp.utils.utils import pprint_dictionary_to_file
from claasp.utils.utils import bytes_positions_to_little_endian_for_32_bits
from claasp.utils.utils import coerce_exact_int
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.avalanche_tests import AvalancheTests


def test_bytes_positions_to_little_endian_for_32_bits():
    lst = list(range(32))
    output_lst = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 20, 21, 22, 23, 8, 9, 10, 11, 12, 13, 14, 15, 0,
                  1, 2, 3, 4, 5, 6, 7]
    assert bytes_positions_to_little_endian_for_32_bits(lst) == output_lst


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


def test_coerce_exact_int_with_positive_integer():
    """Test coerce_exact_int with a positive integer."""
    assert coerce_exact_int(5, "test_param") == 5


def test_coerce_exact_int_with_negative_integer():
    """Test coerce_exact_int with a negative integer."""
    assert coerce_exact_int(-42, "test_param") == -42


def test_coerce_exact_int_with_zero():
    """Test coerce_exact_int with zero."""
    assert coerce_exact_int(0, "test_param") == 0


def test_coerce_exact_int_with_large_integer():
    """Test coerce_exact_int with a large integer."""
    large_int = 10**100
    assert coerce_exact_int(large_int, "test_param") == large_int


def test_coerce_exact_int_with_exact_float():
    """Test coerce_exact_int with a float that is exactly an integer."""
    assert coerce_exact_int(5.0, "test_param") == 5
    assert coerce_exact_int(-10.0, "test_param") == -10


def test_coerce_exact_int_with_non_exact_float():
    """Test coerce_exact_int rejects non-integer floats."""
    try:
        coerce_exact_int(5.5, "test_param")
        assert False, "Expected ValueError for non-integer float"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_boolean_true():
    """Test coerce_exact_int rejects boolean True."""
    try:
        coerce_exact_int(True, "test_param")
        assert False, "Expected ValueError for boolean True"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_boolean_false():
    """Test coerce_exact_int rejects boolean False."""
    try:
        coerce_exact_int(False, "test_param")
        assert False, "Expected ValueError for boolean False"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_string():
    """Test coerce_exact_int rejects string input."""
    try:
        coerce_exact_int("123", "test_param")
        assert False, "Expected ValueError for string input"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_none():
    """Test coerce_exact_int rejects None."""
    try:
        coerce_exact_int(None, "test_param")
        assert False, "Expected ValueError for None"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_list():
    """Test coerce_exact_int rejects list input."""
    try:
        coerce_exact_int([1, 2, 3], "test_param")
        assert False, "Expected ValueError for list input"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_with_dict():
    """Test coerce_exact_int rejects dict input."""
    try:
        coerce_exact_int({"key": "value"}, "test_param")
        assert False, "Expected ValueError for dict input"
    except ValueError as e:
        assert "test_param must be an integer" in str(e)


def test_coerce_exact_int_preserves_value():
    """Test that coerce_exact_int returns the correct integer value."""
    test_values = [1, 10, 100, -1, -50, 0, 1000000]
    for val in test_values:
        result = coerce_exact_int(val, "test")
        assert result == val
        assert isinstance(result, int)


def test_coerce_exact_int_parameter_name_in_error():
    """Test that parameter_name appears in error messages."""
    param_names = ["word_size", "number_of_rounds", "rotation"]
    for param_name in param_names:
        try:
            coerce_exact_int(3.14, param_name)
            assert False, f"Expected ValueError for {param_name}"
        except ValueError as e:
            assert param_name in str(e)