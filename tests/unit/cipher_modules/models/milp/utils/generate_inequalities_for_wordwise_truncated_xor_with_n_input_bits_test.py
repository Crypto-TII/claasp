from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import *
def test_generate_valid_points_input_words():
    valid_points = generate_valid_points_input_words()
    assert len(valid_points) == 18
    assert valid_points[0] == '000000'
    assert valid_points[1] == '010001'
    assert valid_points[-2] == '100000'
    assert valid_points[-1] == '110000'

def test_update_dictionary_that_contains_wordwise_truncated_input_inequalities():
    update_dictionary_that_contains_wordwise_truncated_input_inequalities(3)
    dictio = output_dictionary_that_contains_wordwise_truncated_input_inequalities()
    assert dictio[3] == ['01000', '-0--1', '1---1', '-0-1-', '1--1-', '-01--', '1-1--']
def test_generate_valid_points_for_xor_between_n_input_words():
    valid_points = generate_valid_points_for_xor_between_n_input_words()
    assert len(valid_points) == 324
    assert valid_points[0] == '000000000000000000'
    assert valid_points[1] == '000000010001010001'
    assert valid_points[-2] == '110000100000110000'
    assert valid_points[-1] == '110000110000110000'

def test_update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs():
    update_dictionary_that_contains_wordwise_truncated_xor_inequalities_between_n_inputs(3, 3)
    dictio = output_dictionary_that_contains_wordwise_truncated_xor_inequalities()
    assert dictio[3][3][:2] == ['1----1----------0---', '--100--100-0----1---']
    assert dictio[3][3][-2:] == ['------01------------', '----------1----0----']