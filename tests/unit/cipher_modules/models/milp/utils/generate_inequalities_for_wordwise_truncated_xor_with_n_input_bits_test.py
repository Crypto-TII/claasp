from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits import generate_valid_points_input_words, generate_valid_points_for_xor_between_n_input_words

def test_generate_valid_points_input_words():
    valid_points = generate_valid_points_input_words()
    assert len(valid_points) == 18
    assert valid_points[0] == '000000'
    assert valid_points[1] == '010001'
    assert valid_points[-2] == '100000'
    assert valid_points[-1] == '110000'

def test_generate_valid_points_for_xor_between_n_input_words():
    valid_points = generate_valid_points_for_xor_between_n_input_words()
    assert len(valid_points) == 324
    assert valid_points[0] == '000000000000000000'
    assert valid_points[1] == '000000010001010001'
    assert valid_points[-2] == '110000100000110000'
    assert valid_points[-1] == '110000110000110000'
