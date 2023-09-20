from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_wordwise_truncated_mds_matrices import \
 generate_valid_points_for_truncated_mds_matrix
def test_generate_valid_points_for_truncated_mds_matrix():
    valid_points = generate_valid_points_for_truncated_mds_matrix(dimensions=(4, 4), max_pattern_value=3)
    assert len(valid_points) == 81
    assert valid_points[0] == '0000000000000000'
    assert valid_points[1] == '0000000110101010'
    assert valid_points[-2] == '1010100111111111'
    assert valid_points[-1] == '1010101011111111'

