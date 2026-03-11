from claasp.ciphers.toys.reverse_permutation import ReversePermutation


def test_reverse_permutation_component_id():
    assert ReversePermutation(bit_size=4).component_from(0, 0).id == "linear_layer_0_0"
