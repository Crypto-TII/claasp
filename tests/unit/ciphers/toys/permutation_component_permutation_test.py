from claasp.ciphers.toys.permutation_component_permutation import PermutationComponentPermutation


def test_permutation_component_permutation_component_id():
    assert PermutationComponentPermutation().component_from(0, 0).id == "linear_layer_0_0"
