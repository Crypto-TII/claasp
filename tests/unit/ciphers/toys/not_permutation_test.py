from claasp.ciphers.toys.not_permutation import NotPermutation


def test_not_permutation_component_id():
    assert NotPermutation(bit_size=8).component_from(0, 0).id == "not_0_0"
