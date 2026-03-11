from claasp.ciphers.toys.sigma_permutation import SigmaPermutation


def test_sigma_permutation_component_id():
    assert SigmaPermutation(bit_size=4).component_from(0, 0).id == "sigma_0_0"
