from claasp.ciphers.toys.theta_xoodoo_permutation import ThetaXoodooPermutation


def test_theta_xoodoo_permutation_component_id():
    assert ThetaXoodooPermutation().component_from(0, 0).id == "theta_xoodoo_0_0"
