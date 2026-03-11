from claasp.ciphers.toys.theta_keccak_permutation import ThetaKeccakPermutation


def test_theta_keccak_permutation_component_id():
    assert ThetaKeccakPermutation(bit_size=25).component_from(0, 0).id == "theta_keccak_0_0"
