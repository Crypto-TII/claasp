from claasp.ciphers.toys.rotate_permutation import RotatePermutation


def test_rotate_permutation_component_id():
    assert RotatePermutation(bit_size=8, parameter=-3).component_from(0, 0).id == "rot_0_0"
