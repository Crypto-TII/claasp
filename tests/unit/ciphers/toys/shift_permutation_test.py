from claasp.ciphers.toys.shift_permutation import ShiftPermutation


def test_shift_permutation_component_id():
    assert ShiftPermutation(bit_size=8, parameter=-2).component_from(0, 0).id == "shift_0_0"
