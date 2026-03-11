from claasp.ciphers.toys.shift_rows_permutation import ShiftRowsPermutation


def test_shift_rows_permutation_component_id():
    assert ShiftRowsPermutation(bit_size=4).component_from(0, 0).id == "shift_rows_0_0"
