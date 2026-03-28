from claasp.ciphers.single_component_ciphers.shift_permutation import ShiftPermutation


def shift_right(value, amount, bit_size):
    mask = (1 << bit_size) - 1
    return (value >> amount) & mask


def test_shift_permutation_properties():
    shift = ShiftPermutation(bit_size=8, parameter=3)
    assert shift.type == 'permutation'
    assert shift.id == 'shift_permutation_p8_o8_r1'
    assert shift.component_from(0, 0).id == 'shift_0_0'

    value = 0x96
    assert shift.evaluate([value]) == shift_right(value, 3, 8)