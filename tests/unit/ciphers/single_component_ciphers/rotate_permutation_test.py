from claasp.ciphers.single_component_ciphers.rotate_permutation import RotatePermutation


def rotate_right(value, amount, bit_size):
    mask = (1 << bit_size) - 1
    amount %= bit_size
    return ((value >> amount) | ((value << (bit_size - amount)) & mask)) & mask


def test_rotate_permutation_properties():
    rotate = RotatePermutation(bit_size=8, parameter=3)
    assert rotate.type == 'permutation'
    assert rotate.id == 'rotate_permutation_p8_o8_r1'
    assert rotate.component_from(0, 0).id == 'rot_0_0'

    value = 0x96
    assert rotate.evaluate([value]) == rotate_right(value, 3, 8)
