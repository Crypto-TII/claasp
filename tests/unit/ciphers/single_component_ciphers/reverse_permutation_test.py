from claasp.ciphers.single_component_ciphers.reverse_permutation import ReversePermutation


def reverse_bits(value, bit_size):
    return int(f'{value:0{bit_size}b}'[::-1], 2)


def test_reverse_permutation_properties():
    reverse = ReversePermutation(bit_size=8)
    assert reverse.type == 'permutation'
    assert reverse.id == 'reverse_permutation_p8_o8_r1'
    assert reverse.component_from(0, 0).id == 'linear_layer_0_0'

    value = 0x96
    output = reverse.evaluate([value])
    assert output == reverse_bits(value, 8)
    assert reverse.evaluate([output]) == value
