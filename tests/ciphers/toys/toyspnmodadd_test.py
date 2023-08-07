import sys
from io import StringIO

from claasp.ciphers.toys.toyspnmodadd import ToySPNmodadd


def test_toyspnmodadd():
    toyspnmodadd = ToySPNmodadd()
    assert toyspnmodadd.number_of_rounds == 2

    plaintext = 0x3F
    key = 0x3F
    ciphertext = 0x28
    assert toyspnmodadd.evaluate([plaintext, key]) == ciphertext

    assert hex(toyspnmodadd.evaluate([plaintext, key])) == '0x28'
    expected_evaluation = """
Round_0

rot_0_0_input = 0b111110
rot_0_0_output = 0b011111
intermediate_output_0_1_input = 0b011111
intermediate_output_0_1_output = 0b011111
modadd_0_2_input = 0xfdf
modadd_0_2_output = 0b011110
sbox_0_3_input = 0b011
sbox_0_3_output = 0b010
sbox_0_4_input = 0b110
sbox_0_4_output = 0b100
rot_0_5_input = 0b010100
rot_0_5_output = 0b001010
intermediate_output_0_6_input = 0b001010
intermediate_output_0_6_output = 0b001010

Round_1

rot_1_0_input = 0b011111
rot_1_0_output = 0b101111
intermediate_output_1_1_input = 0b101111
intermediate_output_1_1_output = 0b101111
modadd_1_2_input = 0x2af
modadd_1_2_output = 0b111001
sbox_1_3_input = 0b111
sbox_1_3_output = 0b111
sbox_1_4_input = 0b001
sbox_1_4_output = 0b101
rot_1_5_input = 0b111101
rot_1_5_output = 0b111110
intermediate_output_1_6_input = 0b111110
intermediate_output_1_6_output = 0b111110
cipher_output_1_7_input = 0b111110
cipher_output_1_7_output = 0b111110
"""
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toyspnmodadd.evaluate([0x3F, 0x3E], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0x3e'
    assert result.getvalue() == expected_evaluation

    toyspnmodadd = ToySPNmodadd(block_bit_size=9, key_bit_size=9, number_of_rounds=10)
    assert hex(toyspnmodadd.evaluate([0x1FF, 0x1FE])) == '0x24'

    toyspnmodadd = ToySPNmodadd(block_bit_size=8, key_bit_size=8,
                      sbox=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0], rotation_layer=-2,
                      number_of_rounds=10)
    assert hex(toyspnmodadd.evaluate([0xFF, 0xFE])) == '0xee'
