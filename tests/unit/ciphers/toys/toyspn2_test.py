import sys
from io import StringIO

from claasp.ciphers.toys.toyspn2 import ToySPN2


def test_toyspn2():
    toyspn2 = ToySPN2()
    assert toyspn2.number_of_rounds == 2

    expected_evaluation = """
Round_0

rot_0_0_input = 0b000001
rot_0_0_output = 0b100000
intermediate_output_0_1_input = 0b100000
intermediate_output_0_1_output = 0b100000
xor_0_2_input = 0xfe0
xor_0_2_output = 0b011111
sbox_0_3_input = 0b011
sbox_0_3_output = 0b010
sbox_0_4_input = 0b111
sbox_0_4_output = 0b111
rot_0_5_input = 0b010111
rot_0_5_output = 0b101011
intermediate_output_0_6_input = 0b101011
intermediate_output_0_6_output = 0b101011

Round_1

rot_1_0_input = 0b100000
rot_1_0_output = 0b010000
intermediate_output_1_1_input = 0b010000
intermediate_output_1_1_output = 0b010000
xor_1_2_input = 0xad0
xor_1_2_output = 0b111011
sbox_1_3_input = 0b111
sbox_1_3_output = 0b111
sbox_1_4_input = 0b011
sbox_1_4_output = 0b010
rot_1_5_input = 0b111010
rot_1_5_output = 0b011101
intermediate_output_1_6_input = 0b011101
intermediate_output_1_6_output = 0b011101
cipher_output_1_7_input = 0b011101
cipher_output_1_7_output = 0b011101
"""
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    evaluation = hex(toyspn2.evaluate([0x3F, 0x01], verbosity=True))
    sys.stdout = old_stdout
    assert evaluation == '0x1d'
    assert result.getvalue() == expected_evaluation



