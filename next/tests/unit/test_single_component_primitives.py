import pytest

from claasp_next.primitives.single_component_primitives import (
    And, Constant, Fsr, IdeaModmul, Identity, LinearLayer, MixColumn, Modadd,
    Modmul, Modsub, Not, Or, Permutation, Reverse, Rotate, Sbox, Shift,
    ShiftRows, Sigma, ThetaGaston, ThetaKeccak, ThetaXoodoo, VariableRotate,
    VariableShift, WordPermutation, Xor,
)


def test_nary_word_fixtures_match_native_integer_operations():
    values = (0b1010, 0b1100, 0b0111)
    assert And(4, 3).evaluate(*values) == (values[0] & values[1] & values[2])
    assert Or(4, 3).evaluate(*values) == (values[0] | values[1] | values[2])
    assert Xor(4, 3).evaluate(*values) == (values[0] ^ values[1] ^ values[2])
    assert Modadd(4, 3).evaluate(11, 7, 3) == (11 + 7 + 3) % 16
    assert Modmul(8).evaluate(13, 19) == (13 * 19) % 256
    assert Modsub(4).evaluate(11, 7) == 4
    assert IdeaModmul(4, modulus=17).evaluate(3, 5) == 15


def test_structural_and_unary_fixtures_preserve_boundaries():
    assert Constant(8, 0x5A).evaluate() == 0x5A
    assert Identity(16).evaluate(0xCAFE) == 0xCAFE
    assert Not(8).evaluate(Not(8).evaluate(0xA5)) == 0xA5
    assert Rotate(8, -2).evaluate(Rotate(8, 2).evaluate(0xA5)) == 0xA5
    assert Shift(8, 1).evaluate(0x81) == 0x40
    assert VariableRotate(8, 3).evaluate(0xA5, 0) == 0xA5
    assert VariableShift(8, 3).evaluate(0xA5, 0) == 0xA5
    assert Sbox(4).evaluate(0xA) == 0xA


def test_permutation_fixtures_use_destination_by_source_descriptions():
    assert Permutation(4).evaluate(0b1100) == 0b0011
    assert Permutation(8, (1, 0), 4).evaluate(0xAB) == 0xBA
    assert Reverse(8).evaluate(Reverse(8).evaluate(0xD2)) == 0xD2
    assert WordPermutation(2, 4).evaluate(0b00_01_10_11) == 0b11_00_01_10
    assert ShiftRows(1, 8, 4).evaluate(0x01020304) == 0x04010203
    with pytest.raises(ValueError, match="divisible"):
        Permutation(10, word_size=4)


def test_linear_field_feedback_and_permutation_specific_fixtures():
    # Legacy linear descriptions are column-oriented: this matrix maps 10 -> 11.
    assert LinearLayer(2, ((1, 1), (0, 1))).evaluate(0b10) == 0b11
    assert MixColumn(4).evaluate(0xABCD) == 0xABCD
    assert Fsr(4).evaluate(0b1010) == 0b0101
    assert Fsr(4, [[[4, [[0], [1]], [[0]]]], 1]).evaluate(0b1010) == 0b0101
    assert Sigma(8).evaluate(0xA5) == (0xA5 ^ 0xD2 ^ 0x69)
    assert ThetaGaston().evaluate(0) == 0
    assert ThetaKeccak().evaluate(0) == 0
    assert ThetaXoodoo().evaluate(0) == 0
