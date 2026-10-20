from claasp.cipher_modules.models.smt.utils.utils import (
    get_component_hex_value,
    smt_and,
    smt_assert,
    smt_carry,
    smt_distinct,
    smt_equivalent,
    smt_implies,
    smt_ite,
    smt_lipmaa,
    smt_not,
    smt_or,
    smt_xor,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_smt_and():
    assert smt_and(["a", "c", "e"]) == "(and a c e)"


def test_smt_assert():
    assert smt_assert("(= a b c)") == "(assert (= a b c))"


def test_smt_carry():
    assert smt_carry("x_3", "y_3", "c_2") == "(or (and x_3 y_3) (and x_3 c_2) (and y_3 c_2))"


def test_smt_distinct():
    assert smt_distinct("a", "q") == "(distinct a q)"


def test_smt_equivalent():
    assert smt_equivalent(["a", "b", "c", "d"]) == "(= a b c d)"


def test_smt_implies():
    assert smt_implies("(and a c)", "(or l f)") == "(=> (and a c) (or l f))"


def test_smt_ite():
    assert smt_ite("t", "(and a b)", "(and a e)") == "(ite t (and a b) (and a e))"


def test_smt_lipmaa():
    assert smt_lipmaa("hw", "alpha", "beta", "gamma", "beta_1") == "(or hw (not (xor alpha beta gamma beta_1)))"


def test_smt_not():
    assert smt_not("(xor a e)") == "(not (xor a e))"


def test_smt_or():
    assert smt_or(["b", "d", "f"]) == "(or b d f)"


def test_smt_xor():
    assert smt_xor(["b", "d", "f"]) == "(xor b d f)"


def test_get_component_hex_value():
    speck = SpeckBlockCipher(number_of_rounds=1)
    component = speck.component_from_id("rot_0_0")
    variable2value = {f"rot_0_0_{i}": 0 for i in range(16)}
    variable2value["rot_0_0_0"] = 1
    variable2value["rot_0_0_15"] = 1

    assert get_component_hex_value(component, "", variable2value) == "0x8001"
    # missing variables are considered as zero
    assert get_component_hex_value(component, "_o", variable2value) == "0x0000"
