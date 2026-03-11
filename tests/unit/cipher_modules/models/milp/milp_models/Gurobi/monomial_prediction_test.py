import pytest

from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *
from claasp.name_mappings import BLOCK_CIPHER
from claasp.cipher import Cipher

"""

Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
- obtain the ANF of this chosen output bit,
- find the degree of this ANF,
- or check the presence or absence of a specified monomial.

This module can only be used if the user possesses a Gurobi license.

"""

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_anf_of_specific_output_bit():
    # Return the anf of the chosen output bit
    cipher = GimliPermutation(number_of_rounds=1, word_size=4)
    milp = MilpMonomialPredictionModel(cipher)
    R = milp.get_boolean_polynomial_ring()
    poly = milp.find_anf_of_specific_output_bit(0, chosen_cipher_output="xor_0_16")
    expected = R("p0 + p1*p33 + p1 + p17 + p33")
    assert poly == expected

    cipher = TriviumStreamCipher(keystream_bit_len=1, number_of_initialization_clocks=13)
    milp = MilpMonomialPredictionModel(cipher)
    R = milp.get_boolean_polynomial_ring()
    poly = milp.find_anf_of_specific_output_bit(0)
    expected = R("k0 + k27 + i9 + i24")
    assert poly == expected

    cipher = AsconPermutation(number_of_rounds=1)
    milp = MilpMonomialPredictionModel(cipher)
    R = milp.get_boolean_polynomial_ring()
    poly = milp.find_anf_of_specific_output_bit(0, chosen_cipher_output="xor_0_15")
    expected = R("p0 + p64*p128 + p128 + p256")
    assert poly == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_upper_bound_degree_of_specific_output_bit():
    # Return an upper bound on the degree of the anf of the chosen output bit
    cipher = ToyAESBlockCipher(number_of_rounds=2, word_size=2, state_size=2)
    milp = MilpMonomialPredictionModel(cipher)
    degree = milp.find_upper_bound_degree_of_specific_output_bit(0, chosen_cipher_output="mix_column_0_7")
    assert degree == 2

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_superpoly_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=3)
    milp = MilpMonomialPredictionModel(cipher)
    R = milp.get_boolean_polynomial_ring()
    superpoly = milp.find_superpoly_of_specific_output_bit(cube=["p1", "p2"], output_bit_index=0)
    expected = R("p3*p10*p11 + p3*p10 + p4*p10 + p5*p10 + p10*p11*p18 + p10*p11*k50 + p10*p18 + p10*p19 + p10*k33 + p10*k50 + p10*k51 + p10 + p25 + k57")
    assert superpoly == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_exact_degree_of_superpoly_of_all_output_bits():
    cipher = SimonBlockCipher(number_of_rounds=4)
    milp = MilpMonomialPredictionModel(cipher)
    degrees = milp.find_exact_degree_of_superpoly_of_all_output_bits(["p1", "p2"])
    expected = [-1, -1, -1, -1, 2, 3, 3, 3, 3, -1, -1, -1, -1, 3, 3, 3, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 0]
    assert degrees == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_exact_degree_of_all_output_bits():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    degrees = milp.find_exact_degree_of_all_output_bits(which_var_degree="p")
    expected = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    assert degrees == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_check_anf_correctness():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    milp = MilpMonomialPredictionModel(cipher)
    check = milp.check_anf_correctness(14)
    assert check == True

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_upper_bound_degree_of_cube_monomial_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p2"]
    degree = milp.find_upper_bound_degree_of_cube_monomial_of_specific_output_bit(0, cube)
    expected = 2
    assert degree == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_keycoeff_of_cube_monomial_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p9"]
    keycoeff = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(0, cube)
    R = milp.get_boolean_polynomial_ring()
    expected = R("k49")
    assert keycoeff == expected

@pytest.mark.skip(reason="Requires Gurobi license")
def test_check_correctness_of_keycoeff_of_cube_monomial_or_superpoly():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p9"]
    keycoeff = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(0, cube)
    res = check_correctness_of_keycoeff_of_cube_monomial_or_superpoly(cipher, 0, cube, keycoeff)
    assert res == True
@pytest.mark.skip(reason="Requires Gurobi license")
def test_modmul_modeling_correctness_via_anf_exhaustive():
    """
    Verify MODMUL modeling correctness by generating ANFs for all output bits
    and comparing their evaluation against the actual product for all 3-bit inputs.
    """
    n = 3
    cipher = Cipher("test_modmul_3", BLOCK_CIPHER, ["input"], [n * 2], n)
    cipher.add_round()
    cipher.add_MODMUL_component(
        ["input", "input"],
        [list(range(n)), list(range(n, 2 * n))],
        n,
        2**n
    )
    cipher.add_cipher_output_component(["modmul_0_0"], [list(range(n))], n)

    milp = MilpMonomialPredictionModel(cipher)
    anfs = [milp.find_anf_of_specific_output_bit(i) for i in range(n)]
    for x in range(2**n):
        for y in range(2**n):
            subs = {}
            for i in range(n):
                subs[f"i{i}"] = (x >> (n - 1 - i)) & 1
                subs[f"i{n + i}"] = (y >> (n - 1 - i)) & 1
            res_bits = [int(anf.subs(subs)) for anf in anfs]
            computed_z = 0
            for bit in res_bits:
                computed_z = (computed_z << 1) | bit
            expected_z = (x * y) % (2**n)
            assert computed_z == expected_z, (
                f"ModMul fail for n={n}, x={x}, y={y}: "
                f"Expected {expected_z}, got {computed_z}"
            )

@pytest.mark.skip(reason="Requires Gurobi license")
def test_msx64_degree_upper_bound():
    from claasp.ciphers.block_ciphers.msx_block_cipher import MSXBlockCipher
    cipher = MSXBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=1)
    milp = MilpMonomialPredictionModel(cipher)
    assert milp.find_upper_bound_degree_of_specific_output_bit(0) == 32

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_degree_in_cube_vars_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=13)
    milp = MilpMonomialPredictionModel(cipher)
    cube = [f"p{i}" for i in range(1, 32)]
    d = milp.find_degree_in_cube_vars_of_specific_output_bit(16, cube)
    assert d == 30