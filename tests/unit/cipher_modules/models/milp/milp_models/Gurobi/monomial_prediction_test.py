from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *

"""

Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
- obtain the ANF of this chosen output bit,
- find the degree of this ANF,
- or check the presence or absence of a specified monomial.

This module can only be used if the user possesses a Gurobi license.

"""

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

def test_find_upper_bound_degree_of_specific_output_bit():
    # Return an upper bound on the degree of the anf of the chosen output bit
    cipher = AESBlockCipher(number_of_rounds=2, word_size=2, state_size=2)
    milp = MilpMonomialPredictionModel(cipher)
    degree = milp.find_upper_bound_degree_of_specific_output_bit(0, chosen_cipher_output="mix_column_0_7")
    assert degree == 2

def test_find_superpoly_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=3)
    milp = MilpMonomialPredictionModel(cipher)
    R = milp.get_boolean_polynomial_ring()
    superpoly = milp.find_superpoly_of_specific_output_bit(cube=["p1", "p2"], output_bit_index=0)
    expected = R("p3*p10*p11 + p3*p10 + p4*p10 + p5*p10 + p10*p11*p18 + p10*p11*k50 + p10*p18 + p10*p19 + p10*k33 + p10*k50 + p10*k51 + p10 + p25 + k57")
    assert superpoly == expected

def test_find_exact_degree_of_superpoly_of_all_output_bits():
    cipher = SimonBlockCipher(number_of_rounds=4)
    milp = MilpMonomialPredictionModel(cipher)
    degrees = milp.find_exact_degree_of_superpoly_of_all_output_bits(["p1", "p2"])
    expected = [-1, -1, -1, -1, 2, 3, 3, 3, 3, -1, -1, -1, -1, 3, 3, 3, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, -1, -1, -1, -1, -1, 0]
    assert degrees == expected

def test_find_exact_degree_of_all_output_bits():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    degrees = milp.find_exact_degree_of_all_output_bits(which_var_degree="p")
    expected = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    assert degrees == expected

def test_check_anf_correctness():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    milp = MilpMonomialPredictionModel(cipher)
    check = milp.check_anf_correctness(14)
    assert check == True

def test_find_upper_bound_degree_of_cube_monomial_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p2"]
    degree = milp.find_upper_bound_degree_of_cube_monomial_of_specific_output_bit(0, cube)
    expected = 2
    assert degree == expected

def test_find_keycoeff_of_cube_monomial_of_specific_output_bit():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p9"]
    keycoeff = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(0, cube)
    R = milp.get_boolean_polynomial_ring()
    expected = R("k49")
    assert keycoeff == expected

def test_check_correctness_of_keycoeff_of_cube_monomial_or_superpoly():
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpMonomialPredictionModel(cipher)
    cube = ["p0", "p9"]
    keycoeff = milp.find_keycoeff_of_cube_monomial_of_specific_output_bit(0, cube)
    res = check_correctness_of_keycoeff_of_cube_monomial_or_superpoly(cipher, 0, cube, keycoeff)
    assert res == True
