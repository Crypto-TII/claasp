from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.permutations.gaston_sbox_permutation import GastonSboxPermutation
from claasp.ciphers.block_ciphers.aradi_block_cipher import AradiBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.cipher_modules.division_trail_search import *

"""

Given a number of rounds of a chosen cipher and a chosen output bit, this module produces a model that can either:
- obtain the ANF of this chosen output bit,
- find the degree of this ANF,
- or check the presence or absence of a specified monomial.

This module can only be used if the user possesses a Gurobi license.

"""

def test_find_anf_of_specific_output_bit():
    # Return the monomials of the anf of the chosen output bit
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpDivisionTrailModel(cipher)
    monomials = milp.find_anf_of_specific_output_bit(0)
    assert monomials == ['p18','k32','p0','p3p24','p0p3p9','p2p9p24','p0p2p9','p10p17','p2p9p10','p10k49','p3k56','p17p24','p2p9k56','p0p9p17','k50','p24k49','p0p9k49','p4','k49k56','p17k56']

    # Return the monomials of degree 2 of the anf of the chosen output bit
    cipher = SimonBlockCipher(number_of_rounds=2)
    milp = MilpDivisionTrailModel(cipher)
    monomials = milp.find_anf_of_specific_output_bit(0, fixed_degree=2)
    assert monomials ==['p17p24', 'p0p9k49', 'p3p24', 'p2p9k56', 'p10p17']

def test_find_degree_of_specific_output_bit():
    # Return the degree of the anf of the chosen output bit of the ciphertext
    cipher = AradiBlockCipher(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(0)
    assert degree == 3

    # Return the degree of the anf of the chosen output bit of the component xor_0_12
    cipher = AradiBlockCipher(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(0, chosen_cipher_output='xor_0_12')
    assert degree == 3

    cipher = SpeckBlockCipher(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(15)
    assert degree == 1

    cipher = GastonSboxPermutation(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(0)
    assert degree == 2

    cipher = MidoriBlockCipher(number_of_rounds=2)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(0)
    assert degree == 8

def test_check_presence_of_particular_monomial_in_specific_anf():
    # Return the all monomials that contains p230 of the anf of the chosen output bit
    cipher = GastonSboxPermutation(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    monomials = milp.check_presence_of_particular_monomial_in_specific_anf([("plaintext", 230)], 0)
    assert monomials == ['p181p230','p15p230','p33p230','p54p230','p55p230','p82p230','p100p230','p114p230','p115p230','p128p230','p140p230','p141p230','p146p230','p223p230','p205p230','p209p230','p210p230','p230p267','p230p313','p230p314','p230p315']
