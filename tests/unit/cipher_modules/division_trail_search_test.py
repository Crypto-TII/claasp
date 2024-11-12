from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.permutations.gaston_sbox_permutation import GastonSboxPermutation
from claasp.ciphers.block_ciphers.aradi_block_cipher import AradiBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.division_trail_search import *

def test_get_where_component_is_used():
    cipher = SimonBlockCipher(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    predecessors = ['intermediate_output_0_0', 'rot_0_1', 'rot_0_2', 'rot_0_3', 'and_0_4', 'xor_0_5', 'xor_0_6', 'intermediate_output_0_7', 'cipher_output_0_8']
    input_id_link_needed = 'xor_0_6'
    block_needed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    occurences = milp.get_where_component_is_used(predecessors, input_id_link_needed, block_needed)
    assert list(occurences.keys()) == ['plaintext', 'key', 'rot_0_1', 'rot_0_2', 'rot_0_3', 'and_0_4', 'xor_0_5', 'xor_0_6']

def test_get_monomial_occurences():
    cipher = GastonSboxPermutation(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    component = cipher.get_component_from_id('sbox_0_30')
    anfs = milp.get_anfs_from_sbox(component)
    assert len(anfs) == 5

def test_find_degree_of_specific_output_bit():
    cipher = AradiBlockCipher(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    degree = milp.find_degree_of_specific_output_bit(0)
    assert degree == 3

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

def test_check_presence_of_particular_monomial_in_specific_anf():
    cipher = GastonSboxPermutation(number_of_rounds=1)
    milp = MilpDivisionTrailModel(cipher)
    monomials = milp.check_presence_of_particular_monomial_in_specific_anf([("plaintext", 230)], 0)
    assert monomials == ['p181p230','p15p230','p33p230','p54p230','p55p230','p82p230','p100p230','p114p230','p115p230','p128p230','p140p230','p141p230','p146p230','p223p230','p205p230','p209p230','p210p230','p230p267','p230p313','p230p314','p230p315']
