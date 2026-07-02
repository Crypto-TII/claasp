import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules.models.milp.milp_models.Gurobi.monomial_prediction import *
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.permutations.gimli_permutation import GimliPermutation
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.name_mappings import BLOCK_CIPHER

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
    cipher.add_modmul_component(
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

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_coefficient_of_cube_by_divide_and_conquer_gaston():
    cipher = GastonPermutation(number_of_rounds=3)
    milp = MilpMonomialPredictionModel(cipher)
    cube = [f"p{i}" for i in range(256, 264)]
    coeff = milp.find_coefficient_of_cube_by_divide_and_conquer(
        output_bit_index=61,
        middle_round=1,
        cube=cube
    )
    assert coeff == 1

@pytest.mark.skip(reason="Requires Gurobi license")
def test_find_superpoly_by_divide_and_conquer_speck():
    cipher = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=6)
    cipher = cipher.remove_key_schedule()
    milp = MilpMonomialPredictionModel(cipher)
    inactive_bits = [24, 26]
    cube = [f"p{i}" for i in range(32) if i not in inactive_bits]
    res = milp.find_coefficient_of_cube_by_divide_and_conquer(
        output_bit_index=15,
        middle_round=2,
        cube=cube
    )
    assert str(res) == "k²7*k²8 + k²7*k³6 + k²7*k³13 + k²8*k³5 + k²8*k³12 + k²8 + k³5*k³6 + k³5*k³13 + k³6*k³12 + k³6 + k³12*k³13 + k³13"

# S-boxes taken from CLAASP cipher definitions. Only xoodoo (hull path) and aes
# (ANF-circuit path) are active, to keep the test fast; the rest are commented out.
SBOXES_UNDER_TEST = [
    ("xoodoo", 3, [0, 5, 3, 2, 6, 1, 4, 7]),
    # ("aradi", 4, [0, 1, 2, 3, 4, 13, 15, 6, 8, 11, 5, 14, 12, 7, 10, 9]),
    # ("present", 4, [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]),
    # ("skinny", 4, [12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15]),
    # ("prince", 4, [11, 15, 3, 2, 10, 12, 9, 1, 6, 7, 8, 0, 14, 5, 13, 4]),
    # ("gaston", 5, [0x00, 0x05, 0x0a, 0x0b, 0x14, 0x11, 0x16, 0x17, 0x09, 0x0c, 0x03, 0x02, 0x0d, 0x08, 0x0f, 0x0e,
    #              0x12, 0x15, 0x18, 0x1b, 0x06, 0x01, 0x04, 0x07, 0x1a, 0x1d, 0x10, 0x13, 0x1e, 0x19, 0x1c, 0x1f]),
    ("aes", 8, [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]),
]


def _check_sbox_anf(name, n, sbox):
    cipher = Cipher(f"test_sbox_{name}", BLOCK_CIPHER, ["input"], [n], n)
    cipher.add_round()
    cipher.add_sbox_component(["input"], [list(range(n))], n, sbox)
    cipher.add_cipher_output_component(["sbox_0_0"], [list(range(n))], n)

    milp = MilpMonomialPredictionModel(cipher)
    anfs = [milp.find_anf_of_specific_output_bit(i) for i in range(n)]
    for x in range(2**n):
        subs = {f"i{j}": (x >> (n - 1 - j)) & 1 for j in range(n)}
        computed = 0
        for anf in anfs:
            computed = (computed << 1) | int(anf.subs(subs))
        assert computed == sbox[x], f"{name} S-box ANF mismatch at x={x}: expected {sbox[x]}, got {computed}"

@pytest.mark.skip(reason="Requires Gurobi license")
def test_sbox_anf_correctness():
    """
    Verify exact S-box (3SDP-woU) modeling on several S-boxes up to 5 bits. For each,
    recover the ANF of every output bit from a single-S-box cipher and check the ANFs
    reconstruct the full S-box truth table over all 2^n inputs.
    """
    for name, n, sbox in SBOXES_UNDER_TEST:
        _check_sbox_anf(name, n, sbox)

