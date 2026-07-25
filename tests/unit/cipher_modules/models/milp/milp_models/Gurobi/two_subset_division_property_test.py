import pytest

from claasp.cipher_modules.models.milp.milp_models.Gurobi.two_subset_division_property import *
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher

"""

Two-subset bit-based division property (2SDP) MILP model.

An INFEASIBLE model proves the chosen output bit balanced over the cube (an integral
distinguisher). Sound but coarser than the exact monomial prediction model, in exchange
for a much cheaper, faster model.

The tests that solve a model require a Gurobi license; the S-box-table, encoding-flag and
unsupported-component tests do not.

"""

# uBlock 4-bit S-box.
UBLOCK_SBOX = [0x7, 0x4, 0x9, 0xC, 0xB, 0xA, 0xD, 0x8, 0xF, 0xE, 0x1, 0x6, 0x0, 0x3, 0x2, 0x5]


def test_ublock_sbox_2sdp_table_has_42_trails():
    cipher = SboxCipher(bit_size=4, lookup_table=UBLOCK_SBOX)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    sbox = [c for c in cipher.get_all_components() if c.type == "sbox"][0]
    table, n, m = milp.get_valid_monomial_exponents_table(sbox)
    assert (n, m) == (4, 4)
    assert sum(len(us) for us in table.values()) == 42


def test_sbox_encoding_flag_defaults_to_onehot():
    # The S-box encoder is one-hot by default and stores whatever flag is passed (no solve).
    cipher = SboxCipher(bit_size=4, lookup_table=UBLOCK_SBOX)
    assert MilpTwoSubsetDivisionPropertyModel(cipher)._sbox_encoding == "onehot"
    assert MilpTwoSubsetDivisionPropertyModel(cipher, sbox_encoding="convexhull")._sbox_encoding == "convexhull"
    assert MilpTwoSubsetDivisionPropertyModel(cipher, sbox_encoding="espresso")._sbox_encoding == "espresso"


def test_unsupported_component_raises():
    # Components without a 2SDP override refuse rather than return an unsound result.
    cipher = UblockBlockCipher(number_of_rounds=1)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    with pytest.raises(NotImplementedError):
        milp.add_and_constraints(None)


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_balanced_at_specific_output_bit_over_cube_ublock_5():
    cipher = UblockBlockCipher(number_of_rounds=5)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    cube = [f"p{i}" for i in list(range(48, 64)) + list(range(112, 128))]
    assert milp.is_balanced_at_specific_output_bit_over_cube(3, cube) is True
    assert milp.is_balanced_at_specific_output_bit_over_cube(0, cube) is False


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_balanced_over_cube_scan_ublock_5():
    cipher = UblockBlockCipher(number_of_rounds=5)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    cube = [f"p{i}" for i in list(range(48, 64)) + list(range(112, 128))]
    assert milp.is_balanced_over_cube_scan([0, 3], cube) == {0: False, 3: True}


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys_ublock_7():
    cipher = UblockBlockCipher(number_of_rounds=7)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    cube = [f"p{i}" for i in range(128) if i not in {0, 1, 2, 3}]
    assert milp.is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys(0, cube) is True


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless_ublock_6():
    cipher = UblockBlockCipher(number_of_rounds=6)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    cube = [f"p{i}" for i in range(36, 64)] + [f"p{i}" for i in range(100, 128)]
    assert milp.is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless(1, cube) is True
