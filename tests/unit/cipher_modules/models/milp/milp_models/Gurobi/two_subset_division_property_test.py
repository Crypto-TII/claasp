import pytest

from claasp.cipher_modules.models.milp.milp_models.Gurobi.two_subset_division_property import *
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.block_ciphers.hight_block_cipher import HightBlockCipher

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
        milp.add_not_constraints(None)


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


@pytest.mark.skip(reason="Requires Gurobi license")
def test_and_and_or_two_subset_trails():
    # y = x0 & x1 and y = x0 | x1 have the same two-subset trails: with the output exponent fixed
    # to 1 the feasible inputs are exactly (0,1), (1,0), (1,1)
    from gurobipy import GRB

    for cipher in (AndCipher(word_bit_size=1, number_of_inputs=2), OrCipher(word_bit_size=1, number_of_inputs=2)):
        feasible = []
        for a0 in (0, 1):
            for a1 in (0, 1):
                milp = MilpTwoSubsetDivisionPropertyModel(cipher)
                milp.build_generic_model_for_specific_output_bit(0)
                model = milp._model
                model.Params.OutputFlag = 0
                model.addConstr(model.getVarByName(f"{cipher.inputs[0]}[0]") == a0)
                model.addConstr(model.getVarByName(f"{cipher.inputs[1]}[0]") == a1)
                model.update()
                model.optimize()
                if model.Status == GRB.OPTIMAL:
                    feasible.append((a0, a1))
        assert feasible == [(0, 1), (1, 0), (1, 1)]


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_balanced_over_cube_scan_simon32_13():
    # Xiang et al. 2016, E.1: 13-round SIMON32, (c a^15, a^16) -> (?^16, b^16); nothing one round later.
    cube = [f"p{i}" for i in range(1, 32)]
    cipher = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=13)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    result = milp.is_balanced_over_cube_scan(list(range(32)), cube, independent_round_keys=True)
    assert [j for j in range(32) if result[j]] == list(range(16, 32))
    cipher = SimonBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=14)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    assert milp.is_balanced_at_specific_output_bit_over_cube_with_independent_round_keys(16, cube) is False


def test_full_adder_two_subset_table_has_11_trails():
    # one bit slice of the modular addition, (x, y, c) -> (s, c'); no solve
    table = MilpTwoSubsetDivisionPropertyModel.full_adder_two_subset_table()
    assert len(table) == 11
    assert (0b000, 0b00) in table and (0b111, 0b11) in table
    # two active inputs reach the carry only, a single one reaches either output
    assert {v for u, v in table if u == 0b110} == {0b10}
    assert {v for u, v in table if u == 0b001} == {0b01, 0b10}


def test_keyless_model_refused_when_round_keys_are_added():
    # HIGHT adds its subkeys modularly: dropping them is not sound, the independent-key model must be used
    milp = MilpTwoSubsetDivisionPropertyModel(HightBlockCipher(number_of_rounds=2))
    with pytest.raises(ValueError):
        milp._keyless_submodel(keep_round_key_injection=False)


@pytest.mark.skip(reason="Requires Gurobi license")
def test_is_cube_monomial_feasible_keyless_lea_6():
    # Sun et al. (ePrint 2016/1101) B.2: 6-round LEA, (A^32, C^32, C^32, C^32) -> bit 4 of word X1 balanced, only
    cipher = LeaBlockCipher(block_bit_size=128, key_bit_size=128, number_of_rounds=6, reorder_input_and_output=False)
    milp = MilpTwoSubsetDivisionPropertyModel(cipher)
    cube = [f"p{i}" for i in range(32)]
    assert milp.is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless(36, cube) is False
    assert milp.is_cube_monomial_feasible_at_specific_output_bit_over_cube_keyless(37, cube) is True
