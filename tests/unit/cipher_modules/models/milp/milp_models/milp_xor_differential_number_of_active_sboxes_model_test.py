from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_number_of_active_sboxes_model import (
    MilpXorDifferentialNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher


def test_find_lowest_number_of_active_sboxes_toyaes():
    # state_size=4 with a proper MDS MixColumn gives the same minimum active S-box counts as real AES
    # (Daemen & Rijmen, "The Design of Rijndael", 4-round wide-trail bound: 1, 5, 9, 25), independently
    # of the word size used for the S-box.
    expected_active_sboxes = {1: 1, 2: 5}
    for number_of_rounds, expected in expected_active_sboxes.items():
        cipher = ToyAESBlockCipher(word_size=4, state_size=4, number_of_rounds=number_of_rounds)
        milp = MilpXorDifferentialNumberOfActiveSboxesModel(cipher)
        fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

        solution = milp.find_lowest_number_of_active_sboxes(fixed_variables, solver_name="SCIP_EXT")

        assert int(round(float(solution["total_weight"]))) == expected


def test_find_lowest_number_of_active_sboxes_ublock():
    # Ground truth from the uBlock paper's Table "Active S-boxes of uBlock-128" (1 round).
    cipher = UblockBlockCipher(number_of_rounds=1)
    milp = MilpXorDifferentialNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables, solver_name="SCIP_EXT")

    assert int(round(float(solution["total_weight"]))) == 1
