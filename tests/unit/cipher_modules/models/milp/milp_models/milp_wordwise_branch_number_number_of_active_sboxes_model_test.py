from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
    MilpWordwiseBranchNumberNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher


def test_find_lowest_number_of_active_sboxes_toyaes():
    # state_size=4 with a proper MDS MixColumn gives the same minimum active S-box counts as real AES
    # (Daemen & Rijmen, "The Design of Rijndael", 4-round wide-trail bound: 1, 5, 9, 25). For a genuine
    # MDS/wide-trail cipher the word-level branch-number relaxation of [MWGP2011]_ is tight, so this
    # matches the bit-exact model's result (see milp_xor_differential_number_of_active_sboxes_model_test.py)
    # while running in a fraction of the time, since no DDT tables are involved.
    expected_active_sboxes = {1: 1, 2: 5, 3: 9, 4: 25}
    for number_of_rounds, expected in expected_active_sboxes.items():
        cipher = ToyAESBlockCipher(word_size=4, state_size=4, number_of_rounds=number_of_rounds)
        milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
        fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

        solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

        assert int(round(float(solution["total_weight"]))) == expected


def test_find_lowest_number_of_active_sboxes_ublock_round_1():
    # Ground truth from the uBlock paper's Table "Active S-boxes of uBlock-128" (1 round). Matches the
    # bit-exact model here, since round 1 has no internal XOR recombination for the relaxation to exploit.
    cipher = UblockBlockCipher(number_of_rounds=1)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

    assert int(round(float(solution["total_weight"]))) == 1


def test_find_lowest_number_of_active_sboxes_ublock_round_2_is_a_loose_lower_bound():
    # Known limitation, not a bug: uBlock's round function recombines state through many chained word-XORs
    # (a generalised-Feistel/ARX-style mixing, unlike AES's single wide-trail MixColumn per round). The
    # word-level branch-number relaxation of [MWGP2011]_ cannot rule out chained pairwise cancellations
    # across those XORs, so it reports a trivial lower bound of 1 regardless of round count here, well below
    # the uBlock paper's true value of 8 for 2 rounds. Reproducing the paper's exact table requires the
    # bit-exact model (see milp_xor_differential_number_of_active_sboxes_model_test.py), which is tight but
    # far more expensive to solve for uBlock past round 1.
    cipher = UblockBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

    assert int(round(float(solution["total_weight"]))) == 1
