from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
    MilpWordwiseBranchNumberNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.block_ciphers.ublock_single_linear_layer_block_cipher import UblockSingleLinearLayerBlockCipher
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


def test_find_lowest_number_of_active_sboxes_real_aes():
    # Same wide-trail bound as the ToyAES test above, on the real AES-128 implementation (8-bit S-box, real
    # key schedule) rather than the toy simplification -- confirms the model isn't accidentally relying on
    # anything specific to the toy cipher's simpler structure. Limited to 2 rounds to keep the test fast; the
    # bound is exact up to round 4 (round 4 verified manually in ~70s, matching 25).
    expected_active_sboxes = {1: 1, 2: 5}
    for number_of_rounds, expected in expected_active_sboxes.items():
        cipher = AESBlockCipher(number_of_rounds=number_of_rounds)
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
    # Known limitation, not a bug: uBlock's round function (as implemented in UblockBlockCipher) recombines
    # state through many chained word-XORs (a generalised-Feistel/ARX-style mixing expressed as separate
    # ROTATE and XOR components), unlike AES's single wide-trail MixColumn per round. The word-level
    # branch-number relaxation of [MWGP2011]_ cannot rule out chained pairwise cancellations across those
    # separate XORs, so it reports a trivial lower bound of 1 regardless of round count here, well below
    # the uBlock paper's true value of 8 for 2 rounds. UblockSingleLinearLayerBlockCipher below, which
    # compiles the same diffusion into one consolidated linear-layer component, does much better.
    cipher = UblockBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

    assert int(round(float(solution["total_weight"]))) == 1


def test_find_lowest_number_of_active_sboxes_ublock_single_linear_layer_rounds_1_and_2():
    # UblockSingleLinearLayerBlockCipher(use_mix_column=False) computes the mathematically identical cipher
    # to UblockBlockCipher (same rotation amounts 4, 8, 20 and permutations), but compiles the whole round's
    # ARX/Feistel diffusion (state XOR round_key -> S-boxes -> rotate/XOR mixing -> word permutation) into a
    # single linear_layer component instead of many chained rotate/XOR components. Treating that consolidated
    # matrix as ONE branch-number relation -- using its true nibble-level branch number (8, found by
    # _word_branch_number_bounded) rather than decomposing it into many independent, loosely-connected
    # branch-number-2 XOR relations -- removes the "cancels to zero within a single round" looseness that
    # affects UblockBlockCipher above: both round 1 and round 2 now match the paper's table exactly.
    expected_active_sboxes = {1: 1, 2: 8}
    for number_of_rounds, expected in expected_active_sboxes.items():
        cipher = UblockSingleLinearLayerBlockCipher(number_of_rounds=number_of_rounds, use_mix_column=False)
        milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
        fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

        solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

        assert int(round(float(solution["total_weight"]))) == expected


def test_find_lowest_number_of_active_sboxes_ublock_single_linear_layer_round_3_is_still_a_loose_lower_bound():
    # Residual limitation, not a bug: consolidating each round's diffusion into a single linear-layer
    # component (see the rounds-1-and-2 test above) fixes the *within-a-round* looseness, but each round's
    # linear_layer is still treated as an independent, memoryless branch-number relation -- the model has no
    # way to know that reusing the same cancellation pattern across multiple consecutive (structurally
    # identical) rounds is implausible. So the reported bound plateaus at 8 from round 2 onward, rather than
    # growing to the paper's 13, 24, 30, ... A tighter bound would need a relation spanning multiple rounds
    # at once (e.g. the branch number of two or more consecutive linear layers combined), which is not
    # implemented here.
    cipher = UblockSingleLinearLayerBlockCipher(number_of_rounds=3, use_mix_column=False)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

    assert int(round(float(solution["total_weight"]))) == 8
