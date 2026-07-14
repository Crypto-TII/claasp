import time
from types import SimpleNamespace

import pytest

from claasp.cipher_modules.models.milp.milp_models import (
    milp_wordwise_branch_number_number_of_active_sboxes_model as model_module,
)
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_branch_number_number_of_active_sboxes_model import (
    MilpWordwiseBranchNumberNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.utils import get_single_key_scenario_format_for_fixed_values
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.block_ciphers.ublock_single_linear_layer_block_cipher import UblockSingleLinearLayerBlockCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.name_mappings import MIX_COLUMN, WORD_OPERATION


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
    # anything specific to the toy cipher's simpler structure.
    expected_active_sboxes = {1: 1, 2: 5, 3: 9, 4: 25}
    for number_of_rounds, expected in expected_active_sboxes.items():
        cipher = AESBlockCipher(number_of_rounds=number_of_rounds)
        milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
        fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

        solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

        assert int(round(float(solution["total_weight"]))) == expected


def test_find_lowest_number_of_active_sboxes_real_aes_is_fast():
    # [MWGP2011]_ reports that none of their AES active-S-box optimization problems (up to 14 rounds) took
    # longer than 0.40s on a single core with CPLEX. This model's *build* time (as opposed to the MILP solve
    # itself, which depends on the solver -- this uses the free GLPK, not CPLEX) is dominated by
    # MilpWordwiseBranchNumberNumberOfActiveSboxesModel._word_branch_number computing each linear component's
    # exact word-level branch number via the MiniZinc-based solvers in
    # cipher_modules.component_analysis_tests (a real constraint solve, ~1-3s per unique matrix), but this is
    # cached per matrix, so it is paid once (AES-128 only has one MixColumn matrix, reused across every column
    # and round) rather than once per round. A generous 15s ceiling is used here (rather than asserting 0.4s
    # directly) to absorb CI/CPU variance, MiniZinc process-spawn overhead, and the slower open-source solver,
    # while still catching any regression back to the ~70s scale seen before this model was optimized.
    cipher = AESBlockCipher(number_of_rounds=4)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    start = time.time()
    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)
    elapsed = time.time() - start

    assert int(round(float(solution["total_weight"]))) == 25
    assert elapsed < 15, f"expected AES round 4 to solve in well under 15s, took {elapsed:.1f}s"


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
    # separate XORs, so it reports a loose lower bound of 6 here, below the uBlock paper's true value of 8
    # for 2 rounds. UblockSingleLinearLayerBlockCipher below, which compiles the same diffusion into one
    # consolidated linear-layer component, does much better (exact for rounds 1-2).
    cipher = UblockBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    fixed_variables = get_single_key_scenario_format_for_fixed_values(cipher)

    solution = milp.find_lowest_number_of_active_sboxes(fixed_variables)

    assert int(round(float(solution["total_weight"]))) == 6


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


def test_init_model_requires_uniform_sbox_word_size():
    cipher = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)

    with pytest.raises(ValueError, match="exactly one, uniform S-box input size"):
        milp.init_model_in_sage_milp_class()


def test_wordwise_helpers_reject_unaligned_or_unsupported_cases():
    cipher = ToyAESBlockCipher(word_size=4, state_size=4, number_of_rounds=1)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    milp.init_model_in_sage_milp_class()

    with pytest.raises(NotImplementedError, match="not aligned"):
        milp._resolve_word_ids("plaintext", [1, 2, 3, 4])

    with pytest.raises(NotImplementedError, match="only fixing to the all-zero"):
        milp._add_fixed_variable_constraint(
            {
                "component_id": "plaintext",
                "constraint_type": "equal",
                "bit_positions": range(4),
                "bit_values": [1, 0, 0, 0],
            }
        )

    unsupported = SimpleNamespace(
        id="and_0_0",
        type=WORD_OPERATION,
        description=["AND"],
        output_bit_size=4,
    )
    with pytest.raises(NotImplementedError, match="word operation 'AND'"):
        milp._component_constraints(unsupported)


def test_wordwise_permutation_helpers_reject_non_word_permutations():
    cipher = ToyAESBlockCipher(word_size=4, state_size=4, number_of_rounds=1)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    milp.init_model_in_sage_milp_class()

    rotate_right = SimpleNamespace(description=["ROTATE", 1], output_bit_size=8)
    rotate_left = SimpleNamespace(description=["ROTATE", -1], output_bit_size=8)

    assert milp._rotate_bit_perm(rotate_right) == [7, 0, 1, 2, 3, 4, 5, 6]
    assert milp._rotate_bit_perm(rotate_left) == [1, 2, 3, 4, 5, 6, 7, 0]

    bad_permutation = SimpleNamespace(
        id="perm_0_0",
        input_id_links=["plaintext"],
        input_bit_positions=[list(range(8))],
    )
    with pytest.raises(NotImplementedError, match="not sourced from a single input word"):
        milp._exact_permutation_constraints(
            bad_permutation, ["perm_0_0_0", "perm_0_0_1"], [0, 4, 1, 2, 3, 5, 6, 7]
        )

    bad_mix_column = SimpleNamespace(id="mix_column_0_0", type=MIX_COLUMN, description=[[[1]], 0, 2])
    with pytest.raises(NotImplementedError, match="cell size is not a multiple"):
        milp._mix_column_permutation_constraints(bad_mix_column, ["mix_column_0_0_0"])


def test_word_branch_number_is_cached(monkeypatch):
    cipher = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseBranchNumberNumberOfActiveSboxesModel(cipher)
    milp.init_model_in_sage_milp_class()
    mix_column = [component for component in cipher.get_all_components() if component.type == MIX_COLUMN][0]
    calls = []

    def fake_branch_number(matrix):
        calls.append(matrix)
        return 5

    monkeypatch.setattr(model_module, "compute_branch_number_from_field_matrix_with_minizinc", fake_branch_number)

    assert milp._word_branch_number(mix_column) == 5
    assert milp._word_branch_number(mix_column) == 5
    assert len(calls) == 1
