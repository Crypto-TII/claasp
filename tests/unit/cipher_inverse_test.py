import pytest

from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.cipher_modules.inverse_cipher import prune_components_outside_round_range


def find_dangling_input_links(cipher):
    component_ids = {c.id for c in cipher.get_all_components()}
    declared_inputs = set(cipher.inputs)

    dangling = []
    for component in cipher.get_all_components():
        for link in component.input_id_links:
            if link and link not in component_ids and link not in declared_inputs:
                dangling.append((component.id, link))

    return dangling



@pytest.mark.parametrize(
    "cipher_factory",
    [
        lambda: SpeckBlockCipher(number_of_rounds=6),
        lambda: ToyAESBlockCipher(number_of_rounds=6),
        lambda: SimonBlockCipher(number_of_rounds=6),
        lambda: PresentBlockCipher(number_of_rounds=6),
    ],
)
@pytest.mark.parametrize("start_round,end_round", [(0, 1), (2, 3)])
def test_prune_components_outside_round_range_has_no_dangling_input_links(cipher_factory, start_round, end_round):
    cipher = cipher_factory()

    if start_round > 0:
        with pytest.raises(ValueError, match="start_round=0"):
            prune_components_outside_round_range(
                cipher,
                start_round=start_round,
                end_round=end_round,
                keep_key_schedule=False,
            )
        return

    prune_components_outside_round_range(
        cipher,
        start_round=start_round,
        end_round=end_round,
        keep_key_schedule=False,
    )

    dangling = find_dangling_input_links(cipher)
    assert dangling == []


def test_prune_components_outside_round_range_removes_expected_components_for_chacha_6_rounds():
    cipher = ChachaPermutation(number_of_rounds=6, round_mode="half")

    start_round, end_round = 0, 1
    rounds_to_remove = cipher.rounds_as_list[:start_round] + cipher.rounds_as_list[end_round + 1 :]
    expected_removed_ids = {
        component.id
        for current_round in rounds_to_remove
        for component in current_round.components
    }

    removed_component_ids, _ = prune_components_outside_round_range(
        cipher,
        start_round=start_round,
        end_round=end_round,
        keep_key_schedule=False,
    )

    assert set(removed_component_ids) == expected_removed_ids


def test_prune_components_outside_round_range_removes_picture_component_subset_for_speck():
    cipher = SpeckBlockCipher(number_of_rounds=6)

    picture_component_ids = {
        "rot_2_1",
        "modadd_2_2",
        "constant_2_0",
        "rot_2_6",
        "rot_2_4",
        "xor_2_3",
        "modadd_2_7",
        "xor_2_5",
        "rot_2_9",
        "xor_2_8",
        "intermediate_output_2_11",
        "xor_2_10",
        "intermediate_output_2_12",
        "rot_3_1",
        "modadd_3_2",
        "constant_3_0",
        "rot_3_6",
        "rot_3_4",
        "xor_3_3",
        "modadd_3_7",
        "xor_3_5",
        "rot_3_9",
        "xor_3_8",
        "intermediate_output_3_11",
        "xor_3_10",
        "intermediate_output_3_12",
        "rot_4_1",
        "modadd_4_2",
        "constant_4_0",
        "rot_4_6",
        "rot_4_4",
        "xor_4_3",
        "modadd_4_7",
        "xor_4_5",
        "rot_4_9",
        "xor_4_8",
        "intermediate_output_4_11",
        "xor_4_10",
        "intermediate_output_4_12",
        "rot_5_1",
        "modadd_5_2",
        "constant_5_0",
        "rot_5_6",
        "rot_5_4",
        "xor_5_3",
        "modadd_5_7",
        "xor_5_5",
        "rot_5_9",
        "xor_5_8",
        "intermediate_output_5_11",
        "xor_5_10",
        "cipher_output_5_12",
    }

    component_ids_before = {component.id for component in cipher.get_all_components()}

    removed_component_ids, _ = prune_components_outside_round_range(
        cipher,
        start_round=0,
        end_round=1,
        keep_key_schedule=False,
    )

    component_ids_after = {component.id for component in cipher.get_all_components()}
    truly_removed_component_ids = component_ids_before - component_ids_after

    assert picture_component_ids.issubset(truly_removed_component_ids)

    # Keep a sanity check on the function return value as well.
    assert set(removed_component_ids).issubset(truly_removed_component_ids)