from copy import deepcopy
import unittest
from claasp.cipher_modules.inverse_cipher import (
    get_key_schedule_component_ids,
    remove_components_from_rounds,
)
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.name_mappings import INPUT_KEY, INTERMEDIATE_OUTPUT


def remove_components_from_rounds_without_copy(cipher, start_round, end_round, keep_key_schedule):
    list_of_rounds = cipher.rounds_as_list[:start_round] + cipher.rounds_as_list[end_round + 1 :]
    key_schedule_component_ids = get_key_schedule_component_ids(cipher)
    key_schedule_components = [
        cipher.get_component_from_id(component_id)
        for component_id in key_schedule_component_ids
        if INPUT_KEY not in component_id
    ]

    if not keep_key_schedule:
        for current_round in cipher.rounds_as_list:
            for key_component in set(key_schedule_components).intersection(current_round.components):
                cipher.rounds.remove_round_component(current_round.id, key_component)

    removed_component_ids = []
    intermediate_outputs = {}
    for current_round in list_of_rounds:
        for component in set(current_round.components) - set(key_schedule_components):
            if component.type == INTERMEDIATE_OUTPUT and component.description == ["round_output"]:
                intermediate_outputs[current_round.id] = component
            cipher.rounds.remove_round_component(current_round.id, component)
            removed_component_ids.append(component.id)

    if not keep_key_schedule:
        for current_round in cipher.rounds_as_list:
            for component in current_round.components:
                for input_id_link in component.input_id_links:
                    if input_id_link in key_schedule_component_ids and input_id_link not in cipher.inputs:
                        cipher.inputs.append(input_id_link)
                        # This crashes when the key schedule component was removed earlier.
                        new_input_bit_size = cipher.get_component_from_id(input_id_link).output_bit_size
                        cipher.inputs_bit_size.append(new_input_bit_size)

    return removed_component_ids, intermediate_outputs


class TestRemoveComponentsFromRoundsCopyBehavior(unittest.TestCase):
    @staticmethod
    def _build_cipher():
        return ToyAESBlockCipher(number_of_rounds=6)

    def test_not_using_copy_or_deepcopy_breaks_when_key_schedule_component_was_removed(self):
        cipher_without_copy = self._build_cipher()
        no_copy_failed = False
        try:
            remove_components_from_rounds_without_copy(
                cipher_without_copy,
                start_round=0,
                end_round=0,
                keep_key_schedule=False,
            )
        except Exception:
            no_copy_failed = True

        cipher_with_deepcopy = self._build_cipher()
        deep_copy_failed = False
        try:
            remove_components_from_rounds(
                cipher_with_deepcopy,
                start_round=0,
                end_round=0,
                keep_key_schedule=False,
            )
        except Exception:
            deep_copy_failed = True

        self.assertTrue(no_copy_failed)
        self.assertFalse(deep_copy_failed)


if __name__ == "__main__":
    unittest.main()
