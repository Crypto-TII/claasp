"""Partial-cipher extraction and inverse-graph rebuild helpers."""

from claasp import editor
from claasp.name_mappings import INPUT_KEY, INTERMEDIATE_OUTPUT



def _remove_non_key_components_from_rounds(cipher, list_of_rounds, key_schedule_components):
    removed_component_ids = []
    intermediate_outputs = {}

    for current_round in list_of_rounds:
        for component in set(current_round.components) - set(key_schedule_components):
            # The non-key intermediate output of a round is its state round output. It is usually
            # tagged "round_output", but some ciphers (e.g. AES) use a custom tag such as
            # "state_after_round_N"; prefer "round_output" when present, otherwise fall back to the
            # round's (single) non-key intermediate output so partial-cipher rewiring still works.
            if component.type == INTERMEDIATE_OUTPUT and (
                current_round.id not in intermediate_outputs or component.description == ["round_output"]
            ):
                intermediate_outputs[current_round.id] = component
            cipher.rounds.remove_round_component(current_round.id, component)
            removed_component_ids.append(component.id)

    return removed_component_ids, intermediate_outputs


def _prune_components_outside_round_range(
    cipher, start_round, end_round, keep_key_schedule
):
    """
    Prunes components outside the specified round range.

    INPUT:
    - ``cipher`` -- the cipher object
    - ``start_round`` -- the starting round index
    - ``end_round`` -- the ending round index
    - ``keep_key_schedule`` -- boolean indicating whether to keep key schedule components
    """
    list_of_rounds = cipher.rounds_as_list[:start_round] + cipher.rounds_as_list[end_round + 1 :]
    key_schedule_component_ids = editor.get_key_schedule_component_ids(cipher)
    key_schedule_components = [
        cipher.component_from_id(id) for id in key_schedule_component_ids if INPUT_KEY not in id
    ]

    if not keep_key_schedule:
        editor.remove_components(cipher, key_schedule_components)

    removed_component_ids, intermediate_outputs = _remove_non_key_components_from_rounds(
        cipher, list_of_rounds, key_schedule_components
    )

    return removed_component_ids, intermediate_outputs


def get_relative_position(target_link, target_bit_positions, intermediate_output):
    if target_link == intermediate_output.id:
        return target_bit_positions

    intermediate_output_position_links = {}
    current_bit_position = 0
    for input_id_link, input_bit_positions in zip(
        intermediate_output.input_id_links, intermediate_output.input_bit_positions
    ):
        for i in input_bit_positions:
            intermediate_output_position_links[(input_id_link, i)] = current_bit_position
            current_bit_position += 1

    return [
        intermediate_output_position_links[(target_link, bit)]
        for bit in target_bit_positions
        if (target_link, bit) in intermediate_output_position_links
    ]


def get_most_recent_intermediate_output(target_link, intermediate_outputs):
    for index in sorted(intermediate_outputs, reverse=True):
        if target_link in intermediate_outputs[index].input_id_links or target_link == intermediate_outputs[index].id:
            return intermediate_outputs[index]


def update_input_links_from_rounds(cipher_rounds, removed_components, intermediate_outputs):
    for round in cipher_rounds:
        for component in round.components:
            for i, link in enumerate(component.input_id_links):
                if link in removed_components:
                    intermediate_output = get_most_recent_intermediate_output(link, intermediate_outputs)
                    component.input_id_links[i] = f"{intermediate_output.id}"
                    component.input_bit_positions[i] = get_relative_position(
                        link, component.input_bit_positions[i], intermediate_output
                    )
