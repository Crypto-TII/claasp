"""Partial-cipher extraction and inverse-graph rebuild helpers."""

from copy import deepcopy

from claasp.name_mappings import CONSTANT, INPUT_KEY, INPUT_TWEAK, INTERMEDIATE_OUTPUT


def get_key_schedule_component_ids(self):
    key_schedule_component_ids = [input for input in self.inputs if INPUT_KEY in input or INPUT_TWEAK in input]
    component_list = self.get_all_components()
    for c in component_list:
        flag_belong_to_key_schedule = True
        for link in c.input_id_links:
            if link not in key_schedule_component_ids:
                flag_belong_to_key_schedule = False
                break
        if flag_belong_to_key_schedule or (c.type == CONSTANT):
            key_schedule_component_ids.append(c.id)

    return key_schedule_component_ids


def cipher_find_component(cipher, round_number, component_id):
    rounds = cipher._rounds.round_at(round_number)._components
    return next((item for item in rounds if item.id == component_id), None)


def delete_orphan_links(cipher, round_number):
    """
    Delete orphans elements from input_id_link
    INPUT:
    - ``cipher`` -- dictionary with a graph representation
    - ``round_number`` -- round index
    """
    new_components = []
    cipher_round = deepcopy(cipher._rounds.round_at(round_number)._components)
    for component in cipher_round:
        for input_id_link in component.input_id_links:
            if cipher_find_component(cipher, round_number, input_id_link) == None:
                idx = component.input_id_links.index(input_id_link)
                component.input_id_links[idx] = ""
        new_components.append(component)
    return new_components


def topological_sort(round_list):
    """
    Perform topological sort on round components.
    INPUT:
    - ``round_list`` -- list of components
    """
    pending = [(component.id, set(component.input_id_links)) for component in round_list]
    emitted = [""]
    while pending:
        next_pending = []
        next_emitted = []
        for entry in pending:
            component_id, input_id_links = entry
            input_id_links.difference_update(emitted)
            if input_id_links:
                next_pending.append(entry)
            else:
                yield component_id
                emitted.append(component_id)
                next_emitted.append(component_id)
        if not next_emitted:
            raise ValueError("cyclic or missing dependancy detected: %r" % (next_pending,))
        pending = next_pending
        emitted = next_emitted


def sort_cipher_graph(cipher):
    """
    Sorts the cipher graph in a way that
    each component input is defined before the current component.

    INPUT:
    - ``cipher`` -- graph representation of a cipher as a python dictionary

    EXAMPLE::
        sage: from claasp.ciphers.single_component_ciphers.identity_cipher import IdentityCipher
        sage: from claasp.cipher_modules.inverse_cipher import sort_cipher_graph
        sage: identity = IdentityCipher()
        sage: sort_cipher_graph(identity)
        identity_cipher_p32_o32_r1
    """

    k = 0
    for _ in range(cipher.number_of_rounds):
        round_components = delete_orphan_links(cipher, k)
        ordered_ids = list(topological_sort(round_components))
        id_dict = {d.id: d for d in cipher._rounds.round_at(k)._components}
        cipher._rounds.round_at(k)._components = [id_dict[i] for i in ordered_ids]
        k = k + 1

    return cipher


def _remove_key_schedule_components(cipher, key_schedule_components):
    for current_round in cipher.rounds_as_list:
        for key_component in set(key_schedule_components).intersection(current_round.components):
            cipher.rounds.remove_round_component(current_round.id, key_component)


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
    key_schedule_component_ids = get_key_schedule_component_ids(cipher)
    key_schedule_components = [
        cipher.component_from_id(id) for id in key_schedule_component_ids if INPUT_KEY not in id
    ]

    if not keep_key_schedule:
        _remove_key_schedule_components(cipher, key_schedule_components)

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
