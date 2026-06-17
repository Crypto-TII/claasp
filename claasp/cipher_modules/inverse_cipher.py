import weakref
from copy import *

from sage.crypto.sbox import SBox
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from claasp.cipher_modules.component_analysis_tests import (
    binary_matrix_of_linear_component,
    get_inverse_matrix_in_integer_representation,
    int_to_poly,
)
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids
from claasp.component import Component
from claasp.components import (
    cipher_output_component,
    intermediate_output_component,
    linear_layer_component,
    modsub_component,
)
from claasp.input import Input
from claasp.name_mappings import (
    CIPHER_INPUT,
    CIPHER_OUTPUT,
    CONSTANT,
    INPUT_KEY,
    INPUT_PLAINTEXT,
    INPUT_STATE,
    INPUT_TWEAK,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    PERMUTATION_COMPONENT,
    SBOX,
    WORD_OPERATION,
)


class _CipherView:
    """Cached, indexed read-only view of a cipher used by the inversion engine.

    The component list (plus the synthetic ``cipher_input`` components) and its indexes are
    built once; previously every ``component_from_id`` / ``get_output_components`` call
    rebuilt the whole list, making the traversal O(n^2). The cipher is not mutated during
    inversion, so the view is cached per cipher object (weakly, to avoid leaks).
    """

    __slots__ = ("components", "by_id", "consumers")

    def __init__(self, cipher):
        components = cipher.get_all_components()
        for component in components:
            setattr(component, "round", int(component.id.split("_")[-2]))
        for index, input_id in enumerate(cipher.inputs):
            description = [INPUT_KEY] if INPUT_KEY in input_id else [input_id]
            input_component = Component(
                input_id, "cipher_input", Input(0, [[]], [[]]), cipher.inputs_bit_size[index], description
            )
            setattr(input_component, "round", -1)
            components.append(input_component)
        self.components = components
        self.by_id = {component.id: component for component in components}
        consumers = {}
        for component in components:
            seen = set()
            for link in component.input_id_links:
                # links are component-id strings; synthetic inputs carry [[]] placeholders.
                if isinstance(link, str) and link not in seen:
                    seen.add(link)
                    consumers.setdefault(link, []).append(component)
        self.consumers = consumers


_CIPHER_VIEW_CACHE = weakref.WeakKeyDictionary()


def _cipher_view(cipher):
    view = _CIPHER_VIEW_CACHE.get(cipher)
    if view is None:
        view = _CipherView(cipher)
        _CIPHER_VIEW_CACHE[cipher] = view
    return view


def get_cipher_components(self):
    # Return a fresh shallow copy: callers (e.g. the cipher_inverse worklist) mutate the
    # returned list with .remove(). The cached view's list and indexes stay intact.
    return list(_cipher_view(self).components)


def get_all_components_with_the_same_input_id_link_and_input_bit_positions(input_id_link, input_bit_positions, self):
    cipher_components = get_cipher_components(self)
    output_list = []
    for c in cipher_components:
        for i in range(len(c.input_id_links)):
            copy_input_bit_positions = copy(input_bit_positions)
            copy_input_bit_positions.sort()
            list_to_be_compared = copy(c.input_bit_positions[i])
            list_to_be_compared.sort()
            if input_id_link == c.input_id_links[i] and all(
                ele in copy_input_bit_positions for ele in list_to_be_compared
            ):
                output_list.append(c)
                break
    return output_list


def get_output_components(component, self):
    return list(_cipher_view(self).consumers.get(component.id, []))


def is_bit_contained_in(bit, available_bits):
    for b in available_bits:
        if bit["component_id"] == b["component_id"] and bit["position"] == b["position"] and bit["type"] == b["type"]:
            return True
    return False


def add_bit_to_bit_list(bit, bit_list):
    if not is_bit_contained_in(bit, bit_list):
        bit_list.append(bit)
    return


def _are_all_bits_available(id, input_bit_positions_len, offset, available_bits):
    for j in range(input_bit_positions_len):
        bit = {"component_id": id, "position": offset + j, "type": "input"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def get_available_output_components(component, available_bits, self, return_index=False):
    cipher_components = get_cipher_components(self)
    available_output_components = []
    for c in cipher_components:
        accumulator = 0
        for i in range(len(c.input_id_links)):
            if (component.id == c.input_id_links[i]) and (c not in available_output_components):
                all_bits_available = _are_all_bits_available(
                    c.id, len(c.input_bit_positions[i]), accumulator, available_bits
                )
                if all_bits_available:
                    if return_index:
                        available_output_components.append(
                            (c, list(range(accumulator, accumulator + len(c.input_bit_positions[i]))))
                        )
                    else:
                        available_output_components.append(c)
            accumulator += len(c.input_bit_positions[i])

    return available_output_components


def is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
    if bit_name not in all_equivalent_bits.keys():
        return False
    for name in list_of_bit_names:
        if name in all_equivalent_bits[bit_name]:
            return True
    return False


def equivalent_bits_in_common(bits_of_an_output_component, component_bits, all_equivalent_bits):
    bits_in_common = []
    for bit1 in bits_of_an_output_component:
        bit_name1 = f"{bit1['component_id']}_{bit1['position']}_{bit1['type']}"
        if bit_name1 not in all_equivalent_bits.keys():
            return []
        for bit2 in component_bits:
            bit_name2 = f"{bit2['component_id']}_{bit2['position']}_{bit2['type']}"
            if bit_name2 in all_equivalent_bits[bit_name1]:
                bits_in_common.append(bit1)
                break
    return bits_in_common


def links_from_recovered_outputs(
    component, available_output_components, all_equivalent_bits, self
):
    tmp_input_id_links = []
    tmp_input_bit_positions = []
    for bit_position in range(component.output_bit_size):
        bit_name_input = f"{component.id}_{bit_position}_output"
        flag_link_found = False
        for c in available_output_components:
            if is_possibly_invertible_component(c):
                starting_bit_position = 0
                l = []
                for index, link in enumerate(c.input_id_links):
                    if link == component.id:
                        l += list(
                            range(starting_bit_position, starting_bit_position + len(c.input_bit_positions[index]))
                        )
                    starting_bit_position += len(c.input_bit_positions[index])
                for i in l:
                    bit_name = f"{c.id}_{i}_input"
                    if is_bit_adjacent_to_list_of_bits(bit_name_input, [bit_name], all_equivalent_bits):
                        if c.input_bit_size == c.output_bit_size:
                            bit_name_output_updated = f"{c.id}_{i}_output_updated"
                            if is_bit_adjacent_to_list_of_bits(
                                bit_name, [bit_name_output_updated], all_equivalent_bits
                            ):
                                tmp_input_id_links.append(c.id)
                                tmp_input_bit_positions.append(i)
                                flag_link_found = True
                                break
                        else:
                            for j in range(c.output_bit_size):
                                bit_name_output_updated = f"{c.id}_{j}_output_updated"
                                if is_bit_adjacent_to_list_of_bits(
                                    bit_name, [bit_name_output_updated], all_equivalent_bits
                                ):
                                    tmp_input_id_links.append(c.id)
                                    tmp_input_bit_positions.append(j)
                                    flag_link_found = True
                                    break
                            if flag_link_found:
                                break
                if flag_link_found:
                    break

    input_id_links = []
    input_bit_positions = []
    pivot = tmp_input_id_links[0]
    input_bit_position_of_pivot = []
    input_id_links.append(pivot)
    for index, link in enumerate(tmp_input_id_links):
        if link == pivot:
            input_bit_position_of_pivot.append(tmp_input_bit_positions[index])
        else:
            input_bit_positions.append(input_bit_position_of_pivot)
            pivot = link
            input_id_links.append(pivot)
            input_bit_position_of_pivot = []
            input_bit_position_of_pivot.append(tmp_input_bit_positions[index])
    input_bit_positions.append(input_bit_position_of_pivot)

    return input_id_links, input_bit_positions


def get_all_bit_names(self):
    dictio = {}
    cipher_components = get_cipher_components(self)
    for c in cipher_components:
        if c.type != INTERMEDIATE_OUTPUT:
            starting_bit_position = 0
            for index, input_id_link in enumerate(c.input_id_links):
                j = 0
                for i in c.input_bit_positions[index]:
                    output_bit = {"component_id": input_id_link, "position": i, "type": "output"}
                    output_bit_name = f"{input_id_link}_{i}_output"
                    input_bit = {"component_id": c.id, "position": starting_bit_position + j, "type": "input"}
                    input_bit_name = c.id + "_" + str(starting_bit_position + j) + "_input"
                    if output_bit_name not in dictio:
                        dictio[output_bit_name] = output_bit
                    if input_bit_name not in dictio:
                        dictio[input_bit_name] = input_bit

                    if c.type != CIPHER_OUTPUT:
                        output_updated_bit = {"component_id": input_id_link, "position": i, "type": "output_updated"}
                        output_updated_bit_name = f"{input_id_link}_{i}_output_updated"
                        if output_updated_bit_name not in dictio:
                            dictio[output_updated_bit_name] = output_updated_bit
                    output_updated_bit = {
                        "component_id": c.id,
                        "position": starting_bit_position + j,
                        "type": "output_updated",
                    }
                    output_updated_bit_name = f"{c.id}_{starting_bit_position + j}_output_updated"
                    if output_updated_bit_name not in dictio:
                        dictio[output_updated_bit_name] = output_updated_bit
                    j += 1
                starting_bit_position += len(c.input_bit_positions[index])

    return dictio


def get_all_equivalent_bits(self):
    dictio = {}
    component_list = self.get_all_components()
    for c in component_list:
        current_bit_position = 0
        for index, input_id_link in enumerate(c.input_id_links):
            if c.type == "constant":
                input_bit_positions = list(range(c.output_bit_size))
            else:
                input_bit_positions = c.input_bit_positions[index]
            for i in input_bit_positions:
                output_bit_name = f"{input_id_link}_{i}_output"
                input_bit_name = f"{c.id}_{current_bit_position}_input"
                current_bit_position += 1
                if output_bit_name not in dictio:
                    dictio[output_bit_name] = []
                dictio[output_bit_name].append(input_bit_name)

    updated_dictio = {}
    for key, values in dictio.items():
        updated_dictio[key] = values
        for value in values:
            if value not in dictio:
                updated_dictio[value] = []
            updated_dictio[value].append(key)
            for other_value in values:
                if other_value != value:
                    updated_dictio[value].append(other_value)

    return updated_dictio


def get_equivalent_input_bit_from_output_bit(
    potential_unwanted_component,
    base_component,
    available_bits,
    all_equivalent_bits,
    key_schedule_components,
    self,
    base_component_input_index=None,
    override_positions=None,
):
    all_bit_names = get_all_bit_names(self)
    potential_unwanted_bits = []
    potential_unwanted_bits_names = []
    input_bit_positions_of_potential_unwanted_component = []
    if override_positions is not None:
        # Only consider an explicit subset of the link's positions. Used when a link is only
        # partially available (e.g. a MODADD whose packed input is one recovered operand and one
        # known operand sourced from an equivalent recovered component, as in Chaskey).
        input_bit_positions_of_potential_unwanted_component = override_positions
    elif base_component_input_index is not None:
        # When the same link appears more than once among the inputs (e.g. a round key whose
        # words are reassembled from disjoint slices of a single key-schedule component), the
        # specific occurrence must be used; matching only by id would collapse them to the last
        # occurrence and lose the other slices.
        input_bit_positions_of_potential_unwanted_component = base_component.input_bit_positions[
            base_component_input_index
        ]
    else:
        for index, input_id_link in enumerate(base_component.input_id_links):
            if input_id_link == potential_unwanted_component.id:
                input_bit_positions_of_potential_unwanted_component = base_component.input_bit_positions[index]

    for i in input_bit_positions_of_potential_unwanted_component:
        output_bit = {"component_id": potential_unwanted_component.id, "position": i, "type": "output"}
        output_bit_name = f"{potential_unwanted_component.id}_{i}_output"
        potential_unwanted_bits.append(output_bit)
        potential_unwanted_bits_names.append(output_bit_name)

    equivalent_bits = []
    for potential_unwanted_bits_name in potential_unwanted_bits_names:
        for equivalent_bit in all_equivalent_bits[potential_unwanted_bits_name]:
            if (
                (equivalent_bit in all_bit_names.keys())
                and (all_bit_names[equivalent_bit]["component_id"] != base_component.id)
                and (all_bit_names[equivalent_bit] in available_bits)
                and (all_bit_names[equivalent_bit]["component_id"] not in key_schedule_components)
                and (all_bit_names[equivalent_bit]["type"] == "output_updated")
            ):
                if len(equivalent_bits) == 0:
                    equivalent_bits.append(equivalent_bit)
                elif all_bit_names[equivalent_bit]["component_id"] == all_bit_names[equivalent_bits[0]]["component_id"]:
                    equivalent_bits.append(equivalent_bit)

    if len(equivalent_bits) == 0:
        return potential_unwanted_component.id, input_bit_positions_of_potential_unwanted_component
    else:
        input_bit_positions = []
        for bit in equivalent_bits:
            input_bit_positions.append(all_bit_names[bit]["position"])
        input_bit_positions.sort()
        return all_bit_names[equivalent_bits[0]]["component_id"], input_bit_positions


def links_from_known_inputs(
    component, available_bits, all_equivalent_bits, key_schedule_components, self
):
    input_id_links = []
    input_bit_positions = []
    for i in range(len(component.input_id_links)):
        # Source the positions of this link that are already known (available as a forward
        # "output"). A fully-available link yields all its positions (unchanged behaviour); a
        # partially-available link yields only its known sub-range, which lets us invert an
        # operation whose packed input mixes a recovered operand with a known one (e.g. a Chaskey
        # MODADD where one half is the recovered output and the other half is a known operand
        # available through an equivalent recovered component).
        available_positions = [
            position
            for position in component.input_bit_positions[i]
            if is_bit_contained_in(
                {"component_id": component.input_id_links[i], "position": position, "type": "output"},
                available_bits,
            )
        ]
        if not available_positions:
            continue
        potential_unwanted_component = component_from_id(component.input_id_links[i], self)
        equivalent_component, input_bit_positions_of_equivalent_component = (
            get_equivalent_input_bit_from_output_bit(
                potential_unwanted_component,
                component,
                available_bits,
                all_equivalent_bits,
                key_schedule_components,
                self,
                base_component_input_index=i,
                override_positions=available_positions,
            )
        )
        input_id_links.append(equivalent_component)
        input_bit_positions.append(input_bit_positions_of_equivalent_component)

    return input_id_links, input_bit_positions


def component_input_bits(component):
    component_input_bits_list = []
    for index, link in enumerate(component.input_id_links):
        tmp = []
        for position in component.input_bit_positions[index]:
            tmp.append({"component_id": link, "position": position, "type": "output_updated"})
        component_input_bits_list.append(tmp)
    return component_input_bits_list


def component_output_bits(component, self):
    # set of list_bits needed to invert
    output_components = get_output_components(component, self)
    component_output_bits_list = []
    for c in output_components:
        tmp = []
        for j in range(c.output_bit_size):
            bit = {"component_id": c.id, "position": j, "type": "output_updated"}
            tmp.append(bit)
        component_output_bits_list.append(tmp)
    return component_output_bits_list


def are_these_bits_available(bits_list, available_bits):
    for bit in bits_list:
        if bit not in available_bits:
            return False
    return True


def are_there_enough_available_inputs_to_evaluate_component(
    component, available_bits, all_equivalent_bits, key_schedule_components, self
):
    #  check input links
    component_input_bits_list = component_input_bits(component)
    can_be_evaluated = [True] * len(component_input_bits_list)
    available_output_components = []
    if component.type in (CONSTANT, CIPHER_INPUT):
        return False
    for index, bits_list in enumerate(component_input_bits_list):
        if not are_these_bits_available(bits_list, available_bits):
            can_be_evaluated[index] = False
    available_input_components = [
        component_from_id(c_id, self)
        for i, c_id in enumerate(component.input_id_links)
        if can_be_evaluated[i] == True
    ]

    if sum(can_be_evaluated) == len(can_be_evaluated):
        return True
    else:
        for index, link in enumerate(component.input_id_links):
            if not can_be_evaluated[index]:
                component_of_link = component_from_id(link, self)
                output_components = get_output_components(component_of_link, self)
                link_bit_names = []
                for bit in component_input_bits_list[index]:
                    link_bit_name = f"{bit['component_id']}_{bit['position']}_output"
                    link_bit_names.append(link_bit_name)
                for _, output_component in enumerate(output_components):
                    if (output_component.id not in component.input_id_links) and (output_component.id != component.id):
                        index_id = output_component.input_id_links.index(link)
                        starting_bit = 0
                        for index_list, list_bit_positions in enumerate(output_component.input_bit_positions):
                            if index_list == index_id:
                                break
                            starting_bit += len(list_bit_positions)
                        # The output_updated bits of an inverted component are indexed in
                        # output space (0..output_bit_size), which does not coincide with the
                        # input-space offset (starting_bit) when the recovered link is not the
                        # first input (e.g. a multi-input XOR). Scan the producer's actual
                        # output_updated bits for adjacency to the needed link bits; phase 2
                        # below verifies full coverage per input bit.
                        is_adjacent = any(
                            is_bit_adjacent_to_list_of_bits(
                                f"{output_component.id}_{k}_output_updated",
                                link_bit_names,
                                all_equivalent_bits,
                            )
                            for k in range(output_component.output_bit_size)
                        )
                        if is_adjacent:
                            available_output_components.append(output_component)

        list_of_bit_names = []
        for c in available_output_components:
            for i in range(c.output_bit_size):
                list_of_bit_names.append(f"{c.id}_{i}_output_updated")
        for c in available_input_components:
            for i in range(c.output_bit_size):
                list_of_bit_names.append(f"{c.id}_{i}_output")
        for i in range(component.input_bit_size):
            bit_name = f"{component.id}_{i}_input"
            if not is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
                return False
        return True


def _get_successor_components(component_id, cipher):
    graph_cipher = create_networkx_graph_from_input_ids(cipher)
    return list(graph_cipher.successors(component_id))


def inversion_stall_message(stuck_components):
    """Human-readable diagnostic for a ``cipher_inverse()`` that can no longer make progress.

    Lists how many components are stuck and of which kinds, plus a sample with their input
    links, instead of the opaque "Unable to invert cipher for now.".
    """
    from collections import Counter

    def _kind(component):
        description = component.description
        if isinstance(description, list) and description:
            return f"{component.type}/{description[0]}"
        return component.type

    by_kind = Counter(_kind(component) for component in stuck_components)
    lines = [
        f"Unable to invert cipher: {len(stuck_components)} component(s) could not be processed "
        "(neither evaluable forward nor invertible from the currently recovered bits).",
        "Stuck by kind: " + ", ".join(f"{kind}={count}" for kind, count in by_kind.most_common()),
    ]
    for component in stuck_components[:10]:
        lines.append(f"  {component.id} <- {component.input_id_links}")
    if len(stuck_components) > 10:
        lines.append(f"  ... and {len(stuck_components) - 10} more")
    return "\n".join(lines)


def _input_bit_value_is_recovered(link, position, available_bits, all_equivalent_bits):
    """
    True if the value of input bit ``{link}[position]`` is already known in the inverse cipher,
    either directly (its own ``output_updated`` is available) or through the equivalence map (some
    other recovered component carries the same value as an available ``output_updated`` bit).

    This lets the inversion-readiness credit a known operand even when it is only reachable through
    the equivalence map (e.g. a shift-register state bit that equals a ciphertext bit, as in
    TinyJambu), rather than requiring the operand's own link to be available.
    """
    if {"component_id": link, "position": position, "type": "output_updated"} in available_bits:
        return True
    for equivalent_bit in all_equivalent_bits.get(f"{link}_{position}_output", []):
        if equivalent_bit.endswith("_output_updated"):
            source_id, source_position = equivalent_bit[: -len("_output_updated")].rsplit("_", 1)
            if {"component_id": source_id, "position": int(source_position), "type": "output_updated"} in available_bits:
                return True
    return False


def are_there_enough_available_inputs_to_perform_inversion(component, available_bits, all_equivalent_bits, self):
    """
    NOTE: it assumes that the component input size is a multiple of the output size
    """
    # STEP 1 - Special case for output components which have no output links (only cipher output)
    if (component.type == CIPHER_OUTPUT) or (component.id == INPUT_KEY):
        return True
    if component.type == INTERMEDIATE_OUTPUT and _get_successor_components(component.id, self) == []:
        return False

    # STEP 2 - Other components
    bit_lists_link_to_component_from_output = component_output_bits(component, self)
    component_output_bits_list = []
    for i in range(component.output_bit_size):
        component_output_bits_list.append({"component_id": component.id, "position": i, "type": "output"})
    bit_lists_link_to_component_from_output_and_available = []
    for bit_list in bit_lists_link_to_component_from_output:
        bits_in_common = equivalent_bits_in_common(bit_list, component_output_bits_list, all_equivalent_bits)
        for bit in bits_in_common:
            if bit in available_bits:
                bit_lists_link_to_component_from_output_and_available.append(bit)

    # handling available bits from inputs
    bit_lists_link_to_component_from_input = component_input_bits(component)
    can_be_used_for_inversion = [True] * len(bit_lists_link_to_component_from_input)
    for index, bits_list in enumerate(bit_lists_link_to_component_from_input):
        if not are_these_bits_available(bits_list, available_bits):
            can_be_used_for_inversion[index] = False
    for index, link in enumerate(component.input_id_links):
        if not can_be_used_for_inversion[index]:
            component_of_link = component_from_id(link, self)
            output_components = get_output_components(component_of_link, self)
            link_bit_names = []
            for bit in bit_lists_link_to_component_from_input[index]:
                link_bit_name = f"{bit['component_id']}_{bit['position']}_output"
                link_bit_names.append(link_bit_name)
            for output_component in output_components:
                nb_available_output_component_bits = 0
                if (
                    (output_component.id not in component.input_id_links)
                    and (output_component.id != component.id)
                    and (output_component.type != INTERMEDIATE_OUTPUT)
                ):
                    for i in range(output_component.output_bit_size):
                        output_component_bit_name = f"{output_component.id}_{i}_output_updated"
                        output_component_bit = {
                            "component_id": output_component.id,
                            "position": i,
                            "type": "output_updated",
                        }
                        if is_bit_adjacent_to_list_of_bits(
                            output_component_bit_name, link_bit_names, all_equivalent_bits
                        ) and (output_component_bit in available_bits):
                            nb_available_output_component_bits += 1
                    if nb_available_output_component_bits == output_component.output_bit_size or (
                        len(link_bit_names) > 0 and nb_available_output_component_bits >= len(link_bit_names)
                    ):
                        can_be_used_for_inversion[index] = True

    # Merging available bits from inputs and output
    bit_lists_link_to_component_from_input_and_output = list(bit_lists_link_to_component_from_output_and_available)
    for index, bits_list in enumerate(bit_lists_link_to_component_from_input):
        if can_be_used_for_inversion[index]:
            bit_lists_link_to_component_from_input_and_output += bits_list
        else:
            # Credit input bits whose value is individually known (directly or via the equivalence
            # map), so a partially-available input link still contributes its known bits. The bit
            # being recovered is simply not available and therefore not counted - which is correct.
            for bit in bits_list:
                if _input_bit_value_is_recovered(
                    bit["component_id"], bit["position"], available_bits, all_equivalent_bits
                ):
                    bit_lists_link_to_component_from_input_and_output.append(bit)

    if component.id == INPUT_PLAINTEXT or INTERMEDIATE_OUTPUT in component.id:
        return len(bit_lists_link_to_component_from_input_and_output) >= component.output_bit_size
    else:
        return len(bit_lists_link_to_component_from_input_and_output) >= component.input_bit_size


def is_possibly_invertible_component(component):
    # if sbox is a permutation
    if component.type == SBOX and len(list(set(component.description))) == len(component.description):
        is_invertible = True
    # if sbox is NOT a permutation, then cannot be inverted
    elif component.type == SBOX and len(list(set(component.description))) != len(component.description):
        is_invertible = False
    elif component.type == LINEAR_LAYER:
        is_invertible = True
    elif component.type == PERMUTATION_COMPONENT:
        is_invertible = True
    elif component.type == MIX_COLUMN:
        is_invertible = True
    # for rotations and shift rows
    elif component.type == WORD_OPERATION and component.description[0] == "ROTATE":
        is_invertible = True
    elif component.type == CONSTANT:
        is_invertible = True
    elif component.type == WORD_OPERATION and component.description[0] == "SHIFT":
        is_invertible = False
    elif component.type == WORD_OPERATION and component.description[0] == "XOR":
        is_invertible = True
    elif component.type == WORD_OPERATION and component.description[0] == "SIGMA":
        is_invertible = True
    elif component.type == WORD_OPERATION and component.description[0] == "MODADD":
        is_invertible = True
    elif component.type == WORD_OPERATION and component.description[0] == "OR":
        is_invertible = False
    elif component.type == WORD_OPERATION and component.description[0] == "AND":
        is_invertible = False
    elif component.type == WORD_OPERATION and component.description[0] == "NOT":
        is_invertible = True
    elif component.type in [CIPHER_INPUT, CIPHER_OUTPUT, INTERMEDIATE_OUTPUT]:
        is_invertible = True
    else:
        is_invertible = False

    return is_invertible


def find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits):
    bit_positions = []
    list_of_keys = []

    for index, input_id_link in enumerate(inverse_component.input_id_links):
        for position, i in enumerate(inverse_component.input_bit_positions[index]):
            potential_equivalent_bit_name = f"{input_id_link}_{i}_output_updated"
            if potential_equivalent_bit_name in all_equivalent_bits.keys():
                list_of_keys += all_equivalent_bits[potential_equivalent_bit_name]
    offset = 0
    for index, input_id_link in enumerate(component.input_id_links):
        for pos, i in enumerate(component.input_bit_positions[index]):
            output_bit_name = f"{input_id_link}_{i}_output"
            if output_bit_name in all_equivalent_bits and not any(
                "output_updated" in item for item in all_equivalent_bits[output_bit_name]
            ):
                bit_positions.append(offset + pos)
        offset += len(component.input_bit_positions[index])
    return bit_positions


def update_output_bits(inverse_component, self, all_equivalent_bits, available_bits):
    def _add_output_bit_equivalences(id, bit_positions, component, all_equivalent_bits, available_bits):
        for i in range(component.output_bit_size):
            output_bit_name_updated = f"{id}_{i}_output_updated"
            bit = {"component_id": id, "position": i, "type": "output_updated"}
            available_bits.append(bit)
            input_bit_name = f"{id}_{bit_positions[i]}_input"
            all_equivalent_bits[input_bit_name].append(output_bit_name_updated)
            if output_bit_name_updated not in all_equivalent_bits.keys():
                all_equivalent_bits[output_bit_name_updated] = []
            all_equivalent_bits[output_bit_name_updated].append(input_bit_name)
            for name in all_equivalent_bits[input_bit_name]:
                if name != output_bit_name_updated:
                    all_equivalent_bits[output_bit_name_updated].append(name)
                    all_equivalent_bits[name].append(output_bit_name_updated)

    id = inverse_component.id
    component = component_from_id(id, self)

    if (
        (component.description == [INPUT_KEY])
        or (component.description == [INPUT_TWEAK])
        or (component.type == CONSTANT)
    ):
        for i in range(component.output_bit_size):
            output_bit_name_updated = f"{id}_{i}_output_updated"
            bit = {"component_id": id, "position": i, "type": "output_updated"}
            available_bits.append(bit)
            input_bit_name = f"{id}_{i}_output"
            if input_bit_name not in all_equivalent_bits.keys():
                all_equivalent_bits[input_bit_name] = []
            all_equivalent_bits[input_bit_name].append(output_bit_name_updated)
            if output_bit_name_updated not in all_equivalent_bits.keys():
                all_equivalent_bits[output_bit_name_updated] = []
            all_equivalent_bits[output_bit_name_updated].append(input_bit_name)
            for name in all_equivalent_bits[input_bit_name]:
                if name != output_bit_name_updated:
                    all_equivalent_bits[output_bit_name_updated].append(name)
    elif component.input_bit_size == component.output_bit_size:
        _add_output_bit_equivalences(
            id, range(component.output_bit_size), component, all_equivalent_bits, available_bits
        )
    else:
        input_bit_positions = find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits)
        _add_output_bit_equivalences(id, input_bit_positions, component, all_equivalent_bits, available_bits)


def _links_from_outputs(component, output_components, all_equivalent_bits, self):
    """Input links/positions for a reversed component, sourced from its (recovered) outputs."""
    return links_from_recovered_outputs(
        component, output_components, all_equivalent_bits, self
    )


def _finalize_inverse(inverse_component, component, self, all_equivalent_bits, available_bits, klass, round_value, update=True):
    """Common epilogue: set the component's class and round, then register its recovered bits."""
    inverse_component.__class__ = klass
    setattr(inverse_component, "round", round_value)
    if update:
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    return inverse_component


def _invert_sbox(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(SBox(component.description).inverse()),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_linear_layer(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(inv_binary_matrix),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_permutation(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    permutation, word_size = component.description
    inverse_permutation = [0] * len(permutation)
    for source_word, destination_word in enumerate(permutation):
        inverse_permutation[destination_word] = source_word
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [inverse_permutation, word_size],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_mix_column(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    description = component.description
    x = PolynomialRing(GF(2), "x").gen()
    irr_poly = int_to_poly(int(description[1]), int(description[2]), x)
    if irr_poly and not irr_poly.is_irreducible():
        inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
        inverse_component = Component(
            component.id,
            LINEAR_LAYER,
            Input(component.input_bit_size, input_id_links, input_bit_positions),
            component.output_bit_size,
            list(inv_binary_matrix.transpose()),
        )
        klass = linear_layer_component.LinearLayer
    else:
        inv_matrix = get_inverse_matrix_in_integer_representation(component)
        inverse_component = Component(
            component.id,
            component.type,
            Input(component.input_bit_size, input_id_links, input_bit_positions),
            component.output_bit_size,
            [[list(row) for row in inv_matrix]] + component.description[1:],
        )
        klass = component.__class__
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, klass, component.round
    )


def _invert_sigma(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
    inverse_component = Component(
        component.id,
        LINEAR_LAYER,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(inv_binary_matrix.transpose()),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_xor(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    links_out, positions_out = _links_from_outputs(component, oc, all_equivalent_bits, self)
    links_in, positions_in = links_from_known_inputs(
        component, available_bits, all_equivalent_bits, key_schedule_components, self
    )
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, links_in + links_out, positions_in + positions_out),
        component.output_bit_size,
        component.description,
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_rotate(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.description[0], -component.description[1]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_not(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.description[0], component.description[1]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_modadd(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    links_out, positions_out = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    links_in, positions_in = links_from_known_inputs(
        component, available_bits, all_equivalent_bits, key_schedule_components, self
    )
    # MODSUB is non-commutative: minuend - subtrahend. The minuend is the recovered output of the
    # original MODADD (sourced from output components); the subtrahend(s) are the known operands
    # (sourced from input components). Place the minuend first directly, rather than relying on a
    # positional reorder that conflates a producer's input- and output-bit spaces (which mis-orders
    # the operand whenever the minuend is read through a bit-reorganizing component, e.g. Sparx).
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, links_out + links_in, positions_out + positions_in),
        component.output_bit_size,
        ["MODSUB", component.description[1], component.description[2]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, modsub_component.ModSub, component.round
    )


def _invert_constant(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, component.type, Input(0, [[]], [[]]), component.output_bit_size, component.description
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, component.round
    )


def _invert_cipher_output(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, CIPHER_INPUT, Input(0, [[]], [[]]), component.output_bit_size, [CIPHER_INPUT]
    )
    setattr(inverse_component, "round", -1)
    update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    return inverse_component


def _invert_cipher_input_data(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        CIPHER_OUTPUT,
        Input(component.output_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.id],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits,
        cipher_output_component.CipherOutput, component.round, update=False,
    )


def _invert_cipher_input_key(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, CIPHER_INPUT, Input(0, [[]], [[]]), component.output_bit_size, [component.id]
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__, -1
    )


def _invert_intermediate_output(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        INTERMEDIATE_OUTPUT,
        Input(component.output_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        component.description,
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits,
        intermediate_output_component.IntermediateOutput, component.round,
    )


def _inversion_rule_key(component):
    if component.type == WORD_OPERATION:
        return (WORD_OPERATION, component.description[0])
    if component.type == CIPHER_INPUT:
        if component.id in [INPUT_PLAINTEXT, INPUT_STATE] or INTERMEDIATE_OUTPUT in component.id:
            return (CIPHER_INPUT, "data")
        if component.description == [INPUT_KEY] or component.id == INPUT_TWEAK:
            return (CIPHER_INPUT, "key")
        return (CIPHER_INPUT, None)
    return component.type


_INVERSION_RULES = {
    SBOX: _invert_sbox,
    LINEAR_LAYER: _invert_linear_layer,
    PERMUTATION_COMPONENT: _invert_permutation,
    MIX_COLUMN: _invert_mix_column,
    (WORD_OPERATION, "SIGMA"): _invert_sigma,
    (WORD_OPERATION, "XOR"): _invert_xor,
    (WORD_OPERATION, "ROTATE"): _invert_rotate,
    (WORD_OPERATION, "NOT"): _invert_not,
    (WORD_OPERATION, "MODADD"): _invert_modadd,
    CONSTANT: _invert_constant,
    CIPHER_OUTPUT: _invert_cipher_output,
    (CIPHER_INPUT, "data"): _invert_cipher_input_data,
    (CIPHER_INPUT, "key"): _invert_cipher_input_key,
    INTERMEDIATE_OUTPUT: _invert_intermediate_output,
}


def component_inverse(component, available_bits, all_equivalent_bits, key_schedule_components, self):
    """Return the reversed form of an invertible component (assumes it is actually invertible)."""
    handler = _INVERSION_RULES.get(_inversion_rule_key(component))
    if handler is None:
        return Component("NA", "NA", Input(0, [[]], [[]]), component.output_bit_size, ["NA"])
    output_components = get_output_components(component, self)
    available_output_components = get_available_output_components(component, available_bits, self)
    return handler(
        component,
        available_bits,
        all_equivalent_bits,
        key_schedule_components,
        self,
        output_components,
        available_output_components,
    )


def update_available_bits_with_component_output_bits(component, available_bits, cipher):
    output_components = get_output_components(component, cipher)

    for i in range(component.output_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "output"}
        add_bit_to_bit_list(bit, available_bits)

    # add bits of the connected output components
    for c in output_components:
        accumulator = 0
        for i in range(len(c.input_id_links)):
            if c.input_id_links[i] == component.id:
                for j in range(len(c.input_bit_positions[i])):
                    component_output_bit = {"component_id": component.id, "position": j, "type": "output"}
                    if is_bit_contained_in(component_output_bit, available_bits):
                        c_input_bit = {"component_id": c.id, "position": accumulator + j, "type": "input"}
                        add_bit_to_bit_list(c_input_bit, available_bits)
            accumulator += len(c.input_bit_positions[i])
    return


def update_available_bits_with_component_input_bits(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "input"}
        add_bit_to_bit_list(bit, available_bits)

    # add bits of the connected input components
    for i in range(len(component.input_id_links)):
        for j in range(len(component.input_bit_positions[i])):
            bit1 = {
                "component_id": component.input_id_links[i],
                "position": component.input_bit_positions[i][j],
                "type": "output",
            }
            add_bit_to_bit_list(bit1, available_bits)
    return


def apply_inversion_step(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Process one component during inversion.

    Tries first to **evaluate it forward** (when all its inputs are known), otherwise to
    **invert it** (when its output plus enough inputs are known, or it is a key/tweak input).
    On success, updates the running bit-availability state and returns the rebuilt component;
    returns ``None`` if the component cannot be processed yet.
    """
    if are_there_enough_available_inputs_to_evaluate_component(
        component, available_bits, all_equivalent_bits, key_schedule_component_ids, self
    ):
        inverted_component = evaluated_component(
            component, available_bits, key_schedule_component_ids, all_equivalent_bits, self
        )
        update_available_bits_with_component_output_bits(component, available_bits, self)
        return inverted_component

    is_invertible = is_possibly_invertible_component(component) and are_there_enough_available_inputs_to_perform_inversion(
        component, available_bits, all_equivalent_bits, self
    )
    is_key_or_tweak_input = component.type == CIPHER_INPUT and component.description[0] in (INPUT_KEY, INPUT_TWEAK)
    if is_invertible or is_key_or_tweak_input:
        inverted_component = component_inverse(
            component, available_bits, all_equivalent_bits, key_schedule_component_ids, self
        )
        update_available_bits_with_component_input_bits(component, available_bits)
        update_available_bits_with_component_output_bits(component, available_bits, self)
        return inverted_component

    return None


def all_input_bits_available(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "input"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def all_output_updated_bits_available(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "output_updated"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def all_output_bits_available(component, available_bits):
    for i in range(component.output_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "output_updated"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def component_from_id(component_id, self):
    return _cipher_view(self).by_id.get(component_id)


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


def is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits):
    for bit in output_bits_updated_list:
        if not is_bit_adjacent_to_list_of_bits(bit, input_bits_list, all_equivalent_bits):
            return False
    return True


def resolve_evaluated_input_via_equivalence(component, available_bits, all_equivalent_bits):
    """
    Wire a forward-evaluated component by resolving each of its input bits, through the bit
    equivalence map, to an already-recovered value (an available ``output_updated`` bit).

    Returns ``(input_id_links, input_bit_positions)`` reading from the components that actually
    carry the needed value in the inverse cipher, or ``None`` if any input bit cannot be resolved.

    This is needed when a component's declared input link does not itself carry the wanted value in
    the inverse cipher (e.g. a dead-end ``round_output`` snapshot whose source component was
    inverted, so the source's ``output_updated`` holds a different value than the snapshot captured,
    as in Threefish). All bits of an equivalence class hold the same value, so any available
    representative is correct.
    """
    available_output_updated = {
        (bit["component_id"], bit["position"]) for bit in available_bits if bit["type"] == "output_updated"
    }
    flat_sources = []
    for index, link in enumerate(component.input_id_links):
        for position in component.input_bit_positions[index]:
            bit_name = f"{link}_{position}_output"
            resolved = None
            for equivalent_bit in all_equivalent_bits.get(bit_name, []):
                if equivalent_bit.endswith("_output_updated"):
                    source_id, source_position = equivalent_bit[: -len("_output_updated")].rsplit("_", 1)
                    if (source_id, int(source_position)) in available_output_updated:
                        resolved = (source_id, int(source_position))
                        break
            if resolved is None:
                return None
            flat_sources.append(resolved)

    input_id_links = []
    input_bit_positions = []
    for source_id, source_position in flat_sources:
        if input_id_links and input_id_links[-1] == source_id:
            input_bit_positions[-1].append(source_position)
        else:
            input_id_links.append(source_id)
            input_bit_positions.append([source_position])
    return input_id_links, input_bit_positions


def find_correct_order(id1, list1, id2, list2, all_equivalent_bits):
    list2_ordered = []
    for i in list1:
        bit = f"{id1}_{i}_output"
        for j in list2:
            bit_potentially_equivalent = f"{id2}_{j}_input"
            if bit_potentially_equivalent in all_equivalent_bits[bit]:
                list2_ordered.append(j)
                break
    return list2_ordered


def find_equivalent_output_updated_positions(link, link_positions, producer, all_equivalent_bits):
    """
    Map each requested bit ``{link}_{p}_output`` to the position ``q`` of ``producer`` such that
    ``{producer.id}_{q}_output_updated`` carries that value.

    Returns the ordered list of producer output positions, or ``[]`` if any requested bit is not
    covered. Unlike the input-space ``starting_bit`` heuristic, this resolves the value through the
    producer's output space, which is required when the recovered link is not the producer's first
    input (e.g. a size-reducing inverted multi-input XOR/MODADD).
    """
    positions = []
    for p in link_positions:
        link_bit_name = f"{link}_{p}_output"
        equivalents = all_equivalent_bits.get(link_bit_name, [])
        found = None
        for q in range(producer.output_bit_size):
            if f"{producer.id}_{q}_output_updated" in equivalents:
                found = q
                break
        if found is None:
            return []
        positions.append(found)
    return positions


def evaluated_component(component, available_bits, key_schedule_component_ids, all_equivalent_bits, self):
    input_id_links = []
    input_bit_positions = []

    if component.type != "cipher_input":
        components_with_same_input_bits = []
        starting_bit_position = 0
        for i in range(len(component.input_id_links)):
            components_with_same_input_bits = get_all_components_with_the_same_input_id_link_and_input_bit_positions(
                component.input_id_links[i], component.input_bit_positions[i], self
            )
            components_with_same_input_bits.remove(component)

            # check if the original input component has all output bits available
            original_input_component = component_from_id(component.input_id_links[i], self)
            output_bits_updated_list = []
            for j in component.input_bit_positions[i]:
                output_bit_updated_name = f"{original_input_component.id}_{j}_output_updated"
                output_bits_updated_list.append(output_bit_updated_name)
            input_bits_list = []
            for k in range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[i])):
                input_bit_name = f"{component.id}_{k}_input"
                input_bits_list.append(input_bit_name)
            starting_bit_position += len(component.input_bit_positions[i])
            flag = is_output_bits_updated_equivalent_to_input_bits(
                output_bits_updated_list, input_bits_list, all_equivalent_bits
            )
            if all_output_bits_available(original_input_component, available_bits) and flag:
                input_id_links.append(component.input_id_links[i])
                input_bit_positions.append(component.input_bit_positions[i])
            else:
                # select component for which the connected components have all their inputs available
                link = component.input_id_links[i]
                original_input_bit_positions_of_link = component.input_bit_positions[i]
                available_output_components = get_available_output_components(
                    original_input_component, available_bits, self
                )
                link_bit_names = []
                for l in range(original_input_component.output_bit_size):
                    link_bit_name = f"{link}_{l}_output"
                    link_bit_names.append(link_bit_name)
                for _, available_output_component in enumerate(available_output_components):
                    if (available_output_component.id not in component.input_id_links) and (
                        available_output_component.id != component.id
                    ):
                        index_id_list = [
                            _
                            for _, x in enumerate(available_output_component.input_id_links)
                            if x == link
                            and set(original_input_bit_positions_of_link)
                            <= set(available_output_component.input_bit_positions[_])
                        ]
                        index_id = (
                            index_id_list[0] if index_id_list else available_output_component.input_id_links.index(link)
                        )
                        starting_bit = 0
                        for index_list, list_bit_positions in enumerate(available_output_component.input_bit_positions):
                            if index_list == index_id:
                                break
                            starting_bit += len(list_bit_positions)
                        available_output_component_bit_name = (
                            f"{available_output_component.id}_{starting_bit}_output_updated"
                        )
                        if is_bit_adjacent_to_list_of_bits(
                            available_output_component_bit_name, link_bit_names, all_equivalent_bits
                        ):
                            # if all_input_bits_available(c, available_bits):
                            input_id_links.append(available_output_component.id)
                            # get input bit positions
                            accumulator = 0
                            for j in range(len(available_output_component.input_id_links)):
                                if j == index_id:
                                    if set(original_input_bit_positions_of_link) < set(
                                        available_output_component.input_bit_positions[j]
                                    ):
                                        accumulator += (
                                            original_input_bit_positions_of_link[0]
                                            - available_output_component.input_bit_positions[j][0]
                                        )
                                    l = list(range(accumulator, accumulator + len(component.input_bit_positions[i])))
                                    l_ordered = find_correct_order(
                                        link,
                                        original_input_bit_positions_of_link,
                                        available_output_component.id,
                                        l,
                                        all_equivalent_bits,
                                    )
                                    input_bit_positions.append(l_ordered)
                                    break
                                else:
                                    accumulator += len(available_output_component.input_bit_positions[j])
                        else:
                            # The input-space ``starting_bit`` heuristic above fails when the
                            # recovered link is not the producer's first input (e.g. a size-reducing
                            # inverted multi-input XOR). Resolve the bits through the producer's
                            # output space instead.
                            output_updated_positions = find_equivalent_output_updated_positions(
                                link,
                                original_input_bit_positions_of_link,
                                available_output_component,
                                all_equivalent_bits,
                            )
                            if len(output_updated_positions) == len(original_input_bit_positions_of_link):
                                input_id_links.append(available_output_component.id)
                                input_bit_positions.append(output_updated_positions)
                                break
    else:
        input_id_links = [[]]
        input_bit_positions = [[]]

    empty_indices = [j for j, positions in enumerate(input_bit_positions) if positions == []]
    for index in sorted(empty_indices, reverse=True):
        del input_id_links[index]
        del input_bit_positions[index]

    # If the wiring assembled above does not cover the whole input (e.g. a dead-end round_output
    # snapshot whose source was inverted, so the value it captured is not the source's recovered
    # output but lives on other recovered components - as in Threefish), resolve the input bits
    # through the equivalence map to the components that actually carry that value.
    if component.type != "cipher_input" and sum(len(p) for p in input_bit_positions) != component.input_bit_size:
        resolved = resolve_evaluated_input_via_equivalence(component, available_bits, all_equivalent_bits)
        if resolved is not None:
            input_id_links, input_bit_positions = resolved

    evaluated_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        component.description,
    )
    evaluated_component.__class__ = component.__class__
    setattr(evaluated_component, "round", getattr(component, "round"))

    id = component.id
    for i in range(evaluated_component.output_bit_size):
        output_bit_name_updated = f"{id}_{i}_output_updated"
        bit = {"component_id": id, "position": i, "type": "output_updated"}
        available_bits.append(bit)
        output_bit_name = f"{id}_{i}_output"
        if output_bit_name not in all_equivalent_bits.keys():
            all_equivalent_bits[output_bit_name] = []
        all_equivalent_bits[output_bit_name].append(output_bit_name_updated)
        if output_bit_name_updated not in all_equivalent_bits.keys():
            all_equivalent_bits[output_bit_name_updated] = []
        all_equivalent_bits[output_bit_name_updated].append(output_bit_name)
        for name in all_equivalent_bits[output_bit_name]:
            if name != output_bit_name_updated:
                all_equivalent_bits[output_bit_name_updated].append(name)

    return evaluated_component


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
