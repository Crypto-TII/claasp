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

from claasp.cipher_modules.inverse.cipher_view import (
    AvailableBits,
    _CipherView,
    _are_all_bits_available,
    _cipher_view,
    add_bit_to_bit_list,
    get_all_components_with_the_same_input_id_link_and_input_bit_positions,
    get_available_output_components,
    get_cipher_components,
    get_output_components,
    is_bit_contained_in,
)
from claasp.cipher_modules.inverse.equivalence import (
    add_equivalence,
    bits_equivalent,
    equivalent_bit_names,
    equivalent_bits_in_common,
    get_all_bit_names,
    get_all_equivalent_bits,
    is_bit_adjacent_to_list_of_bits,
)
from claasp.cipher_modules.inverse.partial_cipher import (
    _prune_components_outside_round_range,
    _remove_key_schedule_components,
    _remove_non_key_components_from_rounds,
    cipher_find_component,
    delete_orphan_links,
    get_key_schedule_component_ids,
    get_most_recent_intermediate_output,
    get_relative_position,
    sort_cipher_graph,
    topological_sort,
    update_input_links_from_rounds,
)
from claasp.cipher_modules.inverse.bit_state import (
    _input_bit_value_is_recovered,
    all_output_bits_available,
    are_these_bits_available,
    component_input_bits,
    component_output_bits,
    is_output_bits_updated_equivalent_to_input_bits,
    update_available_bits_with_component_input_bits,
    update_available_bits_with_component_output_bits,
)


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
        for equivalent_bit in equivalent_bit_names(potential_unwanted_bits_name, all_equivalent_bits):
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


def are_there_enough_available_inputs_to_perform_inversion(component, available_bits, all_equivalent_bits, self):
    """
    NOTE: it assumes that the component input size is a multiple of the output size
    """
    # STEP 1 - Special case for output components which have no output links (only cipher output)
    if (component.type == CIPHER_OUTPUT) or (component.id == INPUT_KEY):
        return True
    if component.type == INTERMEDIATE_OUTPUT and get_output_components(component, self) == []:
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
            list_of_keys += equivalent_bit_names(potential_equivalent_bit_name, all_equivalent_bits)
    offset = 0
    for index, input_id_link in enumerate(component.input_id_links):
        for pos, i in enumerate(component.input_bit_positions[index]):
            output_bit_name = f"{input_id_link}_{i}_output"
            if output_bit_name in all_equivalent_bits and not any(
                "output_updated" in item for item in equivalent_bit_names(output_bit_name, all_equivalent_bits)
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
            add_equivalence(all_equivalent_bits, input_bit_name, output_bit_name_updated)

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
            add_equivalence(
                all_equivalent_bits, input_bit_name, output_bit_name_updated, ensure_a=True, symmetric=False
            )
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


def try_evaluate(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Attempt to forward-evaluate the component by sourcing every input bit from an
    already-recovered value. Returns the rebuilt component (committing its recovered outputs), or
    ``None`` if not all input bits can be sourced yet.

    Readiness is *derived* from the build attempt: the component is evaluable iff the pure wiring
    covers the whole input. There is no separate readiness predicate to keep in sync with the
    builder - the single ``_evaluate_wiring`` traversal decides both.
    """
    if component.type in (CONSTANT, CIPHER_INPUT):
        return None
    input_id_links, input_bit_positions = _evaluate_wiring(component, available_bits, all_equivalent_bits, self)
    if sum(len(positions) for positions in input_bit_positions) != component.input_bit_size:
        return None
    inverted_component = _build_evaluated_component(
        component, input_id_links, input_bit_positions, available_bits, all_equivalent_bits
    )
    update_available_bits_with_component_output_bits(component, available_bits, self)
    return inverted_component


def try_invert(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Invert the component when its output plus enough inputs are known (or it is a key/tweak
    input), then commit both its recovered input and output bits. Returns the reversed
    component, or ``None`` if it cannot be inverted yet. Readiness check, build and commit are
    deliberately co-located here.
    """
    is_invertible = is_possibly_invertible_component(component) and are_there_enough_available_inputs_to_perform_inversion(
        component, available_bits, all_equivalent_bits, self
    )
    is_key_or_tweak_input = component.type == CIPHER_INPUT and component.description[0] in (INPUT_KEY, INPUT_TWEAK)
    if not (is_invertible or is_key_or_tweak_input):
        return None
    inverted_component = component_inverse(
        component, available_bits, all_equivalent_bits, key_schedule_component_ids, self
    )
    update_available_bits_with_component_input_bits(component, available_bits)
    update_available_bits_with_component_output_bits(component, available_bits, self)
    return inverted_component


def apply_inversion_step(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Process one component during inversion.

    Tries first to **evaluate it forward** (when all its inputs are known), otherwise to
    **invert it** (when its output plus enough inputs are known, or it is a key/tweak input).
    Each branch co-locates its readiness check with the build and the bit-availability commit
    (see ``try_evaluate`` / ``try_invert``). Returns the rebuilt/reversed component, or ``None``
    if the component cannot be processed yet.
    """
    inverted_component = try_evaluate(
        component, available_bits, all_equivalent_bits, key_schedule_component_ids, self
    )
    if inverted_component is not None:
        return inverted_component
    return try_invert(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self)


def component_from_id(component_id, self):
    return _cipher_view(self).by_id.get(component_id)


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
            for equivalent_bit in equivalent_bit_names(bit_name, all_equivalent_bits):
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
            if bits_equivalent(bit, bit_potentially_equivalent, all_equivalent_bits):
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
        equivalents = equivalent_bit_names(link_bit_name, all_equivalent_bits)
        found = None
        for q in range(producer.output_bit_size):
            if f"{producer.id}_{q}_output_updated" in equivalents:
                found = q
                break
        if found is None:
            return []
        positions.append(found)
    return positions


def _wire_input_link_for_evaluation(
    component, input_index, starting_bit_position, available_bits, all_equivalent_bits, self
):
    """Resolve one input link of a forward-evaluated component to the recovered component(s) that
    carry its value, returning parallel lists ``(ids, positions)`` to append to the rebuilt wiring.

    Two strategies, in order:

    1. **Direct** — if the declared source has all its output bits recovered and those recovered
       bits are equivalent to this component's input bits, reuse the declared link as-is.
    2. **Alternative source** — otherwise scan components that consume the same link for one whose
       recovered ``output_updated`` bits are equivalent to the needed link bits, wiring through
       either the input-space ``starting_bit`` heuristic or, when that fails (the recovered link is
       not the producer's first input, e.g. a size-reducing inverted multi-input XOR), the
       producer's output space via ``find_equivalent_output_updated_positions``.

    May return zero, one, or several contributions (the alternative-source scan does not stop after
    the first adjacent match unless it resolves through output space); an empty result means the
    link could not be wired from currently-recovered bits.
    """
    ids = []
    positions = []
    original_input_component = component_from_id(component.input_id_links[input_index], self)

    output_bits_updated_list = [
        f"{original_input_component.id}_{j}_output_updated" for j in component.input_bit_positions[input_index]
    ]
    input_bits_list = [
        f"{component.id}_{k}_input"
        for k in range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[input_index]))
    ]
    flag = is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits)
    if all_output_bits_available(original_input_component, available_bits) and flag:
        ids.append(component.input_id_links[input_index])
        positions.append(component.input_bit_positions[input_index])
        return ids, positions

    # select component for which the connected components have all their inputs available
    link = component.input_id_links[input_index]
    original_input_bit_positions_of_link = component.input_bit_positions[input_index]
    available_output_components = get_available_output_components(original_input_component, available_bits, self)
    link_bit_names = [f"{link}_{l}_output" for l in range(original_input_component.output_bit_size)]
    for available_output_component in available_output_components:
        if (available_output_component.id not in component.input_id_links) and (
            available_output_component.id != component.id
        ):
            index_id_list = [
                _
                for _, x in enumerate(available_output_component.input_id_links)
                if x == link
                and set(original_input_bit_positions_of_link) <= set(available_output_component.input_bit_positions[_])
            ]
            index_id = index_id_list[0] if index_id_list else available_output_component.input_id_links.index(link)
            starting_bit = 0
            for index_list, list_bit_positions in enumerate(available_output_component.input_bit_positions):
                if index_list == index_id:
                    break
                starting_bit += len(list_bit_positions)
            available_output_component_bit_name = f"{available_output_component.id}_{starting_bit}_output_updated"
            if is_bit_adjacent_to_list_of_bits(
                available_output_component_bit_name, link_bit_names, all_equivalent_bits
            ):
                ids.append(available_output_component.id)
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
                        l = list(range(accumulator, accumulator + len(component.input_bit_positions[input_index])))
                        l_ordered = find_correct_order(
                            link,
                            original_input_bit_positions_of_link,
                            available_output_component.id,
                            l,
                            all_equivalent_bits,
                        )
                        positions.append(l_ordered)
                        break
                    else:
                        accumulator += len(available_output_component.input_bit_positions[j])
            else:
                # The input-space ``starting_bit`` heuristic above fails when the recovered link is
                # not the producer's first input (e.g. a size-reducing inverted multi-input XOR).
                # Resolve the bits through the producer's output space instead.
                output_updated_positions = find_equivalent_output_updated_positions(
                    link, original_input_bit_positions_of_link, available_output_component, all_equivalent_bits
                )
                if len(output_updated_positions) == len(original_input_bit_positions_of_link):
                    ids.append(available_output_component.id)
                    positions.append(output_updated_positions)
                    break
    return ids, positions


def _evaluate_wiring(component, available_bits, all_equivalent_bits, self):
    """Compute the forward-evaluation wiring ``(input_id_links, input_bit_positions)`` for a
    component, sourcing each input bit from an already-recovered value.

    Pure: reads ``available_bits`` / ``all_equivalent_bits`` but mutates nothing. The returned
    wiring may not cover the whole input (when not enough is recovered yet) - callers check
    coverage. This is the single traversal both the builder (``_build_evaluated_component``) and the
    readiness check derive from, so the "can I evaluate?" decision and the construction can never
    drift apart.
    """
    input_id_links = []
    input_bit_positions = []

    if component.type != "cipher_input":
        starting_bit_position = 0
        for i in range(len(component.input_id_links)):
            ids, positions = _wire_input_link_for_evaluation(
                component, i, starting_bit_position, available_bits, all_equivalent_bits, self
            )
            starting_bit_position += len(component.input_bit_positions[i])
            input_id_links.extend(ids)
            input_bit_positions.extend(positions)
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

    return input_id_links, input_bit_positions


def _build_evaluated_component(component, input_id_links, input_bit_positions, available_bits, all_equivalent_bits):
    """Build the rebuilt forward-evaluated component from its (already complete) wiring and commit
    its recovered output bits to the availability/equivalence state. Mutating counterpart to the
    pure ``_evaluate_wiring``."""
    evaluated = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        component.description,
    )
    evaluated.__class__ = component.__class__
    setattr(evaluated, "round", getattr(component, "round"))

    id = component.id
    for i in range(evaluated.output_bit_size):
        output_bit_name_updated = f"{id}_{i}_output_updated"
        available_bits.append({"component_id": id, "position": i, "type": "output_updated"})
        output_bit_name = f"{id}_{i}_output"
        add_equivalence(
            all_equivalent_bits, output_bit_name, output_bit_name_updated, ensure_a=True, symmetric=False
        )

    return evaluated


