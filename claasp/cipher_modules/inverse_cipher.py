from copy import *

from sage.crypto.sbox import SBox
from claasp.cipher_modules.component_analysis_tests import binary_matrix_of_linear_component, \
    get_inverse_matrix_in_integer_representation
from claasp.cipher_modules.graph_generator import create_networkx_graph_from_input_ids
from claasp.component import Component
from claasp.components import modsub_component, cipher_output_component, linear_layer_component, \
    intermediate_output_component
from claasp.input import Input
from claasp.name_mappings import *


def get_cipher_components(self):
    component_list = self.get_all_components()
    for c in component_list:
        setattr(c, 'round', int(c.id.split("_")[-2]))
    # build input components
    for index, input_id in enumerate(self.inputs):
        input_component = Component(input_id, "cipher_input", Input(0, [[]], [[]]), self.inputs_bit_size[index], [input_id])
        setattr(input_component, 'round', -1)
        component_list.append(input_component)
    return component_list

def get_all_components_with_the_same_input_id_link_and_input_bit_positions(input_id_link, input_bit_positions, self):
    cipher_components = get_cipher_components(self)
    output_list = []
    for c in cipher_components:
        for i in range(len(c.input_id_links)):
            copy_input_bit_positions = copy(input_bit_positions)
            copy_input_bit_positions.sort()
            list_to_be_compared = copy(c.input_bit_positions[i])
            list_to_be_compared.sort()
            # if input_id_link == c.input_id_links[i] and list_to_be_compared in copy_input_bit_positions: #changed adding sort
            if input_id_link == c.input_id_links[i] and all(ele in copy_input_bit_positions for ele in list_to_be_compared): #changed adding sort
                output_list.append(c)
                break
    return output_list


def are_equal_components(component1, component2):
    attributes = ["id", "type", "input_id_links", "input_bit_size", "input_bit_positions", "output_bit_position", "description", "round"]
    for attr in attributes:
        if getattr(component1, attr) != getattr(component2, attr):
            return False
    return True


def add_new_component_to_list(component, component_list):
    is_in_list = False
    for c in component_list:
        if are_equal_components(component, c):
            is_in_list = True
    if not is_in_list:
        component_list.append(component)
    return


def get_output_components(component, self):
    cipher_components = get_cipher_components(self)
    output_components = []
    for c in cipher_components:
        if component.id in c.input_id_links:
            add_new_component_to_list(c, output_components)
            # output_components.append(c)
    return output_components


def is_bit_contained_in(bit, available_bits):
    for b in available_bits:
        if bit["component_id"] == b["component_id"] and \
                bit["position"] == b["position"] and \
                bit["type"] == b["type"]:
            return True
    return False

def add_bit_to_bit_list(bit, bit_list):
    if not is_bit_contained_in(bit, bit_list):
        bit_list.append(bit)
    return


def _are_all_bits_available(id, input_bit_positions_len, offset, available_bits):
    for j in range(input_bit_positions_len):
        bit = {
            "component_id": id,
            "position": offset + j,
            "type": "input"
        }
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
                all_bits_available = _are_all_bits_available(c.id, len(c.input_bit_positions[i]), accumulator,
                                                             available_bits)
                if all_bits_available:
                    if return_index:
                        available_output_components.append((c, list(range(accumulator, accumulator + len(c.input_bit_positions[i])))))
                    else:
                        available_output_components.append(c)
            accumulator += len(c.input_bit_positions[i]) # changed

    return available_output_components

def sort_input_id_links_and_input_bit_positions(input_id_links, input_bit_positions, component, self):
    updated_input_bit_positions = []
    updated_input_id_links = []
    ordered_list = []
    index = 0
    input_id_link_already_visited = []
    for input_id_link in input_id_links:
        component_input_id_link = get_component_from_id(input_id_link, self)
        if input_id_link not in input_id_link_already_visited:
            input_id_link_already_visited.append(input_id_link)
            for position, link_of_component_id_link in enumerate(component_input_id_link.input_id_links):
                if link_of_component_id_link == component.id:
                    if len(ordered_list) == 0:
                        l = component_input_id_link.input_bit_positions[position]
                        if l != sorted(l):
                            l_ordered = find_correct_order_for_inversion(l, input_bit_positions[index],
                                                                         component_input_id_link)
                        else:
                            l_ordered = input_bit_positions[index]
                        ordered_list.append(l)
                        updated_input_bit_positions.append(l_ordered)
                        updated_input_id_links.append(input_id_links[index])
                    else:
                        position_to_insert = 0
                        first_index = component_input_id_link.input_bit_positions[position][0]
                        for list in ordered_list:
                            if first_index > list[0]:
                                position_to_insert += 1
                            else:
                                break
                        ordered_list.insert(position_to_insert, component_input_id_link.input_bit_positions[position])
                        l = component_input_id_link.input_bit_positions[position]
                        if l != sorted(l):
                            l_ordered = find_correct_order_for_inversion(l, input_bit_positions[index],
                                                                         component_input_id_link)
                        else:
                            l_ordered = input_bit_positions[index]
                        updated_input_bit_positions.insert(position_to_insert, l_ordered)
                        updated_input_id_links.insert(position_to_insert, input_id_links[index])
                    index += 1
    return updated_input_id_links, updated_input_bit_positions

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
        bit_name1 = bit1["component_id"] + "_" + str(bit1["position"]) + "_" + bit1["type"]
        if bit_name1 not in all_equivalent_bits.keys():
            return []
        for bit2 in component_bits:
            bit_name2 = bit2["component_id"] + "_" + str(bit2["position"]) + "_" + bit2["type"]
            if bit_name2 in all_equivalent_bits[bit_name1]:
                bits_in_common.append(bit1)
                break
    return bits_in_common

def compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component,
                                                                                                          available_output_components,
                                                                                                          all_equivalent_bits,
                                                                                                          self):
    tmp_input_id_links = []
    tmp_input_bit_positions = []
    for bit_position in range(component.output_bit_size):
        bit_name_input = component.id + "_" + str(bit_position) + "_output"
        flag_link_found = False
        for c in available_output_components:
            if is_possibly_invertible_component(c):
                starting_bit_position = 0
                l = []
                for index, link in enumerate(c.input_id_links):
                    if link == component.id:
                        l += list(range(starting_bit_position, starting_bit_position + len(c.input_bit_positions[index])))
                    starting_bit_position += len(c.input_bit_positions[index])
                for i in l:
                    bit_name = c.id + "_" + str(i) + "_input"
                    if is_bit_adjacent_to_list_of_bits(bit_name_input, [bit_name], all_equivalent_bits):
                        if c.input_bit_size == c.output_bit_size:
                            bit_name_output_updated = c.id + "_" + str(i) + "_output_updated"
                            if is_bit_adjacent_to_list_of_bits(bit_name, [bit_name_output_updated],
                                                               all_equivalent_bits):
                                tmp_input_id_links.append(c.id)
                                tmp_input_bit_positions.append(i)
                                flag_link_found = True
                                break
                        else:
                            for j in range(c.output_bit_size):
                                bit_name_output_updated = c.id + "_" + str(j) + "_output_updated"
                                if is_bit_adjacent_to_list_of_bits(bit_name, [bit_name_output_updated],
                                                                   all_equivalent_bits):
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
                    output_bit = {
                        "component_id": input_id_link,
                        "position": i,
                        "type": "output"
                    }
                    output_bit_name = input_id_link + "_" + str(i) + "_output"
                    input_bit = {
                        "component_id": c.id,
                        "position": starting_bit_position + j,
                        "type": "input"
                    }
                    input_bit_name = c.id + "_" + str(starting_bit_position + j) + "_input"
                    if output_bit_name not in dictio.keys():
                        dictio[output_bit_name] = output_bit
                    if input_bit_name not in dictio.keys():
                        dictio[input_bit_name] = input_bit

                    if c.type != CIPHER_OUTPUT:
                        output_updated_bit = {
                            "component_id": input_id_link,
                            "position": i,
                            "type": "output_updated"
                        }
                        output_updated_bit_name = input_id_link + "_" + str(i) + "_output_updated"
                    else:
                        output_updated_bit = {
                            "component_id": c.id,
                            "position": starting_bit_position + j,
                            "type": "output_updated"
                        }
                        output_updated_bit_name = c.id + "_" + str(starting_bit_position + j) + "_output_updated"
                    if output_updated_bit_name not in dictio.keys(): # changed, if added
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
                output_bit_name = input_id_link + "_" + str(i) + "_output"
                input_bit_name = c.id + "_" + str(current_bit_position) + "_input"
                current_bit_position += 1
                if output_bit_name not in dictio.keys():
                    dictio[output_bit_name] = []
                dictio[output_bit_name].append(input_bit_name)

    updated_dictio = {}
    for key, values in dictio.items():
        updated_dictio[key] = values
        for value in values:
            if value not in dictio.keys():
                updated_dictio[value] = []
            updated_dictio[value].append(key)
            for other_value in values:
                if other_value != value:
                    updated_dictio[value].append(other_value)

    return updated_dictio

def get_equivalent_input_bit_from_output_bit(potential_unwanted_component, base_component, available_bits, all_equivalent_bits, key_schedule_components, self):
    all_bit_names = get_all_bit_names(self)
    potential_unwanted_bits = []
    potential_unwanted_bits_names = []
    input_bit_positions_of_potential_unwanted_component = []
    for index, input_id_link in enumerate(base_component.input_id_links):
        if input_id_link == potential_unwanted_component.id:
            input_bit_positions_of_potential_unwanted_component = base_component.input_bit_positions[index]

    for i in input_bit_positions_of_potential_unwanted_component:
        output_bit = {
            "component_id": potential_unwanted_component.id,
            "position": i,
            "type": "output"
        }
        output_bit_name = potential_unwanted_component.id + "_" + str(i) + "_output"
        potential_unwanted_bits.append(output_bit)
        potential_unwanted_bits_names.append(output_bit_name)

    equivalent_bits = []
    for potential_unwanted_bits_name in potential_unwanted_bits_names:
        for equivalent_bit in all_equivalent_bits[potential_unwanted_bits_name]:
            if (equivalent_bit in all_bit_names.keys()) and (
                    all_bit_names[equivalent_bit]["component_id"] != base_component.id) and (
                    all_bit_names[equivalent_bit] in available_bits) and (
                    all_bit_names[equivalent_bit]["component_id"] not in key_schedule_components) and (
                    all_bit_names[equivalent_bit]["type"] == "output_updated"): # changed, line added
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

def compute_input_id_links_and_input_bit_positions_for_inverse_component_from_input_components(component,
                                                                                               available_bits,
                                                                                               all_equivalent_bits,
                                                                                               key_schedule_components,
                                                                                               self):
    input_id_links = []
    input_bit_positions = []
    for i in range(len(component.input_id_links)):
        component_available = True
        bits = []
        for j in range(len(component.input_bit_positions[i])):
            bit = {
                "component_id": component.input_id_links[i],
                "position": component.input_bit_positions[i][j],
                "type": "output"
            }
            bits.append(bit)
            if not is_bit_contained_in(bit, available_bits):
                component_available = False
                break
        if component_available:
            potential_unwanted_component = get_component_from_id(component.input_id_links[i], self)
            equivalent_component, input_bit_positions_of_equivalent_component = get_equivalent_input_bit_from_output_bit(
                potential_unwanted_component, component, available_bits, all_equivalent_bits, key_schedule_components,
                self)
            input_id_links.append(equivalent_component)
            input_bit_positions.append(input_bit_positions_of_equivalent_component)

    return input_id_links, input_bit_positions


def component_input_bits(component):
    component_input_bits_list = []
    for index, link in enumerate(component.input_id_links):
        tmp = []
        for position in component.input_bit_positions[index]:
            tmp.append(
                {
                    "component_id": link,
                    "position": position,
                    "type": "output_updated"
                }
            )
        component_input_bits_list.append(tmp)
    return component_input_bits_list

def component_output_bits(component, self):
    # set of list_bits needed to invert
    output_components = get_output_components(component, self)
    component_output_bits_list = []
    for c in output_components:
        tmp = []
        for j in range(c.output_bit_size):
            bit = {
                "component_id": c.id,
                "position": j,
                "type": "output_updated"
            }
            tmp.append(bit)
        component_output_bits_list.append(tmp)
    return component_output_bits_list

def are_these_bits_available(bits_list, available_bits):
    for bit in bits_list:
        if bit not in available_bits:
            return False
    return True

# def are_there_enough_available_inputs_to_evaluate_component(component, available_bits, all_equivalent_bits, key_schedule_components,
#                 self):
#     #  check input links
#     component_input_bits_list = component_input_bits(component)
#     can_be_evaluated = [True] * len(component_input_bits_list)
#     if component.type == "constant":
#         return False
#     if component.type == "cipher_input":
#         return False
#     for index, bits_list in enumerate(component_input_bits_list):
#         if not are_these_bits_available(bits_list, available_bits):
#             can_be_evaluated[index] = False
#
#     if sum(can_be_evaluated) == len(can_be_evaluated):
#         return True
#     else:
#         for index, link in enumerate(component.input_id_links):
#             if not can_be_evaluated[index]:
#                 component_of_link = get_component_from_id(link, self)
#                 output_components = get_output_components(component_of_link, self)
#                 link_bit_names = []
#                 for bit in component_input_bits_list[index]:
#                     link_bit_name = bit["component_id"] + "_" + str(bit["position"]) + "_output"
#                     link_bit_names.append(link_bit_name)
#                 for output_component in output_components:
#                     if (output_component.id not in component.input_id_links) and (
#                             output_component.id != component.id):
#                         index_id = output_component.input_id_links.index(link)
#                         starting_bit = 0
#                         for index_list, list_bit_positions in enumerate(output_component.input_bit_positions):
#                             if index_list == index_id:
#                                 break
#                             starting_bit += len(list_bit_positions)
#                         output_component_bit_name = output_component.id + "_" + str(starting_bit) + "_output_updated"
#                         if is_bit_adjacent_to_list_of_bits(output_component_bit_name, link_bit_names,
#                                                            all_equivalent_bits):
#                             can_be_evaluated[index] = True
#         return sum(can_be_evaluated) == len(can_be_evaluated)

def are_there_enough_available_inputs_to_evaluate_component(component, available_bits, all_equivalent_bits, key_schedule_components, self):
    #  check input links
    component_input_bits_list = component_input_bits(component)
    can_be_evaluated = [True] * len(component_input_bits_list)
    available_output_components = []
    if component.type in [CONSTANT, CIPHER_INPUT]:
        return False
    for index, bits_list in enumerate(component_input_bits_list):
        if not are_these_bits_available(bits_list, available_bits):
            can_be_evaluated[index] = False
    available_input_components = [get_component_from_id(c_id, self) for i,c_id in enumerate(component.input_id_links) if can_be_evaluated[i] == True]

    if sum(can_be_evaluated) == len(can_be_evaluated):
        return True
    else:
        for index, link in enumerate(component.input_id_links):
            if not can_be_evaluated[index]:
                component_of_link = get_component_from_id(link, self)
                output_components = get_output_components(component_of_link, self)
                # can_be_evaluated_from_outputs = [False] * len(output_components)
                link_bit_names = []
                for bit in component_input_bits_list[index]:
                    link_bit_name = bit["component_id"] + "_" + str(bit["position"]) + "_output"
                    link_bit_names.append(link_bit_name)
                for index_output_comp, output_component in enumerate(output_components):
                    if (output_component.id not in component.input_id_links) and (
                            output_component.id != component.id):
                        index_id = output_component.input_id_links.index(link)
                        starting_bit = 0
                        for index_list, list_bit_positions in enumerate(output_component.input_bit_positions):
                            if index_list == index_id:
                                break
                            starting_bit += len(list_bit_positions)
                        output_component_bit_name = output_component.id + "_" + str(starting_bit) + "_output_updated"
                        if is_bit_adjacent_to_list_of_bits(output_component_bit_name, link_bit_names,
                                                           all_equivalent_bits):
                            # can_be_evaluated[index] = True
                            available_output_components.append(output_component)

        list_of_bit_names = []
        for c in available_output_components:
            for i in range(c.output_bit_size):
                list_of_bit_names.append(c.id + "_" + str(i) + "_output_updated")
        for c in available_input_components:
            for i in range(c.output_bit_size):
                list_of_bit_names.append(c.id + "_" + str(i) + "_output")
        for i in range(component.input_bit_size):
            bit_name = component.id + "_" + str(i) + "_input"
            if not is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
                return False
        return True


def _get_successor_components(component_id, cipher):
    graph_cipher = create_networkx_graph_from_input_ids(cipher)
    return list(graph_cipher.successors(component_id))

def are_there_enough_available_inputs_to_perform_inversion(component, available_bits, all_equivalent_bits, self):
    """
    NOTE: it assumes that the component input size is a multiple of the output size
    """
    # STEP 1 - Special case for output components which have no output links (only cipher output)
    if (component.type == CIPHER_OUTPUT) or (component.id == INPUT_KEY):
        return True
    if (component.type == INTERMEDIATE_OUTPUT and _get_successor_components(component.id, self) == []):
        return False

    # STEP 2 - Other components
    bit_lists_link_to_component_from_output = component_output_bits(component, self)
    component_output_bits_list = []
    for i in range(component.output_bit_size):
        component_output_bits_list.append({"component_id" : component.id, "position" : i, "type" : "output"})
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
            component_of_link = get_component_from_id(link, self)
            output_components = get_output_components(component_of_link, self)
            link_bit_names = []
            for bit in bit_lists_link_to_component_from_input[index]:
                link_bit_name = bit["component_id"] + "_" + str(bit["position"]) + "_output"
                link_bit_names.append(link_bit_name)
            for output_component in output_components:
                nb_available_output_component_bits = 0
                if (output_component.id not in component.input_id_links) and (
                        output_component.id != component.id) and (output_component.type != INTERMEDIATE_OUTPUT):
                    for i in range(output_component.output_bit_size):
                        output_component_bit_name = output_component.id + "_" + str(i) + "_output_updated"
                        output_component_bit = {"component_id": output_component.id, "position": i, "type": "output_updated"}
                        if is_bit_adjacent_to_list_of_bits(output_component_bit_name, link_bit_names, all_equivalent_bits) and (output_component_bit in available_bits):
                            nb_available_output_component_bits += 1
                    if nb_available_output_component_bits == output_component.output_bit_size:
                        can_be_used_for_inversion[index] = True

    # Merging available bits from inputs and output
    bit_lists_link_to_component_from_input_and_output = bit_lists_link_to_component_from_output_and_available
    for index, bits_list in enumerate(bit_lists_link_to_component_from_input):
        if can_be_used_for_inversion[index]:
            bit_lists_link_to_component_from_input_and_output += bits_list

    if component.id == INPUT_PLAINTEXT or INTERMEDIATE_OUTPUT in component.id:
        return len(bit_lists_link_to_component_from_input_and_output) >= component.output_bit_size
    else:
        return len(bit_lists_link_to_component_from_input_and_output) >= component.input_bit_size

def is_possibly_invertible_component(component):

    # if sbox is a permutation
    if component.type == SBOX and \
            len(list(set(component.description))) == len(component.description):
        is_invertible = True
    # if sbox is NOT a permutation, then cannot be inverted
    elif component.type == SBOX and len(list(set(component.description))) != len(component.description):
        is_invertible = False
    elif component.type == LINEAR_LAYER:
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

def is_intersection_of_input_id_links_null(inverse_component, component):
    flag_intersection_null = True
    for input_id_link in component.input_id_links:
        if input_id_link in inverse_component.input_id_links:
            flag_intersection_null = False
    if flag_intersection_null:
        return True, []

    if (component.type == "constant"):
        return False, list(range(component.output_bit_size))

    starting_bit_position = 0
    input_bit_positions = []
    for index, input_id_link in enumerate(component.input_id_links):
        if input_id_link not in inverse_component.input_id_links:
            input_bit_positions += range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[index]))
        starting_bit_position += len(component.input_bit_positions[index])
    return False, input_bit_positions

def find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits):
    starting_bit_position = 0
    for index, input_id_link in enumerate(component.input_id_links):
        input_bit_positions_of_inverse = inverse_component.input_bit_positions[index]
        for position, i in enumerate(component.input_bit_positions[index]):
            input_bit_name = input_id_link + "_" + str(i) + "_output"
            potential_equivalent_bit_name = inverse_component.input_id_links[index] + "_" + str(
                input_bit_positions_of_inverse[position]) + "_input"
            if input_bit_name not in all_equivalent_bits[potential_equivalent_bit_name]:
                input_bit_positions = list(
                    range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[index])))
                return input_bit_positions
        starting_bit_position += len(component.input_bit_positions[index])
    raise ValueError("Equivalent bits not found")

def update_output_bits(inverse_component, self, all_equivalent_bits, available_bits):

    def _add_output_bit_equivalences(id, bit_positions, component, all_equivalent_bits, available_bits):
        for i in range(component.output_bit_size):
            output_bit_name_updated = id + "_" + str(i) + "_output_updated"
            bit = {
                "component_id": id,
                "position": i,
                "type": "output_updated"
            }
            available_bits.append(bit)
            input_bit_name = id + "_" + str(bit_positions[i]) + "_input"
            all_equivalent_bits[input_bit_name].append(output_bit_name_updated)
            if output_bit_name_updated not in all_equivalent_bits.keys():
                all_equivalent_bits[output_bit_name_updated] = []
            all_equivalent_bits[output_bit_name_updated].append(input_bit_name)
            for name in all_equivalent_bits[input_bit_name]:
                if name != output_bit_name_updated:
                    all_equivalent_bits[output_bit_name_updated].append(name)
                    all_equivalent_bits[name].append(output_bit_name_updated)

    id = inverse_component.id
    component = get_component_from_id(id, self)
    flag_is_intersection_of_input_id_links_null, input_bit_positions = is_intersection_of_input_id_links_null(
        inverse_component, component)

    if (component.id == INPUT_KEY) or (component.type == CONSTANT):
        for i in range(component.output_bit_size):
            output_bit_name_updated = id + "_" + str(i) + "_output_updated"
            bit = {
                "component_id": id,
                "position": i,
                "type": "output_updated"
            }
            available_bits.append(bit)
            input_bit_name = id + "_" + str(i) + "_output"
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
        _add_output_bit_equivalences(id, range(component.output_bit_size), component, all_equivalent_bits, available_bits)
    else:
        if flag_is_intersection_of_input_id_links_null:
            input_bit_positions = find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits)
        _add_output_bit_equivalences(id, input_bit_positions, component, all_equivalent_bits, available_bits)

def order_input_id_links_for_modadd(component, input_id_links, input_bit_positions, available_bits, self):
    available_output_components_with_indices = get_available_output_components(component, available_bits, self, True)

    old_index = 0
    for index, input_id_link in enumerate(input_id_links):
        index_id_list = [_ for _, x in enumerate(available_output_components_with_indices) if
                         x[0].id == input_id_link and set(x[1]) == set(input_bit_positions[index])]
        if index_id_list:
            old_index = index
            break
    input_id_links.insert(0, input_id_links.pop(old_index))
    input_bit_positions.insert(0, input_bit_positions.pop(old_index))
    return input_id_links, input_bit_positions

def component_inverse(component, available_bits, all_equivalent_bits, key_schedule_components, self):
    """
    This functions assumes that the component is actually invertible.
    """
    output_components = get_output_components(component, self)
    available_output_components = get_available_output_components(component, available_bits, self)

    if component.type == SBOX:
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component, output_components, all_equivalent_bits, self)
        S = SBox(component.description)
        Sinv = list(S.inverse())
        inverse_component = Component(component.id, component.type, Input(component.input_bit_size, input_id_links, input_bit_positions), component.output_bit_size, Sinv)
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == LINEAR_LAYER:
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component, output_components, all_equivalent_bits, self)
        binary_matrix = binary_matrix_of_linear_component(component)
        inv_binary_matrix = binary_matrix.inverse()
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, list(inv_binary_matrix))
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == MIX_COLUMN:
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(
            component, available_output_components, all_equivalent_bits, self)
        inv_matrix = get_inverse_matrix_in_integer_representation(component)
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, [[list(row) for row in inv_matrix]] + component.description[1:])
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == WORD_OPERATION and component.description[0] == "SIGMA":
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component, output_components, all_equivalent_bits, self)
        binary_matrix = binary_matrix_of_linear_component(component)
        inv_binary_matrix = binary_matrix.inverse()
        inverse_component = Component(component.id, LINEAR_LAYER,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, list(inv_binary_matrix.transpose()))
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == WORD_OPERATION and component.description[0] == "XOR":
        input_id_links_from_output_components, input_bit_positions_from_output_components = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(
            component, output_components, all_equivalent_bits, self)
        input_id_links_from_input_components, input_bit_positions_from_input_components = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_input_components(component, available_bits, all_equivalent_bits, key_schedule_components, self)
        input_id_links = input_id_links_from_input_components + input_id_links_from_output_components
        input_bit_positions = input_bit_positions_from_input_components + input_bit_positions_from_output_components
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, component.description)
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == WORD_OPERATION and component.description[0] == "ROTATE":
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component, available_output_components, all_equivalent_bits, self)
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, [component.description[0], -component.description[1]])
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == WORD_OPERATION and component.description[0] == "NOT":
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(component, available_output_components, all_equivalent_bits, self)
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, [component.description[0], component.description[1]])
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == WORD_OPERATION and component.description[0] == "MODADD":
        input_id_links_from_output_components, input_bit_positions_from_output_components = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(
            component, available_output_components, all_equivalent_bits, self)
        input_id_links_from_input_components, input_bit_positions_from_input_components = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_input_components(
            component, available_bits, all_equivalent_bits, key_schedule_components, self)
        input_id_links = input_id_links_from_input_components + input_id_links_from_output_components
        input_bit_positions = input_bit_positions_from_input_components + input_bit_positions_from_output_components
        input_id_links, input_bit_positions = order_input_id_links_for_modadd(component, input_id_links, input_bit_positions, available_bits, self)
        inverse_component = Component(component.id, component.type,
                                      Input(component.input_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, ["MODSUB", component.description[1], component.description[2]])
        inverse_component.__class__ = modsub_component.MODSUB
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == CONSTANT:
        inverse_component = Component(component.id, component.type,
                                      Input(0, [[]], [[]]),
                                      component.output_bit_size, component.description)
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == CIPHER_OUTPUT:
        inverse_component = Component(component.id, CIPHER_INPUT,
                                      Input(0, [[]], [[]]),
                                      component.output_bit_size, [CIPHER_INPUT])
        setattr(inverse_component, "round", -1)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == CIPHER_INPUT and (component.id in [INPUT_PLAINTEXT, INPUT_STATE] or INTERMEDIATE_OUTPUT in component.id):
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(
            component, available_output_components, all_equivalent_bits, self)
        inverse_component = Component(component.id, CIPHER_OUTPUT,
                                      Input(component.output_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, [component.id])
        inverse_component.__class__ = cipher_output_component.CipherOutput
        setattr(inverse_component, "round", component.round)
    elif component.type == CIPHER_INPUT and (component.id == INPUT_KEY or component.id == INPUT_TWEAK):
        inverse_component = Component(component.id, CIPHER_INPUT,
                                      Input(0, [[]], [[]]),
                                      component.output_bit_size, [component.id])
        inverse_component.__class__ = component.__class__
        setattr(inverse_component, "round", -1)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    elif component.type == INTERMEDIATE_OUTPUT:
        input_id_links, input_bit_positions = compute_input_id_links_and_input_bit_positions_for_inverse_component_from_available_output_components(
            component, available_output_components, all_equivalent_bits, self)
        inverse_component = Component(component.id, INTERMEDIATE_OUTPUT,
                                      Input(component.output_bit_size, input_id_links, input_bit_positions),
                                      component.output_bit_size, [component.id])
        inverse_component.__class__ = intermediate_output_component.IntermediateOutput
        setattr(inverse_component, "round", component.round)
        update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    else:
        inverse_component = Component("NA", "NA",
                                      Input(0, [[]], [[]]),
                                      component.output_bit_size, ["NA"])

    return inverse_component

def update_available_bits_with_component_output_bits(component, available_bits, cipher):
    output_components = get_output_components(component, cipher)

    for i in range(component.output_bit_size):
        bit = {
            "component_id": component.id,
            "position": i,
            "type": "output"
        }
        add_bit_to_bit_list(bit, available_bits)

    # add bits of the connected output components
    for c in output_components:
        accumulator = 0
        for i in range(len(c.input_id_links)):
            if c.input_id_links[i] == component.id:
                for j in range(len(c.input_bit_positions[i])):
                    component_output_bit = {
                        "component_id": component.id,
                        "position": j,
                        "type": "output"
                    }
                    if is_bit_contained_in(component_output_bit, available_bits):
                        c_input_bit = {
                            "component_id": c.id,
                            "position": accumulator + j,
                            "type": "input"
                        }
                        add_bit_to_bit_list(c_input_bit, available_bits)
            accumulator += len(c.input_bit_positions[i])
    return


def update_available_bits_with_component_input_bits(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {
            "component_id": component.id,
            "position": i,
            "type": "input"
        }
        add_bit_to_bit_list(bit, available_bits)

    # add bits of the connected input components
    for i in range(len(component.input_id_links)):
        for j in range(len(component.input_bit_positions[i])):
            bit1 = {
                "component_id": component.input_id_links[i],
                "position": component.input_bit_positions[i][j],
                "type": "output"
            }
            add_bit_to_bit_list(bit1, available_bits)
    return


def all_input_bits_available(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {
            "component_id": component.id,
            "position": i,
            "type": "input"
        }
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True

def all_output_updated_bits_available(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {
            "component_id": component.id,
            "position": i,
            "type": "output_updated"
        }
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True

def all_output_bits_available(component, available_bits):
    for i in range(component.output_bit_size):
        bit = {
            "component_id": component.id,
            "position": i,
            "type": "output_updated"
        }
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def get_component_from_id(component_id, self):
    cipher_components = get_cipher_components(self)
    for c in cipher_components:
        if c.id == component_id:
            return c
    return None


def get_key_schedule_component_ids(self):
    key_schedule_component_ids = [INPUT_KEY]
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

def find_correct_order(id1, list1, id2, list2, all_equivalent_bits):
    list2_ordered = []
    for i in list1:
        bit = id1 + "_" + str(i) + "_output"
        for j in list2:
            bit_potentially_equivalent = id2 + "_" + str(j) + "_input"
            if bit_potentially_equivalent in all_equivalent_bits[bit]:
                list2_ordered.append(j)
                break
    return list2_ordered

def find_correct_order_for_inversion(list1, list2, component):
    list2_ordered = []
    for i in list1:
        list2_ordered.append(list2[i % component.output_bit_size])
    return list2_ordered

# def evaluated_component(component, available_bits, key_schedule_component_ids, all_equivalent_bits, self):
#     input_id_links = []
#     input_bit_positions = []
#     if (component.type == "fdjgfk") and (component.id not in key_schedule_component_ids):
#         for index_link, link in enumerate(component.input_id_links):
#             component_of_link = get_component_from_id(link, self)
#             available_output_components = get_available_output_components(component_of_link, available_bits, self)
#             link_bit_names = []
#             for i in range(component_of_link.output_bit_size):
#                 link_bit_name = link + "_" + str(i) + "_output"
#                 link_bit_names.append(link_bit_name)
#             for index_available_output_component, available_output_component in enumerate(available_output_components):
#                 if (available_output_component.id not in component.input_id_links) and (
#                         available_output_component.id != component.id):
#                     index_id = available_output_component.input_id_links.index(link)
#                     starting_bit = 0
#                     for index_list, list_bit_positions in enumerate(available_output_component.input_bit_positions):
#                         if index_list == index_id:
#                             break
#                         starting_bit += len(list_bit_positions)
#                     available_output_component_bit_name = available_output_component.id + "_" + str(starting_bit) + "_output_updated"
#                     if is_bit_adjacent_to_list_of_bits(available_output_component_bit_name, link_bit_names,
#                                                        all_equivalent_bits):
#                         input_id_links.append(available_output_component.id)
#                         input_bit_positions.append(list(range(starting_bit, starting_bit + len(available_output_component.input_bit_positions[index_list]))))
#
#         evaluated_component = Component(component.id, component.type, Input(component.input_bit_size, input_id_links, input_bit_positions),
#                                         component.output_bit_size, component.description)
#         setattr(evaluated_component, "round", getattr(component, "round"))
#         return evaluated_component
#
#     if component.type != "cipher_input":
#         components_with_same_input_bits = []
#         starting_bit_position = 0
#         for i in range(len(component.input_id_links)):
#             components_with_same_input_bits = get_all_components_with_the_same_input_id_link_and_input_bit_positions(
#                 component.input_id_links[i], component.input_bit_positions[i], self)
#             components_with_same_input_bits.remove(component)
#
#             # check if the original input component has all output bits available
#             original_input_component = get_component_from_id(component.input_id_links[i], self)
#             output_bits_updated_list = []
#             for j in component.input_bit_positions[i]:
#                 output_bit_updated_name = original_input_component.id + "_" + str(j) + "_output_updated"
#                 output_bits_updated_list.append(output_bit_updated_name)
#             input_bits_list = []
#             for k in range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[i])):
#                 input_bit_name = component.id + "_" + str(k) + "_input"
#                 input_bits_list.append(input_bit_name)
#             starting_bit_position += len(component.input_bit_positions[i])
#             flag = is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits)
#             if all_output_bits_available(original_input_component, available_bits) and flag:
#                 input_id_links.append(component.input_id_links[i])
#                 input_bit_positions.append(component.input_bit_positions[i])
#             else:
#                 # select component for which the connected components have all their inputs available
#                 link = component.input_id_links[i]
#                 original_input_bit_positions_of_link = component.input_bit_positions[i]
#                 for c in components_with_same_input_bits:
#                     if all_input_bits_available(c, available_bits):
#                         input_id_links.append(c.id)
#                         # get input bit positions
#                         accumulator = 0 # changed
#                         for j in range(len(c.input_id_links)):
#                             if component.input_id_links[i] == c.input_id_links[j]:
#                                 l = [h for h in range(accumulator, accumulator + len(component.input_bit_positions[i]))]
#                                 l_ordered = find_correct_order(link, original_input_bit_positions_of_link, c.id, l, all_equivalent_bits)
#                                 input_bit_positions.append(l_ordered)
#                                 # break?
#                             else:
#                                 accumulator += len(c.input_bit_positions[j]) # changed
#     else:
#         input_id_links = [[]]
#         input_bit_positions = [[]]
#     evaluated_component = Component(component.id, component.type, Input(component.input_bit_size, input_id_links, input_bit_positions),
#                                     component.output_bit_size, component.description)
#     setattr(evaluated_component, "round", getattr(component, "round"))
#
#     id = component.id
#     for i in range(evaluated_component.output_bit_size):
#         output_bit_name_updated = id + "_" + str(i) + "_output_updated"
#         bit = {
#             "component_id": id,
#             "position": i,
#             "type": "output_updated"
#         }
#         available_bits.append(bit)
#         output_bit_name = id + "_" + str(i) + "_output"
#         if output_bit_name not in all_equivalent_bits.keys():
#             all_equivalent_bits[output_bit_name] = []
#         all_equivalent_bits[output_bit_name].append(output_bit_name_updated)
#         if output_bit_name_updated not in all_equivalent_bits.keys():
#             all_equivalent_bits[output_bit_name_updated] = []
#         all_equivalent_bits[output_bit_name_updated].append(output_bit_name)
#         for name in all_equivalent_bits[output_bit_name]:
#             if name != output_bit_name_updated:
#                 all_equivalent_bits[output_bit_name_updated].append(name)
#
#     return evaluated_component

def evaluated_component(component, available_bits, key_schedule_component_ids, all_equivalent_bits, self):
    input_id_links = []
    input_bit_positions = []

    if component.type != "cipher_input":
        components_with_same_input_bits = []
        starting_bit_position = 0
        for i in range(len(component.input_id_links)):
            components_with_same_input_bits = get_all_components_with_the_same_input_id_link_and_input_bit_positions(
                component.input_id_links[i], component.input_bit_positions[i], self)
            components_with_same_input_bits.remove(component)

            # check if the original input component has all output bits available
            original_input_component = get_component_from_id(component.input_id_links[i], self)
            output_bits_updated_list = []
            for j in component.input_bit_positions[i]:
                output_bit_updated_name = original_input_component.id + "_" + str(j) + "_output_updated"
                output_bits_updated_list.append(output_bit_updated_name)
            input_bits_list = []
            for k in range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[i])):
                input_bit_name = component.id + "_" + str(k) + "_input"
                input_bits_list.append(input_bit_name)
            starting_bit_position += len(component.input_bit_positions[i])
            flag = is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits)
            if all_output_bits_available(original_input_component, available_bits) and flag:
                input_id_links.append(component.input_id_links[i])
                input_bit_positions.append(component.input_bit_positions[i])
            else:
                # select component for which the connected components have all their inputs available
                link = component.input_id_links[i]
                original_input_bit_positions_of_link = component.input_bit_positions[i]
                available_output_components = get_available_output_components(original_input_component, available_bits, self)
                link_bit_names = []
                for l in range(original_input_component.output_bit_size):
                    link_bit_name = link + "_" + str(l) + "_output"
                    link_bit_names.append(link_bit_name)
                for index_available_output_component, available_output_component in enumerate(
                        available_output_components):
                    if (available_output_component.id not in component.input_id_links) and (
                            available_output_component.id != component.id):
                        index_id_list = [_ for _, x in enumerate(available_output_component.input_id_links) if x == link and set(original_input_bit_positions_of_link) <= set(available_output_component.input_bit_positions[_])]
                        index_id = index_id_list[0] if index_id_list else available_output_component.input_id_links.index(link)
                        starting_bit = 0
                        for index_list, list_bit_positions in enumerate(available_output_component.input_bit_positions):
                            if index_list == index_id:
                                break
                            starting_bit += len(list_bit_positions)
                        available_output_component_bit_name = available_output_component.id + "_" + str(
                            starting_bit) + "_output_updated"
                        if is_bit_adjacent_to_list_of_bits(available_output_component_bit_name, link_bit_names,
                                                           all_equivalent_bits):
                            # if all_input_bits_available(c, available_bits):
                            input_id_links.append(available_output_component.id)
                            # get input bit positions
                            accumulator = 0 # changed
                            for j in range(len(available_output_component.input_id_links)):
                                if j == index_id:
                                    if set(original_input_bit_positions_of_link) < set(available_output_component.input_bit_positions[j]):
                                        accumulator += original_input_bit_positions_of_link[0] - available_output_component.input_bit_positions[j][0]
                                    l = [h for h in range(accumulator, accumulator + len(component.input_bit_positions[i]))]
                                    l_ordered = find_correct_order(link, original_input_bit_positions_of_link, available_output_component.id, l, all_equivalent_bits)
                                    input_bit_positions.append(l_ordered)
                                    break
                                else:
                                    accumulator += len(available_output_component.input_bit_positions[j]) # changed
    else:
        input_id_links = [[]]
        input_bit_positions = [[]]
    evaluated_component = Component(component.id, component.type, Input(component.input_bit_size, input_id_links, input_bit_positions),
                                    component.output_bit_size, component.description)
    evaluated_component.__class__ = component.__class__
    setattr(evaluated_component, "round", getattr(component, "round"))

    id = component.id
    for i in range(evaluated_component.output_bit_size):
        output_bit_name_updated = id + "_" + str(i) + "_output_updated"
        bit = {
            "component_id": id,
            "position": i,
            "type": "output_updated"
        }
        available_bits.append(bit)
        output_bit_name = id + "_" + str(i) + "_output"
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
                component.input_id_links[idx] = ''
        new_components.append(component)
    return new_components

def topological_sort(round_list):
    """
    Perform topological sort on round components.
    INPUT:
    - ``round_list`` -- list of components
    """
    pending = [(component.id, set(component.input_id_links)) for component in round_list]
    emitted = ['']
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
        sage: from tii.graph_representations.creator import GraphRepresentationCreator
        sage: GR = GraphRepresentationCreator()
        sage: cipher_python_dictionary = GR.identity_block_cipher_creator()
        sage: sorted_cipher = GR.sort_cipher_graph(cipher_python_dictionary)
    """

    k = 0
    for _ in range(cipher.number_of_rounds):
        round_components = delete_orphan_links(cipher, k)
        ordered_ids = list(topological_sort(round_components))
        id_dict = {d.id: d for d in cipher._rounds.round_at(k)._components}
        cipher._rounds.round_at(k)._components = [id_dict[i] for i in ordered_ids]
        k = k + 1

    return cipher

def remove_components_from_rounds(cipher, start_round, end_round, keep_key_schedule):
    list_of_rounds = cipher.rounds_as_list[:start_round] + cipher.rounds_as_list[end_round + 1:]
    key_schedule_component_ids = get_key_schedule_component_ids(cipher)
    key_schedule_components = [cipher.get_component_from_id(id) for id in key_schedule_component_ids[1:]]

    if not keep_key_schedule:
        for current_round in cipher.rounds_as_list:
            for key_component in set(key_schedule_components).intersection(current_round.components):
                cipher.rounds.remove_round_component(current_round.id, key_component)

    removed_component_ids = []
    intermediate_outputs = {}
    for current_round in list_of_rounds:
        for component in set(current_round.components) - set(key_schedule_components):
            if component.type == INTERMEDIATE_OUTPUT and component.description == ['round_output']:
                intermediate_outputs[current_round.id] = component
            cipher.rounds.remove_round_component(current_round.id, component)
            removed_component_ids.append(component.id)

    return removed_component_ids, intermediate_outputs

def get_relative_position(target_link, target_bit_positions, descendant):
    offset = 0
    if target_link == descendant.id:
        return target_bit_positions
    for i, link in enumerate(descendant.input_id_links):
        child_input_bit_position = descendant.input_bit_positions[i]
        if link == target_link:
            if set(target_bit_positions) <= set(child_input_bit_position):
                return [idx + offset for idx, e in enumerate(child_input_bit_position) if e in target_bit_positions]
        offset += len(child_input_bit_position)
    return []

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
                    component.input_id_links[i] = f'{intermediate_output.id}'
                    component.input_bit_positions[i] = get_relative_position(link, component.input_bit_positions[i], intermediate_output)
