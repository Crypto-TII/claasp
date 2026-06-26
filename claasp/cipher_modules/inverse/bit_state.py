"""Per-component bit accounting and availability helpers for the inversion engine."""

from claasp.cipher_modules.inverse.cipher_view import (
    add_bit_to_bit_list,
    is_bit_contained_in,
)
from claasp.cipher_modules.inverse.equivalence import equivalent_bit_names, is_bit_adjacent_to_list_of_bits


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
    output_components = self.get_successor_components(component)
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
    for equivalent_bit in equivalent_bit_names(f"{link}_{position}_output", all_equivalent_bits):
        if equivalent_bit.endswith("_output_updated"):
            source_id, source_position = equivalent_bit[: -len("_output_updated")].rsplit("_", 1)
            if {"component_id": source_id, "position": int(source_position), "type": "output_updated"} in available_bits:
                return True
    return False


def update_available_bits_with_component_output_bits(component, available_bits, cipher):
    output_components = cipher.get_successor_components(component)

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


def all_output_bits_available(component, available_bits):
    for i in range(component.output_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "output_updated"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits):
    for bit in output_bits_updated_list:
        if not is_bit_adjacent_to_list_of_bits(bit, input_bits_list, all_equivalent_bits):
            return False
    return True
