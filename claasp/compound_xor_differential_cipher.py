from copy import deepcopy

from claasp.components.xor_component import XOR


def get_component_pair(round_component_):
    original_component = deepcopy(round_component_)
    new_id_pair1 = f'{original_component.id}_pair1'
    new_id_pair2 = f'{original_component.id}_pair2'
    original_component.set_id(new_id_pair1)
    component_copy = deepcopy(original_component)
    component_copy.set_id(new_id_pair2)
    return original_component, component_copy


def update_input_id_links(component1_, component2_):
    input_id_links1 = component1_.input_id_links
    input_id_links2 = component2_.input_id_links
    new_input_id_link1 = []
    for input_id_link1 in input_id_links1:
        new_input_id_link1.append(f'{input_id_link1}_pair1')
    new_input_id_link2 = []
    for input_id_link2 in input_id_links2:
        new_input_id_link2.append(f'{input_id_link2}_pair2')
    component1_.set_input_id_links(new_input_id_link1)
    component2_.set_input_id_links(new_input_id_link2)


def update_cipher_inputs(cipher):
    new_inputs_pair1 = []
    new_inputs_pair2 = []
    old_cipher_inputs_ = deepcopy(cipher.inputs)
    for cipher_input in cipher.inputs:
        new_inputs_pair1.append(f'{cipher_input}_pair1')
        new_inputs_pair2.append(f'{cipher_input}_pair2')
    cipher._inputs = new_inputs_pair1 + new_inputs_pair2
    return old_cipher_inputs_


def create_xor_component_inputs(old_cipher_inputs_, cipher, round_object):
    cipher._inputs_bit_size = 2 * cipher.inputs_bit_size
    half_number_of_cipher_inputs = int(len(cipher.inputs_bit_size) / 2)
    i = 0
    for cipher_input in old_cipher_inputs_:
        input_link_positions = [list(range(cipher.inputs_bit_size[i]))] + \
                               [list(range(cipher.inputs_bit_size[i + half_number_of_cipher_inputs]))]
        input_links = [f'{cipher_input}_pair1', f'{cipher_input}_pair2']
        current_components_number = round_object.get_number_of_components()
        output_bit_size = cipher.inputs_bit_size[i]
        new_xor_component = XOR(0, current_components_number, input_links, input_link_positions,
                                output_bit_size)
        new_xor_component.set_id(f'{cipher_input}_pair1_pair2')
        round_object.add_component(new_xor_component)
        i += 1


def create_xor_component(component1_, component2_, round_object, round_number):
    input_link_positions = [list(range(component1_.output_bit_size))] + [list(range(component2_.output_bit_size))]
    input_links = [component1_.id, component2_.id]
    current_components_number = round_object.get_number_of_components()
    output_bit_size = component1_.output_bit_size
    new_xor_component = XOR(round_number, current_components_number, input_links, input_link_positions, output_bit_size)
    if component1_.type == 'intermediate_output':
        new_xor_component.set_id(f'{component1_.id}_pair2')
    elif component1_.type == 'cipher_output':
        new_xor_component.set_id(f'{component1_.id}_pair2')
    round_object.add_component(new_xor_component)


def convert_to_compound_xor_cipher(cipher):
    for round_number in range(cipher.number_of_rounds):
        round_object = cipher.rounds.round_at(round_number)
        round_object_temp = deepcopy(cipher.rounds.round_at(round_number))
        list_of_components = deepcopy(round_object_temp.components)
        for round_component in list_of_components:
            component1, component2 = get_component_pair(round_component)
            round_object.remove_component_from_id(round_component.id)
            round_object.add_component(component1)
            round_object.add_component(component2)
            update_input_id_links(component1, component2)
            create_xor_component(component1, component2, round_object, round_number)
    old_cipher_inputs = update_cipher_inputs(cipher)
    round_object = cipher.rounds.round_at(0)
    create_xor_component_inputs(old_cipher_inputs, cipher, round_object)
    cipher._output_bit_size = 2 * cipher.output_bit_size
