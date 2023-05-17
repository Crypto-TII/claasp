from copy import deepcopy


def creating_component_pairs(round_component_):
    original_component = deepcopy(round_component_)
    new_id_pair1 = f'{original_component.id}_pair1'
    new_id_pair2 = f'{original_component.id}_pair2'
    original_component.set_id(new_id_pair1)
    component_copy = deepcopy(original_component)
    component_copy.set_id(new_id_pair2)
    return original_component, component_copy


def update_input_ids_link(component1_, component2_):
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


def create_xor_components_inputs(old_cipher_inputs_, cipher):
    cipher._inputs_bit_size = 2 * cipher.inputs_bit_size
    half_number_of_cipher_inputs = int(len(cipher.inputs_bit_size) / 2)
    i = 0
    for cipher_input in old_cipher_inputs_:
        cipher.add_XOR_component(
            [f'{cipher_input}_pair1'] + [f'{cipher_input}_pair2'],
            [list(range(cipher.inputs_bit_size[i]))] +
            [list(range(cipher.inputs_bit_size[i + half_number_of_cipher_inputs]))],
            cipher.inputs_bit_size[i]
        )
        i += 1


def create_xor_components(component1_, component2_, cipher):
    cipher.add_XOR_component(
        [component1_.id] + [component2_.id],
        [list(range(component1_.output_bit_size))] + [list(range(component2_.output_bit_size))],
        component1_.output_bit_size
    )


def create_compounded_xor_cipher(cipher):
    old_cipher_inputs = update_cipher_inputs(cipher)
    create_xor_components_inputs(old_cipher_inputs, cipher)
    cipher._output_bit_size = 2 * cipher.output_bit_size
    for round_number in range(cipher.number_of_rounds):
        round_object = cipher.rounds.round_at(round_number)
        list_of_components = deepcopy(round_object.components)
        for round_component in list_of_components:
            component1, component2 = creating_component_pairs(round_component)
            round_object.remove_component_from_id(round_component.id)
            round_object.add_component(component1)
            round_object.add_component(component2)
            update_input_ids_link(component1, component2)
            create_xor_components(component1, component2, cipher)
