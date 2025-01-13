
def extract_constants(cipher):
    constant_components_ids = []
    constant_components = []
    for component in cipher.get_all_components():
        if 'constant' in component.id:
            constant_components_ids.append(component.id)
            constant_components.append(component)
        elif '_' in component.id:
            component_inputs = component.input_id_links
            ks = True
            for comp_input in component_inputs:
                if 'constant' not in comp_input:
                    ks = False
            if ks:
                constant_components_ids.append(component.id)
                constant_components.append(component)
            
    return constant_components, constant_components_ids

def extract_key_schedule(cipher, key_schedule_bits_distribution):
    key_schedule_components_ids = ['key']
    key_schedule_components = []
    for component in cipher.get_all_components():
        component_inputs = component.input_id_links
        ks = True
        for comp_input in component_inputs:
            if 'constant' not in comp_input and comp_input not in key_schedule_components_ids:
                ks = False
        if ks:
            key_schedule_components_ids.append(component.id)
            key_schedule_components.append(component)
            master_key_bits = []
            for id_link, bit_positions in zip(component_inputs, component.input_bit_positions):
                if id_link == 'key':
                    master_key_bits.extend(bit_positions)
                else:
                    if id_link in key_schedule_bits_distribution:
                        master_key_bits.extend(key_schedule_bits_distribution[id_link])
            self.key_schedule_bits_distribution[component.id] = list(set(master_key_bits))
                
    return key_schedule_components, key_schedule_components_ids

def filter_out_strings_containing_substring(strings_list, substring):
    return [string for string in strings_list if substring not in string]

def get_component_from_id(id_link, curr_cipher):
    for component in curr_cipher.get_all_components():
        if component.id == id_link:
            return component
    return None

def get_component_round(id_link):
    if '_' in id_link:
        last_us = - id_link[::-1].index('_') - 1
        start = - id_link[last_us - 1::-1].index('_') + last_us
    
        return int(id_link[start:len(id_link) + last_us])
    else:
        return 0
    
def get_direct_component_correspondance(inverse_cipher, forward_component):
    for inverse_component in inverse_cipher.get_all_components():
        if inverse_component.get_inverse_component_correspondance(inverse_component) == forward_component:
            return inverse_component
                
def get_inverse_component_correspondance(cipher, inverse_cipher, backward_component):
    
    for component in cipher.get_all_components():
        if backward_component.id == component.id:
            direct_inputs = component.input_id_links
    inverse_outputs = []
    for component in inverse_cipher.get_all_components():
        if backward_component.id in component.input_id_links:
            inverse_outputs.append(component.id)
    correspondance = [dir_i for dir_i in direct_inputs if dir_i in inverse_outputs]
    if len(correspondance) > 1:
        return 'Not invertible'
    else:
        return correspondance[0]

def get_inverse_state_key_bits_positions(inverse_cipher, key_schedule_bits_distribution):
    key_bits = key_schedule_bits_distribution
    for component in inverse_cipher.get_all_components():
        if component.id not in key_bits:
            component_key_bits = []
            for id_link in component.input_id_links:
                if id_link in key_bits:
                    component_key_bits.extend(key_bits[id_link])
            key_bits[component.id] = list(set(component_key_bits))
                    
    return key_bits
    
def get_state_key_bits_positions(cipher, key_schedule_bits_distribution):
    key_bits = key_schedule_bits_distribution
    for component in cipher.get_all_components():
        if component.id not in key_bits:
            component_key_bits = []
            for id_link in component.input_id_links:
                if id_link in key_bits:
                    component_key_bits.extend(key_bits[id_link])
        key_bits[component.id] = list(set(component_key_bits))
                    
    return key_bits
       
def group_strings_by_pattern(list_of_data):
    results = []
    data = list_of_data
    data = filter_out_strings_containing_substring(data, 'array')
    prefixes = set([entry.split("_y")[0].split(": ")[1] for entry in data if "_y" in entry])

    # For each prefix, collect matching strings
    for prefix in prefixes:
        sublist = [entry.split(": ")[1][:-1] for entry in data if
                   entry.startswith(f"var bool: {prefix}") and "_y" in entry]
        if sublist:
            results.append(sublist)

    return results