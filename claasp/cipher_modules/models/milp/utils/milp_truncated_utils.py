from claasp.cipher_modules.inverse_cipher import get_key_schedule_component_ids
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_BITWISE_IMPOSSIBLE_AUTO, \
    MILP_WORDWISE_IMPOSSIBLE_AUTO, MILP_BACKWARD_SUFFIX
from claasp.cipher_modules.models.milp.utils.utils import milp_if_then
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY

def generate_incompatiblity_constraints_for_component(model, model_type, x, x_class, backward_component, include_all_components):

    incompatiblity_constraints = []

    if model_type == MILP_BITWISE_IMPOSSIBLE_AUTO:
        output_size = backward_component.output_bit_size
        input_ids, output_ids = backward_component._get_input_output_variables()

    else:
        output_size = backward_component.output_bit_size // model.word_size
        input_ids, output_ids = backward_component._get_wordwise_input_output_linked_class(model)


    if include_all_components:
        # for multiple input components such as the XOR, ensures compatibility occurs on the correct branch
        inputs_to_be_kept = []
        for index, input_id in enumerate(["_".join(i.split("_")[:-1]) for i in set(backward_component.input_id_links)]):
            if INPUT_KEY not in input_id and [link + MILP_BACKWARD_SUFFIX for link in
                                                   model._cipher.get_component_from_id(input_id).input_id_links] == [
                backward_component.id]:
                inputs_to_be_kept.extend([_ for _ in input_ids if input_id in _])
        backward_vars = [x_class[id] for id in (inputs_to_be_kept or input_ids) if INPUT_KEY not in id]
    else:
        backward_vars = [x_class[id] for id in output_ids]

    if model_type == MILP_BITWISE_IMPOSSIBLE_AUTO:
        forward_vars = [x_class["_".join(id.split("_")[:-2] + [id.split("_")[-1]])] for id in output_ids]
    else:
        forward_vars = [x_class["_".join(id.split("_")[:-4] + id.split("_")[-3:])] for id in output_ids]

    inconsistent_vars = [x[f"{backward_component.id}_inconsistent_{_}"] for _ in range(output_size)]

    for inconsistent_index in range(output_size):
        if model_type == MILP_BITWISE_IMPOSSIBLE_AUTO:
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] == 1]
        else:
            incompatibility_constraint = [forward_vars[inconsistent_index] + backward_vars[inconsistent_index] <= 2]
        incompatiblity_constraints.extend(milp_if_then(inconsistent_vars[inconsistent_index], incompatibility_constraint,
                                    model._model.get_max(x_class) * 2))


    return incompatiblity_constraints, inconsistent_vars


def generate_all_incompatibility_constraints_for_fully_automatic_model(model, model_type, x, x_class, include_all_components):

    assert model_type in [MILP_BITWISE_IMPOSSIBLE_AUTO, MILP_WORDWISE_IMPOSSIBLE_AUTO]

    constraints = []
    forward_output = [c for c in model._forward_cipher.get_all_components() if c.type == CIPHER_OUTPUT][0]
    all_inconsistent_vars = []
    backward_components = [c for c in model._backward_cipher.get_all_components() if
                           c.description == ['round_output'] and set(c.input_id_links) != {
                               forward_output.id + MILP_BACKWARD_SUFFIX}]

    key_flow = set(get_key_schedule_component_ids(model._cipher)) - {INPUT_KEY}
    backward_key_flow = [f'{id}{MILP_BACKWARD_SUFFIX}' for id in key_flow]

    if include_all_components:
        backward_components = set(model._backward_cipher.get_all_components()) - set(
            model._backward_cipher.get_component_from_id(key_flow_id) for key_flow_id in backward_key_flow)

    for backward_component in backward_components:
        incompatibility_constraints, inconsistent_vars = generate_incompatiblity_constraints_for_component(model, model_type, x, x_class, backward_component, include_all_components)
        all_inconsistent_vars += inconsistent_vars
        constraints.extend(incompatibility_constraints)

    constraints.extend([sum(all_inconsistent_vars) == 1])

    return constraints


def fix_variables_value_deterministic_truncated_xor_differential_constraints(milp_model, model_variables, fixed_variables=[]):
    constraints = []
    if 'Wordwise' in milp_model.__class__.__name__:
        prefix = "_word"
        suffix = "_class"
    else:
        prefix = ""
        suffix = ""

    for fixed_variable in fixed_variables:
        if fixed_variable["constraint_type"] == "equal":
            for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                component_bit = f'{fixed_variable["component_id"]}{prefix}_{bit_position}{suffix}'
                constraints.append(model_variables[component_bit] == fixed_variable["bit_values"][index])
        else:
            if sum(fixed_variable["bit_values"]) == 0:
                constraints.append(sum(model_variables[f'{fixed_variable["component_id"]}{prefix}_{i}{suffix}'] for i in fixed_variable["bit_positions"]) >= 1)
            else:
                M = milp_model._model.get_max(model_variables) + 1
                d = milp_model._binary_variable
                one_among_n = 0

                for index, bit_position in enumerate(fixed_variable["bit_positions"]):
                    # eq = 1 iff bit_position == diff_index
                    eq = d[f'{fixed_variable["component_id"]}{prefix}_{bit_position}{suffix}_is_diff_index']
                    one_among_n += eq

                    # x[diff_index] < fixed_variable[diff_index] or fixed_variable[diff_index] < x[diff_index]
                    dummy = d[f'{fixed_variable["component_id"]}{prefix}_{bit_position}{suffix}_is_diff_index']
                    a = model_variables[f'{fixed_variable["component_id"]}{prefix}_{bit_position}{suffix}']
                    b = fixed_variable["bit_values"][index]
                    constraints.extend([a <= b - 1 + M * (2 - dummy - eq), a >= b + 1 - M * (dummy + 1 - eq)])

                constraints.append(one_among_n == 1)

    return constraints
