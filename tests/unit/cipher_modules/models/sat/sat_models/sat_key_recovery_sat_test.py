import itertools
import os
import pickle
import types

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.cipher_modules.models.sat.sat_models.sat_shared_truncated_difference_paired_input_differential_linear_model import \
    SharedTruncatedDifferencePairedInputDifferentialLinearModel
from claasp.cipher_modules.models.sat.utils import constants
from claasp.cipher_modules.models.sat.utils.utils import cnf_equivalent
from claasp.cipher_modules.models.utils import set_component_solution
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.components.intermediate_output_component import IntermediateOutput
from claasp.components.modsub_component import MODSUB


def load_or_create_inverse(cipher, pickle_file='chacha_inverse.pkl'):
    if os.path.exists(f'{pickle_file}_{cipher.number_of_rounds}'):
        with open(f'{pickle_file}_{cipher.number_of_rounds}', 'rb') as f:
            inverse = pickle.load(f)
            print("Loaded cached inverse.")
            return inverse
    else:
        inverse = cipher.cipher_inverse()
        with open(f'{pickle_file}_{cipher.number_of_rounds}', 'wb') as f:
            pickle.dump(inverse, f)
            print("Computed and cached inverse.")
            return inverse


def split_512bit_hex_to_32bit_words(hex_string):
    # Normalize input: remove '0x' if present and pad to 128 hex characters
    hex_string = hex_string.lower().lstrip("0x").zfill(128)
    if len(hex_string) != 128:
        raise ValueError("Input must represent a 512-bit number (128 hex characters).")

    # Split into 16 chunks of 8 hex characters (32 bits each)
    hex_list = [hex_string[i:i + 8] for i in range(0, 128, 8)]
    for idx, val in enumerate(hex_list):
        print(f'0x{val},')


def binary_string_to_32bit_hex_chunks(binary_string):
    if len(binary_string) != 512:
        raise ValueError("Input must be exactly 512 characters long.")

    # Step 1: Split into 16 chunks of 32 bits
    chunks = [binary_string[i:i + 32] for i in range(0, 512, 32)]

    # Step 2: Replace '?' with '1' in each chunk
    replaced_chunks = [chunk.replace('?', '1') for chunk in chunks]

    # Step 3: Convert binary to 32-bit hex string
    hex_chunks = [format(int(chunk, 2), '08x') for chunk in replaced_chunks]

    for i, hex_number in enumerate(hex_chunks):
        print(f"state[{i}] ^= 0x{hex_number};")
        print(f"alt_state[{i}] ^= 0x{hex_number};")


def add_prefix_id_to_inputs(chacha_permutation, prefix):
    new_inputs = []
    for chacha_permutation_input in chacha_permutation.inputs:
        new_inputs.append(f'{prefix}_{chacha_permutation_input}')
    chacha_permutation.set_inputs(new_inputs, chacha_permutation.inputs_bit_size)


def add_ciphertext_and_new_plaintext_to_inputs(chacha_permutation):
    chacha_permutation.inputs.append("ciphertext_final")
    chacha_permutation.inputs.append("fake_plaintext")
    chacha_permutation.inputs_bit_size.append(512)
    chacha_permutation.inputs_bit_size.append(512)
    modsub_ids = []
    constants_ids = []
    round_object = chacha_permutation.rounds.round_at(0)
    for i in range(16):
        new_modsub_component = MODSUB(
            0,
            round_object.get_number_of_components(),
            ["ciphertext_final", "fake_plaintext"],
            [list(range(i * 32, (i) * 32 + 32)),
             list(range(i * 32, (i) * 32 + 32))],
            32,
            None
        )
        round_object.add_component(new_modsub_component)

        modsub_ids.append(new_modsub_component.id)
    new_intermediate_output_component = IntermediateOutput(
        0,
        round_object.get_number_of_components(),
        modsub_ids,
        [list(range(32)) for i in range(16)],
        512,
        "round_output"
    )
    round_object.add_component(new_intermediate_output_component)
    new_intermediate_output_component.set_id(chacha_permutation.inputs[0])
    chacha_permutation.inputs.pop(0)
    chacha_permutation.inputs_bit_size.pop(0)


def add_prefix_id_to_components(chacha_permutation, prefix):
    all_components = chacha_permutation.rounds.get_all_components()
    for component in all_components:
        component.set_id(f'{prefix}_{component.id}')
        new_input_id_links = [f'{prefix}_{input_id_link}' for input_id_link in component.input_id_links]
        component.set_input_id_links(new_input_id_links)
    return 0


def construct_backward_chacha(cipher):
    chacha_key_recovery = cipher
    chacha_inverse = load_or_create_inverse(chacha_key_recovery)
    plaintext = 0x099a9a9a6a6a5a435678
    assert chacha_inverse.evaluate([cipher.evaluate([plaintext])]) == plaintext

    add_ciphertext_and_new_plaintext_to_inputs(chacha_inverse)
    add_prefix_id_to_inputs(chacha_inverse, "bottom")
    add_prefix_id_to_components(chacha_inverse, "bottom")
    chacha_inverse.sort_cipher()
    return chacha_inverse


def backward_direction_distinguisher():
    chacha1 = ChachaPermutation(number_of_rounds=6)

    chacha_stream_cipher = construct_backward_chacha(chacha1)
    ciphertext1 = chacha_stream_cipher.evaluate(
        [
            0x25d0b5fcc369d68ec22687607738f623985776ef1197a86417813ac1234a6f27b3491a245076b2f05c129d3983d44a93251b2bc09436b2d313abb7ec4b36f527,
            0x0ac2b2af34fad2c77dad8240368abd7795e86ce6ca98787d252014341ff6a6701f29b858cb54238b1d4801a5a553d2bebc3a3c3fe886d2b4560ea7e6a675044d
        ]
    )
    # print(hex(ciphertext1))

    assert ciphertext1 == 0xd66a44e2c7ecca08a98d50305b0af1c8635f78939f808ca5e45a19758f339f2446f7a84772d6ef6a891cb220523ac24692c0b0f238c63909b2de09c053c2adac

    ciphertext2 = chacha_stream_cipher.evaluate(
        [
            0x00fe7f106b517532a5c863126e289cae9a9343c7e12ecaf5a8f4d981dff42bcfdcdff2aa79483067421f109473b047ac800d448b8f623b0ee33856142cc22c81,
            0x47c59ebc671319c2d9845b1b6d7ed82ec829b81471b0af8ba4c8be567f4a3dc29ec60fdc4405d929631d8a3576d09c62df3ef954ff51eea86fa319ad32eeed56
        ]
    )

    assert ciphertext2 == 0x8d4cd6afb22fd5f4fbedce0fd0abe8b87376ef302a779f46136b9a81c4f6e01d806927fa5f669dd2e794bfa04172e347706e6deb5c08abf1e434b56a0aa60f70
    # import ipdb;
    # ipdb.set_trace()
    # chacha_stream_cipher_copy = deepcopy(chacha_stream_cipher)
    # chacha_stream_cipher_copy.sort_cipher()

    top_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha_stream_cipher.get_components_in_round(round_number))
    for round_number in range(2, 6):
        bottom_part_components.append(chacha_stream_cipher.get_components_in_round(round_number))

    bottom_part_components = list(itertools.chain(*bottom_part_components))
    bottom_part_components = [component.id for component in bottom_part_components]

    bottom_part_components.remove("bottom_intermediate_output_3_24")

    component_model_list = {
        'bottom_part_components': bottom_part_components
    }

    shared_truncated_dl_model = SharedTruncatedDifferencePairedInputDifferentialLinearModel(
        chacha_stream_cipher, component_model_list
    )
    weight = 50
    ciphertext_final = set_fixed_variables(
        component_id='bottom_plaintext',
        constraint_type='not_equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x0,
            512,
            'big'
        )
    )

    bottom_ciphertext_final = set_fixed_variables(
        component_id='bottom_ciphertext_final',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x0,
            512,
            'big'
        )
    )

    plaintext_constants = set_fixed_variables(
        component_id='bottom_fake_plaintext',
        constraint_type='equal',
        bit_positions=range(128),
        bit_values=integer_to_bit_list(
            0x0,
            128,
            'big'
        )
    )

    plaintext_key = set_fixed_variables(
        component_id='bottom_fake_plaintext',
        constraint_type='not_equal',
        bit_positions=range(128),
        bit_values=integer_to_bit_list(
            0x0,
            256,
            'big'
        )
    )

    plaintext_nonce = set_fixed_variables(
        component_id='bottom_fake_plaintext',
        constraint_type='equal',
        bit_positions=range(384, 512),
        bit_values=integer_to_bit_list(
            0x0,
            128,
            'big'
        )
    )

    shared_truncated_dl_model.build_shared_truncated_difference_paired_input_differential_model(
        weight=weight,
        fixed_values=[ciphertext_final, bottom_ciphertext_final],  # , plaintext_constants, plaintext_nonce],
        key_recovery=True
    )

    return shared_truncated_dl_model, shared_truncated_dl_model._variables_list, shared_truncated_dl_model._model_constraints


def forward_direction_model():
    chacha = ChachaPermutation(number_of_rounds=8)
    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 3):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(3, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    state_size = 512

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x0,
            state_size,
            'big'
        )
    )

    ciphertext = set_fixed_variables(
        component_id='cipher_output_7_24',
        constraint_type='not_equal',
        bit_positions=list(range(state_size)),
        bit_values=integer_to_bit_list(
            0x0,
            state_size,
            'big'
        )
    )

    component_model_list = {
        'middle_part_components': middle_part_components,
        'bottom_part_components': bottom_part_components
    }

    sat_heterogeneous_model = SatDifferentialLinearModel(
        chacha, component_model_list, middle_part_model='sat_semi_deterministic_truncated_xor_differential_constraints'
    )
    weight = 40
    num_unknown_vars = 30
    unknown_window_size_configuration = None
    # {
    #     "max_number_of_sequences_window_size_0": 80,
    #     "max_number_of_sequences_window_size_1": 25,
    #     "max_number_of_sequences_window_size_2": 190
    # }
    fixed_values = [plaintext, ciphertext]

    sat_heterogeneous_model.build_xor_differential_linear_model(
        weight, num_unknown_vars, unknown_window_size_configuration
    )
    constraints = sat_heterogeneous_model.fix_variables_value_constraints(
        fixed_values,
        sat_heterogeneous_model.regular_components,
        sat_heterogeneous_model.truncated_components,
        sat_heterogeneous_model.linear_components
    )
    sat_heterogeneous_model.model_constraints.extend(constraints)

    return sat_heterogeneous_model, sat_heterogeneous_model._variables_list, sat_heterogeneous_model._model_constraints


def constraint_for_meet_in_the_middle(forward_distinguisher, backward_distinguisher):
    forward_distinguisher_output = forward_distinguisher.cipher.get_all_components()[-1]
    backward_distinguisher_output = backward_distinguisher.cipher.get_all_components()[-1]
    # import ipdb; ipdb.set_trace()
    constraints = []
    for i in range(forward_distinguisher_output.output_bit_size):
        constraints.extend(cnf_equivalent(
            [f'{forward_distinguisher_output.id}_{i}_i', f'{backward_distinguisher_output.id}_{i}_i']
        ))
    return constraints


def test_differential_linear_trail_with_fixed_weight_8_rounds_chacha_one_case():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation.
    This test is using in the middle part the semi-deterministic model.
    """

    forward_distinguisher, forward_distinguisher_variables, forward_distinguisher_constraints = forward_direction_model()
    backward_distinguisher, backward_distinguisher_variables, backward_distinguisher_constraints = backward_direction_distinguisher()
    # import ipdb; ipdb.set_trace()

    forward_distinguisher._variables_list.extend(backward_distinguisher_variables)
    forward_distinguisher._model_constraints.extend(backward_distinguisher_constraints)

    meet_in_the_middle_constraints = constraint_for_meet_in_the_middle(forward_distinguisher, backward_distinguisher)
    forward_distinguisher._model_constraints.extend(meet_in_the_middle_constraints)

    def custom_parse_solver_output(self, variable2value):

        components_solutions = self._get_cipher_inputs_components_solutions('', variable2value)
        total_weight_diff = 0
        total_weight_lin = 0

        for component in self._cipher.get_all_components():
            if component.id in [d['component_id'] for d in self.regular_components]:
                hex_value = self._get_component_hex_value(component, '', variable2value)
                weight = self.calculate_component_weight(component, '', variable2value)
                components_solutions[component.id] = set_component_solution(hex_value, weight)
                total_weight_diff += weight

            elif component.id in [d['component_id'] for d in self.truncated_components]:
                value = self._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value, weight=0)

            elif component.id in [d['component_id'] for d in self.linear_components]:
                hex_value = self._get_component_hex_value(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                weight = self.calculate_component_weight(component, constants.OUTPUT_BIT_ID_SUFFIX, variable2value)
                total_weight_lin += weight
                components_solutions[component.id] = set_component_solution(hex_value, weight)

        components_solutions = {
            **backward_distinguisher._get_cipher_inputs_components_solutions_double_ids(variable2value),
            **components_solutions
        }

        total_weight_diff = 0
        total_weight_lin = 0

        for component in backward_distinguisher._cipher.get_all_components():
            # import ipdb; ipdb.set_trace()
            if component.id in [d['component_id'] for d in backward_distinguisher.truncated_components]:
                value = backward_distinguisher._get_component_value_double_ids(component, variable2value)
                components_solutions[component.id] = set_component_solution(value, weight=0)

            elif component.id in [d['component_id'] for d in backward_distinguisher.linear_components]:
                hex_value = backward_distinguisher._get_component_hex_value(component, constants.OUTPUT_BIT_ID_SUFFIX,
                                                                            variable2value)
                weight = backward_distinguisher.calculate_component_weight(component, constants.OUTPUT_BIT_ID_SUFFIX,
                                                                           variable2value)
                total_weight_lin += weight
                components_solutions[component.id] = set_component_solution(hex_value, weight)

        import ipdb;
        ipdb.set_trace()
        return components_solutions, total_weight_diff + 2 * total_weight_lin

    # Bind the method to the instance
    forward_distinguisher._parse_solver_output = types.MethodType(custom_parse_solver_output, forward_distinguisher)

    solution = forward_distinguisher.solve(
        "XOR_DIFFERENTIAL_LINEAR_MODEL", solver_name="PARKISSAT_EXT", options=["-c=8"]
    )
    import ipdb;
    ipdb.set_trace()
    # assert trail["status"] == 'SATISFIABLE'
    # input_difference = int(trail['components_values']['plaintext']['value'], 16)
    # output_mask = int(trail['components_values']['cipher_output_7_24']['value'], 16)
    # exp_number_of_samples = 11
    # number_of_rounds = 6
    # state_size = 512
    # chacha = ChachaPermutation(number_of_rounds=number_of_rounds)
    # corr = differential_linear_checker_for_permutation(
    #    chacha, input_difference, output_mask, 1 << exp_number_of_samples, state_size
    # )
    # print(corr)
    # corr = differential_linear_checker_for_permutation(
    #    chacha, input_difference, output_mask, 1 << exp_number_of_samples + 1, state_size
    # )
    # print(corr)
    # assert math.log(abs(corr), 2) < exp_number_of_samples - 1
