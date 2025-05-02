import itertools
from copy import deepcopy

from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_linear_model import \
    SharedDifferencePairedInputDifferentialLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, \
    shared_difference_paired_input_differential_linear_checker_permutation
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.components.intermediate_output_component import IntermediateOutput
from claasp.components.modsub_component import MODSUB


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
    chacha_inverse = chacha_key_recovery.cipher_inverse()
    add_ciphertext_and_new_plaintext_to_inputs(chacha_inverse)
    add_prefix_id_to_inputs(chacha_inverse, "bottom")
    add_prefix_id_to_components(chacha_inverse, "bottom")
    chacha_inverse.sort_cipher()
    return chacha_inverse


def test_backward_direction_distinguisher():
    chacha1 = ChachaPermutation(number_of_rounds=4)
    chacha_stream_cipher = construct_backward_chacha(chacha1)
    chacha_stream_cipher_copy = deepcopy(chacha_stream_cipher)
    chacha_stream_cipher_copy.sort_cipher()

    top_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(chacha_stream_cipher.get_components_in_round(round_number))
    for round_number in range(1, 4):
        bottom_part_components.append(chacha_stream_cipher.get_components_in_round(round_number))

    bottom_part_components = list(itertools.chain(*bottom_part_components))
    bottom_part_components = [component.id for component in bottom_part_components]

    ciphertext_final = set_fixed_variables(
        component_id='bottom_ciphertext_final',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x0,
            512,
            'big'
        )
    )

    plaintext = set_fixed_variables(
        component_id='bottom_fake_plaintext',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000080000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
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

    bottom_cipher_output_1_24 = set_fixed_variables(
        component_id='bottom_cipher_output_3_24',
        constraint_type='not_equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x0,
            512,
            'big'
        )
    )

    bottom_plaintext = set_fixed_variables(
        component_id='bottom_plaintext',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000010000000000000000000000000000000100000000000000000000000000000001000000000000000000000000000000000000000000000000,
            512,
            'big'
        )
    )

    component_model_list = {
        'bottom_part_components': bottom_part_components
    }

    sat_heterogeneous_model = SharedDifferencePairedInputDifferentialLinearModel(chacha_stream_cipher,
                                                                                 component_model_list)
    trail = sat_heterogeneous_model.find_one_shared_difference_paired_input_differential_linear_trail_with_fixed_weight(
        weight=40,
        fixed_values=[
            plaintext,
            ciphertext_final,
            bottom_cipher_output_1_24,
            bottom_plaintext,
            plaintext_constants,
            plaintext_nonce
        ],
        solver_name="KISSAT_EXT"
    )

    assert trail["status"] == "SATISFIABLE"

    input_difference = int(trail['components_values']['bottom_fake_plaintext']['value'], 16)
    output_difference1 = int(trail['components_values']['bottom_plaintext']['value'], 16)

    prob = shared_difference_paired_input_differential_linear_checker_permutation(
        chacha_stream_cipher_copy,
        input_difference,
        output_difference1,
        1 << 14,
        512,
        1
    )

    assert prob < 14
