from __future__ import annotations

import itertools
import os
import pickle

from claasp.cipher_modules.models.sat.sat_models.sat_shared_truncated_difference_paired_input_differential_linear_model import \
    SharedTruncatedDifferencePairedInputDifferentialLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, \
    shared_truncated_difference_paired_input_differential_linear_checker_permutation
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


def test_backward_direction_distinguisher():
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

    sat_heterogeneous_model = SharedTruncatedDifferencePairedInputDifferentialLinearModel(
        chacha_stream_cipher, component_model_list
    )
    weight = 32
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

    # trail = sat_heterogeneous_model.find_one_shared_truncated_difference_paired_input_differential_linear_trail_with_fixed_weight(
    #   weight,
    #   fixed_values=[ciphertext_final, bottom_ciphertext_final, plaintext_nonce, plaintext_constants],
    #   solver_name="KISSAT_EXT"
    # )
    # assert trail['status'] == 'SATISFIABLE'
    # print(trail)
    # import ipdb; ipdb.set_trace()
    input_difference = "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000?0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # trail['components_values']['bottom_fake_plaintext']['value'] #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    output_mask_string = "00000000000000000000000000000001000800800000000000000000000000000000000000001000000000000000000000000000000000000000000100000000"  # trail['components_values']['bottom_plaintext']['value'] #"00000000000000000000000000010000000000000000000000000000000180000000000000000000000000000000000100000000000000000000000000010000"  # trail['components_values']['bottom_plaintext']['value']
    output_mask = int(output_mask_string, 16)
    exp_number_of_samples = 12
    corr1 = shared_truncated_difference_paired_input_differential_linear_checker_permutation(
        chacha_stream_cipher,
        input_difference,
        output_mask,
        1 << exp_number_of_samples,
        512,
        seed=None
    )
    # corr2 = shared_truncated_difference_paired_input_differential_linear_checker_permutation(
    #    chacha_stream_cipher,
    #    input_difference,
    #    output_mask,
    #    1 << exp_number_of_samples + 1,
    #    512,
    #    21
    # )
    print("Output mask C format")
    print(split_512bit_hex_to_32bit_words(output_mask_string))
    print("PNBs C format")
    print(binary_string_to_32bit_hex_chunks(input_difference))
    # assert math.log(abs(corr1), 2) < exp_number_of_samples - 2
    # assert math.log(abs(corr2), 2) < exp_number_of_samples + 1 - 2
    print(corr1)  # , corr2)
