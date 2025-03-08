import itertools

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.cipher_modules.models.sat.utils.utils import _generate_component_model_types, \
    _update_component_model_types_for_truncated_components, _update_component_model_types_for_linear_components
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list, \
    differential_linear_checker_for_permutation, differential_linear_checker_for_block_cipher_single_key
from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation


def test_differential_linear_trail_with_fixed_weight_6_rounds_speck():
    """Test for finding a differential-linear trail with fixed weight for 6 rounds of Speck."""
    speck = SpeckBlockCipher(number_of_rounds=6)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(speck.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(speck.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x05020402, 32, 'big')
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    ciphertext_difference = set_fixed_variables(
        component_id='cipher_output_5_12',
        constraint_type='equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x00040004, 32, 'big')
    )

    component_model_types = _generate_component_model_types(speck)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(speck, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=10, fixed_values=[key, plaintext, ciphertext_difference], solver_name="CADICAL_EXT", num_unknown_vars=2
    )
    assert trail["status"] == 'SATISFIABLE'


def test_lowest_differential_linear_trail_with_fixed_weight_6_rounds_speck():
    """Test for finding the lowest differential-linear trail with fixed weight for 6 rounds of Speck."""
    speck = SpeckBlockCipher(number_of_rounds=6)
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2, 3):
        middle_part_components.append(speck.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(speck.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x0, 32, 'big')
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    ciphertext_difference = set_fixed_variables(
        component_id='cipher_output_5_12',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=integer_to_bit_list(0x0, 32, 'big')
    )

    component_model_types = _generate_component_model_types(speck)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(speck, component_model_types)

    trail = sat_heterogeneous_model.find_lowest_weight_xor_differential_linear_trail(
        fixed_values=[key, plaintext, ciphertext_difference], solver_name="CADICAL_EXT", num_unknown_vars=2
    )
    assert trail["status"] == 'SATISFIABLE'


def test_differential_linear_trail_with_fixed_weight_3_rounds_chacha():
    """Test for finding a differential-linear trail with fixed weight for 3 rounds of ChaCha permutation."""
    chacha = ChachaPermutation(number_of_rounds=6)
    import itertools
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(1, 3):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(3, 6):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000, 512, 'big')
    )

    cipher_output_5_24 = set_fixed_variables(
        component_id='cipher_output_5_24',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101, 512, 'big')
    )

    modadd_3_15 = set_fixed_variables(
        component_id=f'modadd_3_15',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    component_model_types = _generate_component_model_types(chacha)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(chacha, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=5, fixed_values=[plaintext, modadd_3_15, cipher_output_5_24], solver_name="CADICAL_EXT", num_unknown_vars=511
    )
    assert trail["status"] == 'SATISFIABLE'
    assert trail["total_weight"] <= 5


def test_differential_linear_trail_with_fixed_weight_4_rounds_aradi():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of Aradi block cipher."""
    aradi = AradiBlockCipherSBox(number_of_rounds=4)
    import itertools
    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(1):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(1, 3):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(3, 4):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(128),
        bit_values=integer_to_bit_list(0x00000000000080000000000000008000, 128, 'big')
    )

    cipher_output_3_86 = set_fixed_variables(
        component_id='cipher_output_3_86',
        constraint_type='equal',
        bit_positions=range(128),
        bit_values=integer_to_bit_list(0x90900120800000011010002000000000, 128, 'big')
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(256),
        bit_values=[0] * 256
    )

    sbox_4_8 = set_fixed_variables(
        component_id=f'sbox_3_8',
        constraint_type='not_equal',
        bit_positions=range(4),
        bit_values=[0] * 4
    )

    component_model_types = _generate_component_model_types(aradi)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=10, fixed_values=[key, plaintext, sbox_4_8, cipher_output_3_86], solver_name="CADICAL_EXT", num_unknown_vars=128-1
    )
    assert trail["status"] == 'SATISFIABLE'
    assert trail["total_weight"] <= 10


def test_differential_linear_trail_with_fixed_weight_4_rounds_chacha():
    """Test for finding a differential-linear trail with fixed weight for 4 rounds of ChaCha permutation."""
    chacha = ChachaPermutation(number_of_rounds=8)

    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(2):
        top_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(2, 4):
        middle_part_components.append(chacha.get_components_in_round(round_number))
    for round_number in range(4, 8):
        bottom_part_components.append(chacha.get_components_in_round(round_number))

    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='equal',
        bit_positions=range(512),
        bit_values=integer_to_bit_list(
            0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000088088780,
            512,
            'big'
        )
    )

    modadd_4_15 = set_fixed_variables(
        component_id=f'modadd_4_15',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    component_model_types = _generate_component_model_types(chacha)
    _update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    _update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(chacha, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=32, fixed_values=[plaintext, modadd_4_15], solver_name="CADICAL_EXT", num_unknown_vars=511
    )
    assert trail["status"] == 'SATISFIABLE'
    assert trail["total_weight"] <= 32


def test_diff_lin_chacha():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_3_rounds_chacha
    """
    input_difference = 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000
    output_mask = 0x00010000000100010000000100030003000000800000008000000000000001800000000000000001000000010000000201000101010000000000010103000101
    number_of_samples = 2 ** 12
    number_of_rounds = 6
    state_size = 512
    chacha = ChachaPermutation(number_of_rounds=number_of_rounds)
    corr = differential_linear_checker_for_permutation(
        chacha, input_difference, output_mask, number_of_samples, state_size
    )
    import math
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) < 3


def test_diff_lin_speck():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_6_rounds_speck
    """
    input_difference = 0x02110a04
    output_mask = 0x02000201
    number_of_samples = 2 ** 15
    number_of_rounds = 6
    fixed_key = 0x0
    speck = SpeckBlockCipher(number_of_rounds=number_of_rounds)
    block_size = speck.inputs_bit_size[0]
    key_size = speck.inputs_bit_size[1]
    corr = differential_linear_checker_for_block_cipher_single_key(
        speck, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key
    )
    import math
    abs_corr = abs(corr)
    assert abs(math.log(abs_corr, 2)) <= 8


def test_diff_lin_aradi():
    """
    This test is verifying experimentally the test test_differential_linear_trail_with_fixed_weight_4_rounds_aradi
    """
    input_difference = 0x00000000000080000000000000008000
    output_mask = 0x90900120800000011010002000000000
    number_of_samples = 2 ** 12
    number_of_rounds = 4
    fixed_key = 0x90900120800000011010002000000000
    speck = AradiBlockCipherSBox(number_of_rounds=number_of_rounds)
    block_size = speck.inputs_bit_size[0]
    key_size = speck.inputs_bit_size[1]
    corr = differential_linear_checker_for_block_cipher_single_key(
        speck, input_difference, output_mask, number_of_samples, block_size, key_size, fixed_key
    )
    import math
    abs_corr = abs(corr)
    print(corr, abs_corr, abs(math.log(abs_corr, 2)))
    assert abs(math.log(abs_corr, 2)) < 8
