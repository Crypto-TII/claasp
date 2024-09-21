import numpy as np

from claasp.cipher_modules.models.sat.sat_models.sat_differential_linear_model import SatDifferentialLinearModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.utils.utils import get_k_th_bit


def generate_component_model_types(speck_cipher):
    """Generates the component model types for a given Speck cipher."""
    component_model_types = []
    for component in speck_cipher.get_all_components():
        component_model_types.append({
            "component_id": component.id,
            "component_object": component,
            "model_type": "sat_xor_differential_propagation_constraints"
        })
    return component_model_types


def update_component_model_types_for_truncated_components(component_model_types, truncated_components):
    """Updates the component model types for truncated components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in truncated_components:
            component_model_type["model_type"] = "sat_bitwise_deterministic_truncated_xor_differential_constraints"


def update_component_model_types_for_linear_components(component_model_types, linear_components):
    """Updates the component model types for linear components."""
    for component_model_type in component_model_types:
        if component_model_type["component_id"] in linear_components:
            component_model_type["model_type"] = "sat_xor_linear_mask_propagation_constraints"


def extract_bits(columns, positions):
    """Extracts the bits from columns at the specified positions."""
    num_positions = len(positions)
    num_columns = columns.shape[1]
    bit_size = columns.shape[0] * 8

    result = np.zeros((num_positions, num_columns), dtype=np.uint8)

    for i in range(num_positions):
        for j in range(num_columns):
            byte_index = (bit_size - positions[i] - 1) // 8
            bit_index = positions[i] % 8
            result[i, j] = get_k_th_bit(columns[:, j][byte_index], bit_index)
    return result


def extract_bit_positions(binary_str):
    """Extracts bit positions from a binary+unknows string."""
    binary_str = binary_str[::-1]
    positions = [i for i, bit in enumerate(binary_str) if bit in ['1', '0']]
    return positions


def repeat_input_difference(input_difference, num_samples, num_bytes):
    """Repeats the input difference to generate a large sample for testing."""
    bytes_array = input_difference.to_bytes(num_bytes, 'big')
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)
    return np.tile(column_array, (1, num_samples))


def test_differential_linear_trail_with_fixed_weight_3_rounds_speck():
    """Test for finding a differential-linear trail with fixed weight for 8 rounds of Speck."""
    aradi = SpeckBlockCipher(number_of_rounds=8)
    import itertools

    top_part_components = []
    middle_part_components = []
    bottom_part_components = []
    for round_number in range(3):
        top_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(3, 5):
        middle_part_components.append(aradi.get_components_in_round(round_number))
    for round_number in range(5, 8):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    top_part_components = list(itertools.chain(*top_part_components))
    middle_part_components = list(itertools.chain(*middle_part_components))
    bottom_part_components = list(itertools.chain(*bottom_part_components))

    middle_part_components = [component.id for component in middle_part_components]
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id='plaintext',
        constraint_type='not_equal',
        bit_positions=range(32),
        bit_values=[0] * 32
    )

    key = set_fixed_variables(
        component_id='key',
        constraint_type='equal',
        bit_positions=range(64),
        bit_values=(0,) * 64
    )

    modadd_2_7 = set_fixed_variables(
        component_id='modadd_7_7',
        constraint_type='not_equal',
        bit_positions=range(4),
        bit_values=[0] * 4
    )

    component_model_types = generate_component_model_types(aradi)
    update_component_model_types_for_truncated_components(component_model_types, middle_part_components)
    update_component_model_types_for_linear_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatDifferentialLinearModel(aradi, component_model_types)

    trail = sat_heterogeneous_model.find_one_differential_linear_trail_with_fixed_weight(
        weight=14, fixed_values=[key, plaintext, modadd_2_7], solver_name="CADICAL_EXT", num_unknown_vars=31
    )
    assert trail["status"] == 'SATISFIABLE'
