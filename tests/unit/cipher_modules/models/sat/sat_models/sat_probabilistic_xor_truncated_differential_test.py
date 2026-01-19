import itertools
import pytest

from claasp.cipher_modules.models.sat import solvers
from claasp.cipher_modules.models.sat.sat_models.sat_probabilistic_xor_truncated_differential_model import (
    SatProbabilisticXorTruncatedDifferentialModel,
)
from claasp.cipher_modules.models.sat.utils.utils import (
    _generate_component_model_types,
    _update_component_model_types_for_truncated_components,
)
from claasp.cipher_modules.models.utils import (
    set_fixed_variables,
    integer_to_bit_list,
    differential_truncated_checker_single_key,
    differential_truncated_checker_permutation,
)
from claasp.ciphers.block_ciphers.aradi_block_cipher_sbox import AradiBlockCipherSBox
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY, SATISFIABLE


def test_differential_truncated_in_single_key_scenario_speck3264():
    """
    This test is checking the resulting probability after combining two differentials, one regular and one truncated.
    The regular one occurs with probability 2^-12 and the truncated one occurs with probability 1. The regular differential
    start with a fixed input difference of 0xfe2ecdf8 and the output difference is 007ce000. The truncated differential
    starts with a fixed input difference of 007ce000 and the output difference is ????100000000000????100000000011. The
    expected probability for the resulting differential is approximately 2^-12.
    """
    speck = SpeckBlockCipher(number_of_rounds=3)
    num_samples = 2**14
    input_diff = 0xFE2ECDF8
    output_diff = "????100000000000????100000000011"
    key_size = speck.inputs_bit_size[1]
    total_prob_weight = differential_truncated_checker_single_key(
        speck, input_diff, output_diff, num_samples, speck.output_bit_size, 0x0, key_size, seed=42
    )
    assert 14 > abs(total_prob_weight) > 10


def test_differential_in_single_key_scenario_aradi():
    """
    This test is checking the distinguisher tested in test_differential_linear_trail_with_fixed_weight_4_rounds_aradi
    which occurs with probability 2^-8.
    """
    aradi = AradiBlockCipherSBox(number_of_rounds=4)
    num_samples = 2**12
    input_diff = 0x00080021000800210000000000000000
    output_diff = (
        "?0???0??0??0?0??????00??????0?0??0???0??0??0?0??????00??????0?0?"
        "?0???0??0??0?0??????00??????0?0??0???0??0??0?0??????00??????0?0?"
    )

    key_size = aradi.inputs_bit_size[1]
    aradi = differential_truncated_checker_single_key(
        aradi, input_diff, output_diff, num_samples, aradi.output_bit_size, 0x0, key_size, seed=42
    )

    assert 9 > abs(aradi) > 2


def test_find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight_4_rounds():
    """
    Test for finding a XOR probabilistic truncated differential trail with fixed weight for 4 rounds of Speck cipher.
    """
    speck = SpeckBlockCipher(number_of_rounds=4)

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    component_model_types = _generate_component_model_types(speck)
    truncated_components = [
        "constant_2_0",
        "rot_2_1",
        "modadd_2_2",
        "xor_2_3",
        "rot_2_4",
        "xor_2_5",
        "rot_2_6",
        "modadd_2_7",
        "xor_2_8",
        "rot_2_9",
        "xor_2_10",
        "intermediate_output_2_11",
        "intermediate_output_2_12",
        "constant_3_0",
        "rot_3_1",
        "modadd_3_2",
        "xor_3_3",
        "rot_3_4",
        "xor_3_5",
        "rot_3_6",
        "modadd_3_7",
        "xor_3_8",
        "rot_3_9",
        "xor_3_10",
        "intermediate_output_3_11",
        "intermediate_output_3_12",
        "cipher_output_3_12",
    ]
    _update_component_model_types_for_truncated_components(component_model_types, truncated_components)

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(speck, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
        weight=8,
        fixed_values=[intermediate_output_1_12, key, plaintext],
        number_of_unknowns_per_component={"cipher_output_3_12": 31},
    )
    assert trail["components_values"]["cipher_output_3_12"]["value"] == "????????00000000????????000000?1"


def test_find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight_5_rounds():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 5 rounds of Speck cipher."""
    speck = SpeckBlockCipher(number_of_rounds=5)

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    component_model_types = _generate_component_model_types(speck)
    truncated_components = [
        "constant_2_0",
        "rot_2_1",
        "modadd_2_2",
        "xor_2_3",
        "rot_2_4",
        "xor_2_5",
        "rot_2_6",
        "modadd_2_7",
        "xor_2_8",
        "rot_2_9",
        "xor_2_10",
        "intermediate_output_2_11",
        "intermediate_output_2_12",
        "constant_3_0",
        "rot_3_1",
        "modadd_3_2",
        "xor_3_3",
        "rot_3_4",
        "xor_3_5",
        "rot_3_6",
        "modadd_3_7",
        "xor_3_8",
        "rot_3_9",
        "xor_3_10",
        "intermediate_output_3_11",
        "intermediate_output_3_12",
        "constant_4_0",
        "rot_4_1",
        "modadd_4_2",
        "xor_4_3",
        "rot_4_4",
        "xor_4_5",
        "rot_4_6",
        "modadd_4_7",
        "xor_4_8",
        "rot_4_9",
        "xor_4_10",
        "intermediate_output_4_11",
        "intermediate_output_4_12",
        "cipher_output_4_12",
    ]
    _update_component_model_types_for_truncated_components(component_model_types, truncated_components)

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(speck, component_model_types)

    trail = sat_heterogeneous_model.find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
        weight=8,
        fixed_values=[intermediate_output_1_12, key, plaintext],
        number_of_unknowns_per_component={"cipher_output_4_12": 31},
    )

    assert trail["components_values"]["cipher_output_4_12"]["value"] == "???????????????0????????????????"


def test_find_lowest_xor_probabilistic_truncated_differential_trail_with_fixed_weight_5_rounds():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 5 rounds of Speck cipher."""
    speck = SpeckBlockCipher(number_of_rounds=5)

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    component_model_types = _generate_component_model_types(speck)
    truncated_components = [
        "constant_2_0",
        "rot_2_1",
        "modadd_2_2",
        "xor_2_3",
        "rot_2_4",
        "xor_2_5",
        "rot_2_6",
        "modadd_2_7",
        "xor_2_8",
        "rot_2_9",
        "xor_2_10",
        "intermediate_output_2_11",
        "intermediate_output_2_12",
        "constant_3_0",
        "rot_3_1",
        "modadd_3_2",
        "xor_3_3",
        "rot_3_4",
        "xor_3_5",
        "rot_3_6",
        "modadd_3_7",
        "xor_3_8",
        "rot_3_9",
        "xor_3_10",
        "intermediate_output_3_11",
        "intermediate_output_3_12",
        "constant_4_0",
        "rot_4_1",
        "modadd_4_2",
        "xor_4_3",
        "rot_4_4",
        "xor_4_5",
        "rot_4_6",
        "modadd_4_7",
        "xor_4_8",
        "rot_4_9",
        "xor_4_10",
        "intermediate_output_4_11",
        "intermediate_output_4_12",
        "cipher_output_4_12",
    ]
    _update_component_model_types_for_truncated_components(component_model_types, truncated_components)

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(speck, component_model_types)
    trail = sat_heterogeneous_model.find_lowest_weight_xor_probabilistic_truncated_differential_trail(
        fixed_values=[intermediate_output_1_12, key, plaintext], solver_name=solvers.CRYPTOMINISAT_EXT
    )

    assert trail["components_values"]["cipher_output_4_12"]["value"] == "???????????????0????????????????"


def test_wrong_fixed_variables_assignment():
    speck = SpeckBlockCipher(number_of_rounds=5)

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(64), bit_values=(0,) * 64
    )

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT, constraint_type="not_equal", bit_positions=range(32), bit_values=(0,) * 32
    )

    intermediate_output_1_12 = set_fixed_variables(
        component_id="intermediate_output_1_12",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )

    modadd_1_2 = set_fixed_variables(
        component_id="modadd_1_2",
        constraint_type="equal",
        bit_positions=range(32),
        bit_values=(0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    )
    component_model_types = _generate_component_model_types(speck)
    sat_bitwise_deterministic_truncated_components = [
        "constant_2_0",
        "rot_2_1",
        "modadd_2_2",
        "xor_2_3",
        "rot_2_4",
        "xor_2_5",
        "rot_2_6",
        "modadd_2_7",
        "xor_2_8",
        "rot_2_9",
        "xor_2_10",
        "intermediate_output_2_11",
        "intermediate_output_2_12",
        "constant_3_0",
        "rot_3_1",
        "modadd_3_2",
        "xor_3_3",
        "rot_3_4",
        "xor_3_5",
        "rot_3_6",
        "modadd_3_7",
        "xor_3_8",
        "rot_3_9",
        "xor_3_10",
        "intermediate_output_3_11",
        "intermediate_output_3_12",
        "constant_4_0",
        "rot_4_1",
        "modadd_4_2",
        "xor_4_3",
        "rot_4_4",
        "xor_4_5",
        "rot_4_6",
        "modadd_4_7",
        "xor_4_8",
        "rot_4_9",
        "xor_4_10",
        "intermediate_output_4_11",
        "intermediate_output_4_12",
        "cipher_output_4_12",
    ]
    _update_component_model_types_for_truncated_components(
        component_model_types, sat_bitwise_deterministic_truncated_components
    )

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(speck, component_model_types)

    with pytest.raises(ValueError) as exc_info:
        sat_heterogeneous_model.find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
            8,
            fixed_values=[intermediate_output_1_12, key, plaintext, modadd_1_2],
            number_of_unknowns_per_component={"cipher_output_4_12": 31},
            solver_name="CRYPTOMINISAT_EXT",
        )
        assert str(exc_info.value) == "The fixed value in a regular XOR differential model cannot be 2"


def test_differential_linear_trail_with_fixed_weight_4_rounds_aradi():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 4 rounds of Aradi cipher."""
    aradi = AradiBlockCipherSBox(number_of_rounds=4)
    bottom_part_components = []
    for round_number in range(2, 4):
        bottom_part_components.append(aradi.get_components_in_round(round_number))
    bottom_part_components = list(itertools.chain(*bottom_part_components))
    bottom_part_components = [component.id for component in bottom_part_components]

    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=range(128),
        bit_values=integer_to_bit_list(0x00080021000800210000000000000000, 128, "big"),
    )

    key = set_fixed_variables(
        component_id=INPUT_KEY, constraint_type="equal", bit_positions=range(256), bit_values=(0,) * 256
    )

    component_model_types = _generate_component_model_types(aradi)
    _update_component_model_types_for_truncated_components(component_model_types, bottom_part_components)

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(aradi, component_model_types)
    trail = sat_heterogeneous_model.find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
        weight=8,
        fixed_values=[key, plaintext],
        solver_name=solvers.CADICAL_EXT,
        number_of_unknowns_per_component={"cipher_output_3_86": 127},
    )

    assert trail["components_values"]["cipher_output_3_86"]["value"] == (
        "?0???0??0??0?0??????00??????0?0??0???0??0??0?0??????00??????0?0?"
        "?0???0??0??0?0??????00??????0?0??0???0??0??0?0??????00??????0?0?"
    )


def test_differential_linear_trail_with_fixed_weight_3_rounds_chacha():
    """Test for finding a XOR regular truncated differential trail with fixed weight for 4 rounds of ChaCha cipher."""
    chacha = ChachaPermutation(number_of_rounds=3, round_mode=ROUND_MODE_HALF)
    bottom_part_components = []
    for round_number in range(2, 3):
        bottom_part_components.append(chacha.get_components_in_round(round_number))
    bottom_part_components = list(itertools.chain(*bottom_part_components))
    bottom_part_components = [component.id for component in bottom_part_components]
    initial_state_positions = integer_to_bit_list(
        0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008008000000000000000000000000,
        512,
        "big",
    )
    plaintext = set_fixed_variables(
        component_id=INPUT_PLAINTEXT,
        constraint_type="equal",
        bit_positions=list(range(512)),
        bit_values=initial_state_positions,
    )
    intermediate_output_0_24_state = integer_to_bit_list(
        0x00000000000000000000000000000000800008000000000000000000000000008008000000000000000000000000000080080000000000000000000000000000,
        512,
        "big",
    )
    intermediate_output_1_24_state = integer_to_bit_list(
        0x80000800000000000000000000000000000400040000000000000000000000008800000000000000000000000000000008080000000000000000000000000000,
        512,
        "big",
    )
    intermediate_output_0_24 = set_fixed_variables(
        component_id="intermediate_output_0_24",
        constraint_type="equal",
        bit_positions=list(range(512)),
        bit_values=intermediate_output_0_24_state,
    )

    intermediate_output_1_24 = set_fixed_variables(
        component_id="intermediate_output_1_24",
        constraint_type="equal",
        bit_positions=list(range(512)),
        bit_values=intermediate_output_1_24_state,
    )
    # fmt: off
    cipher_output_2_24_state = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0,
        2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0,
        0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    # fmt: on

    cipher_output_2_24 = set_fixed_variables(
        component_id="cipher_output_2_24",
        constraint_type="equal",
        bit_positions=list(range(512)),
        bit_values=cipher_output_2_24_state,
    )

    component_model_types = _generate_component_model_types(chacha)
    _update_component_model_types_for_truncated_components(
        component_model_types,
        bottom_part_components,
        truncated_model_type="sat_semi_deterministic_truncated_xor_differential_constraints",
    )

    sat_heterogeneous_model = SatProbabilisticXorTruncatedDifferentialModel(chacha, component_model_types)

    unknown_window_size_configuration = {
        "max_number_of_sequences_window_size_0": 9,
        "max_number_of_sequences_window_size_1": 9,
        "max_number_of_sequences_window_size_2": 20,
    }

    max_number_of_unknowns_per_component = {"cipher_output_2_24": 12}

    trail = sat_heterogeneous_model.find_one_xor_probabilistic_truncated_differential_trail_with_fixed_weight(
        weight=14,
        number_of_unknowns_per_component=max_number_of_unknowns_per_component,
        fixed_values=[plaintext, intermediate_output_0_24, intermediate_output_1_24, cipher_output_2_24],
        solver_name=solvers.CADICAL_EXT,
        unknown_window_size_configuration=unknown_window_size_configuration,
    )
    assert trail["status"] == SATISFIABLE

    input_difference = int(trail["components_values"][INPUT_PLAINTEXT]["value"], 16)
    output_difference = trail["components_values"]["cipher_output_2_24"]["value"]
    prob = differential_truncated_checker_permutation(
        chacha, input_difference, output_difference, 1 << 14, 512, seed=42
    )

    assert 0 < abs(prob) < 15
