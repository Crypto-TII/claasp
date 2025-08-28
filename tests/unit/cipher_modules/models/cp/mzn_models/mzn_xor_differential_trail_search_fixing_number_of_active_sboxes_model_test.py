from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
    MznXorDifferentialFixingNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.cp.solvers import CHUFFED
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, XOR_DIFFERENTIAL


def test_find_all_xor_differential_trails_with_fixed_weight():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables(INPUT_KEY, "equal", range(128), (0,) * 128),
        set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(128), (0,) * 128),
    ]
    trails = mzn.find_all_xor_differential_trails_with_fixed_weight(30, fixed_variables, CHUFFED, CHUFFED)

    assert len(trails) == 255


def test_find_lowest_weight_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables(INPUT_KEY, "equal", range(128), (0,) * 128),
        set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(128), (0,) * 128),
    ]
    solution = mzn.find_lowest_weight_xor_differential_trail(fixed_variables, CHUFFED, CHUFFED)

    assert str(solution["cipher"]) == "aes_block_cipher_k128_p128_o128_r2"
    assert solution["model_type"] == XOR_DIFFERENTIAL
    assert solution["solver_name"] == CHUFFED
    assert solution["total_weight"] == "30.0"
    assert solution["components_values"][INPUT_KEY] == {"value": "0x00000000000000000000000000000000", "weight": 0}
    assert eval(solution["components_values"][INPUT_PLAINTEXT]["value"]) > 0
    assert solution["components_values"][INPUT_PLAINTEXT]["weight"] == 0
    assert eval(solution["components_values"]["cipher_output_1_32"]["value"]) >= 0
    assert solution["components_values"]["cipher_output_1_32"]["weight"] == 0


def test_find_one_xor_differential_trail():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables(INPUT_KEY, "equal", range(128), (0,) * 128),
        set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(128), (0,) * 128),
    ]
    solution = mzn.find_one_xor_differential_trail(fixed_variables, CHUFFED, CHUFFED)

    assert str(solution["cipher"]) == "aes_block_cipher_k128_p128_o128_r2"
    assert solution["model_type"] == XOR_DIFFERENTIAL
    assert solution["solver_name"] == CHUFFED
    assert eval(solution["total_weight"]) >= 0.0
    assert solution["components_values"][INPUT_KEY] == {"value": "0x00000000000000000000000000000000", "weight": 0}
    assert solution["components_values"][INPUT_PLAINTEXT]["weight"] == 0

    solution = mzn.find_one_xor_differential_trail(fixed_variables, CHUFFED, CHUFFED)

    assert str(solution["cipher"]) == "aes_block_cipher_k128_p128_o128_r2"
    assert solution["model_type"] == XOR_DIFFERENTIAL
    assert solution["solver_name"] == CHUFFED
    assert eval(solution["total_weight"]) >= 0.0
    assert solution["components_values"][INPUT_KEY] == {"value": "0x00000000000000000000000000000000", "weight": 0}
    assert solution["components_values"][INPUT_PLAINTEXT]["weight"] == 0


def test_find_one_xor_differential_trail_with_fixed_weight():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables(INPUT_KEY, "equal", range(128), (0,) * 128),
        set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(128), (0,) * 128),
    ]
    solution = mzn.find_one_xor_differential_trail_with_fixed_weight(224, fixed_variables, CHUFFED, CHUFFED)

    assert str(solution["cipher"]) == "aes_block_cipher_k128_p128_o128_r2"
    assert solution["model_type"] == XOR_DIFFERENTIAL
    assert solution["solver_name"] == CHUFFED
    assert eval(solution["total_weight"]) == 224.0
    assert solution["components_values"][INPUT_KEY] == {"value": "0x00000000000000000000000000000000", "weight": 0}
    assert eval(solution["components_values"][INPUT_PLAINTEXT]["value"]) > 0
    assert solution["components_values"][INPUT_PLAINTEXT]["weight"] == 0
    assert solution["components_values"]["cipher_output_1_32"]["weight"] == 0


def test_solve_full_two_steps_xor_differential_model():
    aes = AESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [set_fixed_variables(INPUT_KEY, "not_equal", range(128), (0,) * 128)]
    constraints = mzn.solve_full_two_steps_xor_differential_model(
        "xor_differential_one_solution", -1, fixed_variables, CHUFFED, CHUFFED
    )

    assert str(constraints["cipher"]) == "aes_block_cipher_k128_p128_o128_r2"
    assert eval(constraints["components_values"]["intermediate_output_0_35"]["value"]) >= 0
    assert constraints["components_values"]["intermediate_output_0_35"]["weight"] == 0
    assert eval(constraints["components_values"]["xor_0_36"]["value"]) >= 0
    assert constraints["components_values"]["xor_0_36"]["weight"] == 0
    assert eval(constraints["components_values"]["intermediate_output_0_37"]["value"]) >= 0
    assert constraints["components_values"]["intermediate_output_0_37"]["weight"] == 0
    assert eval(constraints["total_weight"]) >= 0
