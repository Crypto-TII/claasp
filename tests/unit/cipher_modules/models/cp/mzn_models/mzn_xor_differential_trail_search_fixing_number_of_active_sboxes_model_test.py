from types import SimpleNamespace

import pytest

from claasp.cipher_modules.models.cp.mzn_models import (
    mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model as trail_search_model,
)
from claasp.cipher_modules.models.cp.mzn_models.mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model import (
    MznXorDifferentialFixingNumberOfActiveSboxesModel,
)
from claasp.cipher_modules.models.cp.solvers import CHUFFED
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.lblock_block_cipher import LBlockBlockCipher
from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, UNSATISFIABLE, XOR_DIFFERENTIAL


def test_find_all_xor_differential_trails_with_fixed_weight():
    aes = ToyAESBlockCipher(number_of_rounds=2)
    mzn = MznXorDifferentialFixingNumberOfActiveSboxesModel(aes)
    fixed_variables = [
        set_fixed_variables(INPUT_KEY, "equal", range(128), (0,) * 128),
        set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(128), (0,) * 128),
    ]
    trails = mzn.find_all_xor_differential_trails_with_fixed_weight(30, fixed_variables, CHUFFED, CHUFFED)

    assert len(trails) == 255


def test_find_lowest_weight_xor_differential_trail():
    aes = ToyAESBlockCipher(number_of_rounds=2)
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
    aes = ToyAESBlockCipher(number_of_rounds=2)
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
    aes = ToyAESBlockCipher(number_of_rounds=2)
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
    aes = ToyAESBlockCipher(number_of_rounds=2)
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


def _stub_two_step_model(model, monkeypatch, solver_outputs):
    calls = {"transform_attempts": [], "solve_model_types": [], "models": []}

    model.initialise_model = lambda: None
    model.build_xor_differential_trail_first_step_model = lambda *args: None
    model.build_xor_differential_trail_second_step_model = lambda *args: None
    model.find_possible_number_of_active_sboxes = lambda weight: [weight]
    model.transform_first_step_model = lambda attempt, first_step: calls["transform_attempts"].append(
        (attempt, first_step)
    )
    model.generate_table_of_solutions = lambda solutions: f"table_for_{solutions};"
    model.current_model_parts = lambda: SimpleNamespace(prefix=[])

    def solve_model(model_type, *args):
        calls["solve_model_types"].append(model_type)
        if model_type == "xor_differential_first_step":
            return ["first_step_pattern"], 0.25
        return ["expanded_pattern"], 0.5

    def assemble_model(parts):
        assembled = "\n".join(parts.prefix)
        calls["models"].append(assembled)
        return assembled

    def parse_solver_output(solver_output, model_type, *args):
        assert solver_output == ["SAT"]
        assert model_type == "xor_differential_one_solution"
        return 1.0, 2.0, {"component": {"value": "0x0", "weight": 0}}, "3.0"

    def get_solutions(build_time, components_values, memory, solver_name, time, total_weight):
        return {
            "building_time": build_time,
            "components_values": components_values,
            "memory": memory,
            "solver_name": solver_name,
            "solving_time": time,
            "total_weight": total_weight,
        }

    responses = list(solver_outputs)

    def fake_run(command, input=None, capture_output=None, text=None):
        calls["command"] = command
        calls["solver_inputs"] = calls.get("solver_inputs", []) + [input]
        return SimpleNamespace(returncode=0, stdout=responses.pop(0))

    model.solve_model = solve_model
    model.assemble_model = assemble_model
    model._parse_solver_output = parse_solver_output
    model.get_solutions_dictionaries_with_build_time = get_solutions
    monkeypatch.setattr(trail_search_model.subprocess, "run", fake_run)

    return calls


def test_solve_full_two_steps_retries_unsat_active_sbox_count(monkeypatch):
    model = MznXorDifferentialFixingNumberOfActiveSboxesModel(ToyAESBlockCipher(number_of_rounds=1))
    calls = _stub_two_step_model(model, monkeypatch, ["=====UNSATISFIABLE=====\n", "SAT\n"])

    solution = model.solve_full_two_steps_xor_differential_model(
        "xor_differential_one_solution",
        -1,
        [],
        CHUFFED,
        CHUFFED,
    )

    assert calls["transform_attempts"] == [(0, "first_step_pattern"), (1, "first_step_pattern")]
    assert calls["solve_model_types"] == [
        "xor_differential_first_step",
        "xor_differential_first_step_find_all_solutions",
        "xor_differential_first_step_find_all_solutions",
    ]
    assert calls["models"] == ["table_for_['expanded_pattern'];", "table_for_['expanded_pattern'];"]
    assert solution["components_values"] == {"component": {"value": "0x0", "weight": 0}}
    assert solution["total_weight"] == "3.0"


def test_solve_full_two_steps_returns_unsat_for_fixed_weight(monkeypatch):
    model = MznXorDifferentialFixingNumberOfActiveSboxesModel(ToyAESBlockCipher(number_of_rounds=1))
    calls = _stub_two_step_model(model, monkeypatch, ["=====UNSATISFIABLE=====\n"])

    solution = model.solve_full_two_steps_xor_differential_model(
        "xor_differential_one_solution",
        7,
        [],
        CHUFFED,
        CHUFFED,
    )

    assert calls["transform_attempts"] == []
    assert calls["solve_model_types"] == ["xor_differential_first_step"]
    assert calls["models"] == ["table_for_['first_step_pattern'];"]
    assert solution == UNSATISFIABLE


def test_solve_full_two_steps_warns_about_non_word_aligned_key_schedule_rotations(monkeypatch):
    model = MznXorDifferentialFixingNumberOfActiveSboxesModel(LBlockBlockCipher(number_of_rounds=1))
    _stub_two_step_model(model, monkeypatch, ["SAT\n"])

    with pytest.warns(UserWarning, match="rot_0_13.*not a multiple of the word size"):
        model.solve_full_two_steps_xor_differential_model("xor_differential_one_solution", -1, [], CHUFFED, CHUFFED)


def test_solve_full_two_steps_does_not_warn_for_word_aligned_key_schedule(monkeypatch, recwarn):
    model = MznXorDifferentialFixingNumberOfActiveSboxesModel(ToyAESBlockCipher(number_of_rounds=1))
    _stub_two_step_model(model, monkeypatch, ["SAT\n"])

    model.solve_full_two_steps_xor_differential_model("xor_differential_one_solution", -1, [], CHUFFED, CHUFFED)

    assert len(recwarn) == 0
