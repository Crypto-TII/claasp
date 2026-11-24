"""Boomerang API regression and solver integration tests."""

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
from datetime import timedelta
from types import SimpleNamespace

import pytest
from minizinc import Status

from claasp.cipher import Cipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation


def structure(top=1, middle=1, bottom=1):
    return dict(
        top_part_number_of_rounds=top,
        middle_part_number_of_rounds=middle,
        bottom_part_number_of_rounds=bottom,
    )


def toy_modadd(rounds=1, operation="modadd"):
    cipher = Cipher("boomerang_test", "permutation", ["plaintext"], [4], 4)
    left, right = "plaintext", "plaintext"
    left_bits, right_bits = [0, 1], [2, 3]
    for _ in range(rounds):
        cipher.add_round()
        left = getattr(cipher, "add_" + operation + "_component")(
            [left, right], [left_bits, right_bits], 2
        ).id
        left_bits = [0, 1]
        cipher.add_round_output_component([left, right], [left_bits, right_bits], 4)
    cipher.add_cipher_output_component([left, right], [left_bits, right_bits], 4)
    return cipher


@pytest.mark.parametrize(
    "counts",
    [
        structure(-1, 2, 2),
        structure(1, 0, 2),
        structure(1, 1, 2),
        structure(True, 1, 1),
        structure(1.0, 1, 1),
        {},
    ],
)
def test_invalid_structure(counts):
    with pytest.raises(ValueError):
        MznHadipourBoomerangModel(SpeckBlockCipher(number_of_rounds=3), counts)


@pytest.mark.parametrize("weight", [-2, 0.001, float("inf"), float("nan"), "invalid"])
def test_invalid_weight(weight):
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    with pytest.raises(ValueError):
        model.build_hadipour_boomerang_model(weight)


@pytest.mark.parametrize(
    "cipher",
    [
        SpeckBlockCipher(number_of_rounds=3),
        SimonBlockCipher(number_of_rounds=3),
        LeaBlockCipher(number_of_rounds=3),
        KatanBlockCipher(number_of_rounds=3),
        ChaskeyPiPermutation(number_of_rounds=3),
        ChachaPermutation(number_of_rounds=3, round_mode="half_half"),
    ],
)
def test_build_is_repeatable_and_does_not_mutate_cipher(cipher, tmp_path, monkeypatch):
    before = deepcopy(cipher.as_python_dictionary())
    monkeypatch.chdir(tmp_path)
    with redirect_stdout(StringIO()) as output:
        model = MznHadipourBoomerangModel(
            cipher, structure(1, 1, cipher.number_of_rounds - 2)
        )
        model.build_hadipour_boomerang_model()
        first = model.assemble_model()
        model.build_hadipour_boomerang_model()
        assert model.assemble_model() == first
    assert cipher.as_python_dictionary() == before
    assert not list(tmp_path.iterdir())
    assert output.getvalue() == ""
    assert model.component_and_probability


@pytest.mark.parametrize("middle", [1, 2, 3])
@pytest.mark.parametrize("factory", [SpeckBlockCipher, SimonBlockCipher])
def test_switch_variants(factory, middle):
    model = MznHadipourBoomerangModel(
        factory(number_of_rounds=middle + 2), structure(1, middle, 1)
    )
    model.build_hadipour_boomerang_model()
    assert len(model._middle_probabilities) == middle
    if factory == SpeckBlockCipher:
        kinds = (
            ["BCT"]
            if middle == 1
            else ["UBCT", "LBCT"] + (["EBCT"] if middle == 3 else [])
        )
        for kind in kinds:
            assert "only_large_switch_" + kind.lower() + "_enum" in model.assemble_model()


def test_fixed_values_and_export(tmp_path):
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    fixed = [
        set_fixed_variables("upper_plaintext", "equal", [0, 1, 2, 3], [0, 1, 0, 0])
    ]
    model.build_hadipour_boomerang_model(1.25, fixed)
    assert "constraint weight = 125;" in model.model_constraints
    assert "solve satisfy;" in model.model_constraints
    assert "upper_plaintext[1] = 1" in model.assemble_model()
    model.write_minizinc_model_to_file(str(tmp_path))
    assert len(list(tmp_path.glob("*.mzn"))) == 1


def test_prefix_round_trip_invalidates_cached_lookup():
    cipher = SpeckBlockCipher(number_of_rounds=2)
    component = cipher.component_from_id("rot_0_0")
    cipher.add_prefix()
    assert cipher.component_from_id("upper_rot_0_0") is component
    cipher.remove_prefix()
    assert cipher.component_from_id("rot_0_0") is component
    cipher.remove_prefix("not_present_")
    assert cipher.inputs[0] == "plaintext"


def test_parser_preserves_fractional_weight():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    raw = SimpleNamespace(
        _output_item="upper_plaintext = [0, 1, 0, 0]\nUpper weight = 0.0\nMiddle weight = 1.25\nLower weight = 0.0\nTrail weight = 1.25\n"
    )
    result = model._parse_boomerang_solution(
        raw, Status.OPTIMAL_SOLUTION, "gecode", {"time": timedelta(seconds=2)}
    )
    assert result["components_values"]["upper_plaintext"]["value"] == "0x4"
    assert result["total_weight"] == "1.25"
    assert result["middle_weight"] == 1.25
    assert result["status"] == "SATISFIABLE"


def test_solve_and_fixed_weight_round_trip():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    result = model.find_lowest_weight_boomerang_trail(
        solver_name="gecode", timeout_in_seconds=30
    )
    assert result["status"] == "SATISFIABLE"
    assert result["solver_status"] == "OPTIMAL_SOLUTION"
    assert (
        float(result["total_weight"])
        == 2 * result["upper_weight"]
        + result["middle_weight"]
        + 2 * result["lower_weight"]
    )
    assert result["building_time_seconds"] >= 0
    again = model.find_one_boomerang_trail_with_fixed_weight(
        float(result["total_weight"]), solver_name="gecode", timeout_in_seconds=30
    )
    assert again["status"] == "SATISFIABLE"
    assert again["total_weight"] == result["total_weight"]


def test_unsatisfiable_external_difference():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    fixed = [set_fixed_variables("upper_plaintext", "equal", range(4), [0] * 4)]
    result = model.find_one_boomerang_trail(
        fixed, solver_name="gecode", timeout_in_seconds=30
    )
    assert result["status"] == "UNSATISFIABLE"
    assert result["components_values"] == {}
    assert result["total_weight"] is None
    explicit_limit = model.solve(
        solver_name="gecode", nr_solutions_=1, timeout_in_seconds_=10
    )
    assert explicit_limit["status"] == "UNSATISFIABLE"
    assert explicit_limit["components_values"] == {}


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("middle", [1, 2, 3])
def test_enumerate_small_fixed_external_differences(bounded, middle):
    model = MznHadipourBoomerangModel(toy_modadd(middle), structure(0, middle, 0))
    model.build_hadipour_boomerang_model()
    output = next(
        name
        for name in model.cipher.all_components_ids()
        if name.startswith("lower_cipher_output")
    )
    fixed = [
        set_fixed_variables("upper_plaintext", "equal", range(4), [1, 0, 0, 0]),
        set_fixed_variables(output, "equal", range(4), [1, 0, 0, 0]),
    ]
    method = (
        model.find_all_boomerang_trails_with_weight_at_most
        if bounded
        else model.find_all_boomerang_trails_with_fixed_weight
    )
    solutions = method(
        0, fixed_values=fixed, solver_name="gecode", timeout_in_seconds=30
    )
    assert len(solutions) == 1
    assert all(solution["total_weight"] == "0.0" for solution in solutions)


@pytest.mark.parametrize(
    "delta,nabla", [(1, 1), (1, 4), (4, 1), (4, 4), (5, 5), (3, 7)]
)
@pytest.mark.parametrize("operation", ["modadd", "modsub"])
def test_two_bit_modular_switch_matches_exhaustive_boomerang(delta, nabla, operation):
    import math

    def forward(x):
        left, right = x >> 2, x & 3
        return (((left + right) & 3) << 2) | right

    def backward(x):
        left, right = x >> 2, x & 3
        return (((left - right) & 3) << 2) | right

    if operation == "modsub":
        forward, backward = backward, forward
    successes = sum(
        backward(forward(x) ^ nabla) ^ backward(forward(x ^ delta) ^ nabla) == delta
        for x in range(16)
    )
    cipher = toy_modadd(operation=operation)
    output = "lower_" + cipher.all_components_ids()[-1]
    model = MznHadipourBoomerangModel(cipher, structure(0, 1, 0))
    fixed = [
        set_fixed_variables(
            "upper_plaintext",
            "equal",
            range(4),
            [(delta >> i) & 1 for i in reversed(range(4))],
        ),
        set_fixed_variables(
            output, "equal", range(4), [(nabla >> i) & 1 for i in reversed(range(4))]
        ),
    ]
    solution = model.find_one_boomerang_trail(
        fixed, solver_name="gecode", timeout_in_seconds=10
    )
    assert (solution["status"] == "SATISFIABLE") == bool(successes)
    if successes:
        assert abs(float(solution["total_weight"]) + math.log2(successes / 16)) < 0.1


@pytest.mark.parametrize("middle", [2, 3])
@pytest.mark.parametrize("operation", ["modadd", "modsub"])
def test_multiround_modular_predicates_solve(middle, operation):
    model = MznHadipourBoomerangModel(
        toy_modadd(middle, operation), structure(0, middle, 0)
    )
    result = model.find_one_boomerang_trail(solver_name="gecode", timeout_in_seconds=15)
    assert result["status"] == "SATISFIABLE"


def test_prebuilt_solve_requires_a_model_and_rejects_other_types():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    with pytest.raises(ValueError, match="Build"):
        model.solve()
    with pytest.raises(ValueError, match="only solves"):
        model.solve("xor_linear")


@pytest.mark.parametrize("option", ["timeout_in_seconds_", "processes_"])
def test_invalid_solver_options(option):
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    model.build_hadipour_boomerang_model(None)
    with pytest.raises(ValueError, match="positive"):
        model.solve(**{option: 0})


def test_timeout_status_and_solver_options(monkeypatch):
    from sage.rings.integer import Integer
    import claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model as boomerang

    calls = []

    def fake_solve(**options):
        calls.append(options)
        return SimpleNamespace(
            solution=[] if options.get("nr_solutions") is not None else None,
            status=Status.UNKNOWN,
            statistics={},
        )

    monkeypatch.setattr(
        boomerang, "Instance", lambda solver, model: SimpleNamespace(solve=fake_solve)
    )
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    result = model.find_one_boomerang_trail(
        timeout_in_seconds=Integer(2), processes=Integer(3)
    )
    assert result["status"] == "UNKNOWN"
    assert result["total_weight"] is None
    assert calls[-1]["timeout"] == timedelta(seconds=2)
    assert calls[-1]["processes"] == 3
    assert model.find_all_boomerang_trails_with_fixed_weight(0) == []
    result = model.solve(
        solve_external=True,
        timeout_in_seconds_=Integer(2),
        processes_=Integer(3),
        nr_solutions_=1,
        random_seed_=7,
        free_search_=True,
        optimisation_level_=0,
    )
    assert result["status"] == "UNKNOWN"
    assert calls[-1] == dict(
        all_solutions=False,
        timeout=timedelta(seconds=2),
        processes=3,
        nr_solutions=1,
        random_seed=7,
        intermediate_solutions=False,
        free_search=True,
        optimisation_level=0,
    )


@pytest.mark.parametrize("multiple", [False, True])
def test_solver_error_is_not_reported_as_unknown(multiple):
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    result = SimpleNamespace(solution=None, status=Status.ERROR, statistics={})
    with pytest.raises(RuntimeError, match="MiniZinc solver gecode reported ERROR"):
        model._solver_result(result, "gecode", multiple=multiple, intermediate=False)


def test_invalid_weight_range():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    with pytest.raises(ValueError, match="min_weight"):
        model.find_all_boomerang_trails_with_weight_at_most(1, min_weight=2)


def test_and_extended_switch_matches_all_bit_quartets():
    """Check joint derivative compatibility and probability, including zero directions."""
    import itertools
    import math
    from minizinc import Instance, Model, Solver

    cases = list(itertools.product(range(2), repeat=6))
    model = Model()
    source = [
        "array[0..63] of var bool: valid;",
        "array[0..63] of var 0..200: weights;",
    ]
    expected = []
    for index, (a, b, c, d, upper, lower) in enumerate(cases):
        count = sum(
            ((x & y) ^ ((x ^ a) & (y ^ b))) == upper
            and ((x & y) ^ ((x ^ c) & (y ^ d))) == lower
            and (
                (x & y)
                ^ ((x ^ a) & (y ^ b))
                ^ ((x ^ c) & (y ^ d))
                ^ ((x ^ a ^ c) & (y ^ b ^ d))
            )
            == 0
            for x, y in itertools.product(range(2), repeat=2)
        )
        expected.append(count)
        constraints = MznHadipourBoomerangModel._and_switch_constraints(
            *map(str, (a, b, c, d, upper, lower)),
            str(100 if a or b else 0),
            str(100 if c or d else 0),
            f"weights[{index}]",
            "ebct",
        )
        source.append(constraints[-1])
        conditions = [
            line.removeprefix("constraint ").removesuffix(";")
            for line in constraints[:-1]
        ]
        conditions.extend([f"({a}+{b}>0 \\/ {upper}=0)", f"({c}+{d}>0 \\/ {lower}=0)"])
        source.append(
            f"constraint valid[{index}] = ("
            + " /\\ ".join(f"({condition})" for condition in conditions)
            + ");"
        )
    model.add_string("\n".join(source + ["solve satisfy;"]))
    result = Instance(Solver.lookup("gecode"), model).solve()
    assert result["valid"] == [bool(count) for count in expected]
    for index, count in enumerate(expected):
        if count:
            assert result["weights"][index] == -100 * math.log2(count / 4)


def test_claasp_solver_arguments_return_requested_solutions():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    model.build_hadipour_boomerang_model(0)
    solutions = model.solve(
        solve_external=True,
        solver_name="gecode",
        timeout_in_seconds_=10,
        processes_=1,
        nr_solutions_=2,
        random_seed_=7,
        free_search_=True,
        optimisation_level_=0,
    )
    assert isinstance(solutions, list)
    assert len(solutions) == 2
    assert all(solution["status"] == "SATISFIABLE" for solution in solutions)


def test_optimization_returns_an_incumbent_list():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    model.build_hadipour_boomerang_model()
    solutions = model.solve(
        solver_name="gecode", timeout_in_seconds_=10, intermediate_solutions_=True
    )
    assert isinstance(solutions, list)
    assert solutions
    assert solutions[-1]["solver_status"] == "OPTIMAL_SOLUTION"


def test_only_final_incumbent_is_marked_optimal():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    outputs = [
        SimpleNamespace(
            _output_item=(
                "upper_plaintext = [0, 1, 0, 0]\nUpper weight = 0.0\n"
                f"Middle weight = {weight}\nLower weight = 0.0\nTrail weight = {weight}\n"
            )
        )
        for weight in (0.94, 0.0)
    ]
    result = SimpleNamespace(
        solution=outputs, status=Status.OPTIMAL_SOLUTION, statistics={}
    )
    solutions = model._solver_result(result, "gecode", multiple=True, intermediate=True)
    assert [solution["solver_status"] for solution in solutions] == [
        "SATISFIED",
        "OPTIMAL_SOLUTION",
    ]
    assert [solution["total_weight"] for solution in solutions] == ["0.94", "0.0"]


def test_external_solver_flag_requires_boolean():
    model = MznHadipourBoomerangModel(toy_modadd(), structure(0, 1, 0))
    with pytest.raises(ValueError, match="boolean"):
        model.solve(solve_external="external")


@pytest.mark.parametrize("middle", [1, 2, 3])
def test_real_simon_search_with_each_switch_kind(middle):
    model = MznHadipourBoomerangModel(
        SimonBlockCipher(number_of_rounds=middle + 2), structure(1, middle, 1)
    )
    result = model.find_one_boomerang_trail(
        solver_name="chuffed", timeout_in_seconds=30
    )
    assert result["status"] == "SATISFIABLE"
    assert int(result["components_values"]["upper_plaintext"]["value"], 16) != 0
    output = next(
        name
        for name in result["components_values"]
        if name.startswith("lower_cipher_output")
    )
    assert int(result["components_values"][output]["value"], 16) != 0


def test_reproduce_archived_katan40_weight():
    model = MznHadipourBoomerangModel(
        KatanBlockCipher(number_of_rounds=40), structure(19, 1, 20)
    )
    result = model.find_one_boomerang_trail_with_fixed_weight(
        12, solver_name="chuffed", timeout_in_seconds=30
    )
    assert result["status"] == "SATISFIABLE"
    assert float(result["total_weight"]) == 12


def test_key_first_input_is_selected_without_mutating_cipher():
    from claasp.ciphers.block_ciphers.cham_block_cipher import ChamBlockCipher

    cipher = ChamBlockCipher(number_of_rounds=3)
    before = deepcopy(cipher.as_python_dictionary())
    model = MznHadipourBoomerangModel(cipher, structure(), middle_model="exact")
    model.build_hadipour_boomerang_model()
    assert cipher.as_python_dictionary() == before
    assert model.original_cipher.inputs[0] == "plaintext"
    assert model._external_differences.intersection({"upper_plaintext"})
    assert "upper_key" not in model._data_inputs


def test_exact_sbox_differential_constraints_share_ddt_and_probability_indices():
    from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher

    cipher = PresentBlockCipher(number_of_rounds=3)
    model = MznHadipourBoomerangModel(cipher, structure(), middle_model="exact")
    model.build_hadipour_boomerang_model()
    first = model.assemble_model()
    assert "DDT_upper_sbox" in first
    assert all(
        isinstance(indices, list)
        for indices in model.component_and_probability.values()
    )
    assert any(
        name.startswith("lower_sbox") for name in model.component_and_probability
    )
    model.build_hadipour_boomerang_model()
    assert model.assemble_model() == first


def test_exact_sbox_quartet_replays_with_key_first_graph():
    cipher = Cipher("key_first_sbox", "block_cipher", ["key", "plaintext"], [3, 3], 3)
    state = "plaintext"
    for _ in range(3):
        cipher.add_round()
        state = cipher.add_xor_component([state, "key"], [list(range(3))] * 2, 3).id
        state = cipher.add_sbox_component(
            [state], [list(range(3))], 3, [0, 1, 2, 3, 4, 5, 7, 6]
        ).id
        cipher.add_round_output_component([state], [list(range(3))], 3)
    output = cipher.add_cipher_output_component([state], [list(range(3))], 3).id
    model = MznHadipourBoomerangModel(
        cipher, structure(), middle_model="exact", exclude_returning_quartets=True
    )
    result = model.find_one_boomerang_trail(solver_name="coinbc", timeout_in_seconds=10)
    assert result["status"] == "SATISFIABLE"
    points = []
    for j in range(4):
        values = result["quartet_values"]
        point = [
            int(values[f"quartet_{j}_{name}"]["value"], 16) for name in cipher.inputs
        ]
        assert cipher.evaluate(point) == int(
            values[f"quartet_{j}_{output}"]["value"], 16
        )
        points.append(point)
    assert len({point[1] for point in points}) == 4
    assert len({point[0] for point in points}) == 1
    local_model = MznHadipourBoomerangModel(cipher, structure())
    local_model.build_hadipour_boomerang_model()
    assert any(
        name.startswith("upper_sbox") for name in local_model.component_and_probability
    )
    assert any(
        name.startswith("lower_sbox") for name in local_model.component_and_probability
    )


def test_binary_key_schedule_constants_do_not_reject_valid_twine_quartet():
    from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher
    from claasp.cipher_modules.models.utils import integer_to_bit_list

    cipher = TwineBlockCipher(number_of_rounds=4)
    points = [12, 13, 16, 17]
    outputs = [cipher.evaluate([x, 0]) for x in points]
    assert outputs[0] ^ outputs[1] == outputs[2] ^ outputs[3]
    fixed = [
        set_fixed_variables(
            f"quartet_{j}_plaintext",
            "equal",
            list(range(64)),
            integer_to_bit_list(x, 64, "big"),
        )
        for j, x in enumerate(points)
    ]
    fixed.append(
        set_fixed_variables("quartet_0_key", "equal", list(range(80)), [0] * 80)
    )
    model = MznHadipourBoomerangModel(
        cipher,
        structure(1, 2, 1),
        middle_model="exact",
        exclude_returning_quartets=True,
    )
    result = model.find_one_boomerang_trail(
        fixed_values=fixed, solver_name="gecode", timeout_in_seconds=10
    )
    assert result["status"] == "SATISFIABLE"


def test_exact_or_feistel_quartet_replays():
    cipher = Cipher("or_feistel", "permutation", ["plaintext"], [4], 4)
    left = right = "plaintext"
    left_bits, right_bits = [0, 1], [2, 3]
    for _ in range(3):
        cipher.add_round()
        nonlinear = cipher.add_or_component(
            [left, left], [left_bits, left_bits[::-1]], 2
        ).id
        next_left = cipher.add_xor_component(
            [right, nonlinear], [right_bits, [0, 1]], 2
        ).id
        right, right_bits = left, left_bits
        left, left_bits = next_left, [0, 1]
        cipher.add_round_output_component([left, right], [left_bits, right_bits], 4)
    output = cipher.add_cipher_output_component(
        [left, right], [left_bits, right_bits], 4
    ).id
    model = MznHadipourBoomerangModel(
        cipher, structure(), middle_model="exact", exclude_returning_quartets=True
    )
    result = model.find_one_boomerang_trail(solver_name="gecode", timeout_in_seconds=10)
    assert result["status"] == "SATISFIABLE"
    values = result["quartet_values"]
    for j in range(4):
        x = int(values[f"quartet_{j}_plaintext"]["value"], 16)
        assert cipher.evaluate([x]) == int(values[f"quartet_{j}_{output}"]["value"], 16)
    local_model = MznHadipourBoomerangModel(cipher, structure())
    with pytest.raises(NotImplementedError, match="OR differential constraints require"):
        local_model.build_hadipour_boomerang_model()


@pytest.mark.parametrize('parameters',[
    {'plaintext':0},{'unknown':0},{'key':-1},{'key':1<<64},
    {'key':True},{'key':0.5},[('key',0)],
])
def test_fixed_parameters_reject_invalid_values(parameters):
    cipher = SpeckBlockCipher(number_of_rounds=3)
    split = structure()
    with pytest.raises(ValueError):
        MznHadipourBoomerangModel(cipher, split, fixed_parameters=parameters)


def test_fixed_parameter_values_are_not_xor_differences():
    parameters={'key':0xa5}
    cipher=SpeckBlockCipher(number_of_rounds=3)
    model=MznHadipourBoomerangModel(cipher,structure(),fixed_parameters=parameters)
    parameters['key']=0
    assert model.fixed_parameters=={'key':0xa5}
    assert model.enforce_value_compatibility
    model.build_hadipour_boomerang_model()
    text=model.assemble_model()
    assert 'constraint quartet_0_key[63] = 1;' in text
    assert 'constraint quartet_0_key[62] = 0;' in text
    assert 'constraint quartet_1_key[63] = quartet_0_key[63];' in text
