import shutil
import subprocess

import pytest

from claasp.analysis import AnalysisProblem, FixedValue
from claasp.drivers.solvers import CPStatus, MiniZincSolver
from claasp.primitives import AES, Present, Simon, Speck, ToySpeck
from claasp.representations.constraints.cp import (
    ImpossibleBoundaryCPModel,
    MiniZincModel,
    ModularAddDeterministicTruncatedCPModel,
    PresentActiveSBoxesCPModel,
    PresentDifferentialCPModel,
    PresentFixedActiveSBoxesCPModel,
    PresentLinearCPModel,
    ProbabilisticTruncatedModularAddCPModel,
    SBoxBoomerangCPModel,
    SBoxDifferenceCPModel,
    SimonImpossibleCPModel,
    SpeckARXWindowDifferentialCPModel,
    SpeckDifferentialCPModel,
    SpeckImpossibleCPModel,
    SpeckProbabilisticTruncatedCPModel,
    SpeckSemiDeterministicTruncatedCPModel,
    SpeckTruncatedCPModel,
    WordDeterministicDifferentialLinearCPModel,
    WordDeterministicTruncatedCPModel,
    WordDifferentialCPModel,
    WordLinearCPModel,
    WordSemiDeterministicDifferentialLinearCPModel,
    WordwiseDifferenceCPModel,
)
from claasp.representations.constraints.smt.trails import (
    check_present_linear_smt_trail,
    check_present_smt_trail,
)
from claasp.semantics import (
    DETERMINISTIC_TRUNCATED_XOR,
    PROBABILISTIC_TRUNCATED_XOR,
    XOR_DIFFERENTIAL,
    XOR_LINEAR,
)
from claasp.semantics.cryptanalysis import (
    ImpossiblePropagationBoundary,
    PropagationProblem,
    TruncatedXorDifference,
    WordwiseDifferenceKind,
    WordwiseXorDifference,
    check_probabilistic_truncated_modular_add,
    propagate_single_active_aes_byte,
)

pytestmark = pytest.mark.external


def test_minizinc_proves_present_two_round_active_sbox_optimum():
    model = PresentActiveSBoxesCPModel(Present(number_of_rounds=2))
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert (
        sum(
            bool(solved.assignment[f"active_{round_number}_{nibble}"])
            for round_number in range(1, 3)
            for nibble in range(16)
        )
        == 2
    )
    assert len(trail.steps) == 32


def test_minizinc_solves_opt_in_speck_arx_window_search():
    model = SpeckARXWindowDifferentialCPModel(
        PropagationProblem(
            Speck(number_of_rounds=3), XOR_DIFFERENTIAL, maximum_weight=45
        ),
        window_sizes=(3, 3, 3),
    )
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert trail.total_weight <= 45


def test_minizinc_minimizes_weight_at_fixed_present_activity():
    model = PresentFixedActiveSBoxesCPModel(
        Present(number_of_rounds=2), active_sboxes=2
    )
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    active = sum(
        bool(solved.assignment[f"active_{round_number}_{nibble}"])
        for round_number in range(1, 3)
        for nibble in range(16)
    )
    assert active == 2
    assert trail.total_weight == 4


def test_minizinc_preserves_deterministic_truncated_modular_add_relation():
    solver = MiniZincSolver(solver=_test_solver())
    accepted_model = ModularAddDeterministicTruncatedCPModel(4)
    accepted = solver.solve(
        accepted_model.cp_model(left_pattern="0001", right_pattern="0001", output_pattern="???0")
    )
    assert accepted.status is CPStatus.SATISFIED
    assert tuple(map(str, accepted_model.decode_transition(accepted.assignment))) == (
        "0001",
        "0001",
        "???0",
    )

    rejected_model = ModularAddDeterministicTruncatedCPModel(4)
    rejected = solver.solve(
        rejected_model.cp_model(left_pattern="0001", right_pattern="0001", output_pattern="0000")
    )
    assert rejected.status is CPStatus.UNSATISFIABLE


def test_minizinc_preserves_generic_deterministic_truncated_toy_speck_trail():
    solver = MiniZincSolver(solver=_test_solver())
    fixed = {"plaintext": "00000001", "key": "0" * 16}
    model = WordDeterministicTruncatedCPModel(
        ToySpeck(2), fixed_input_patterns=fixed, output_pattern="???0????"
    )
    solved = solver.solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_characteristic(solved.assignment)
    assert str(trail.output_pattern) == "???0????"
    assert model.check_characteristic(trail)

    rejected = WordDeterministicTruncatedCPModel(
        ToySpeck(2), fixed_input_patterns=fixed, output_pattern="00000000"
    )
    assert solver.solve(rejected.cp_model()).status is CPStatus.UNSATISFIABLE


@pytest.mark.parametrize(
    "model",
    (
        WordDifferentialCPModel(
            ToySpeck(2),
            fixed_weight=1,
            fixed_input_differences={"key": 0},
            nonzero_input="plaintext",
        ),
        WordLinearCPModel(
            ToySpeck(3),
            maximum_weight=1,
            fixed_inputs={"key": 0},
            nonzero_input="plaintext",
        ),
    ),
)
def test_minizinc_preserves_generic_weighted_word_trails(model):
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_characteristic(solved.assignment)
    assert 0 <= trail.total_weight <= 1
    assert model.check_characteristic(trail)


def test_minizinc_preserves_deterministic_differential_linear_composition():
    model = WordDeterministicDifferentialLinearCPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert trail.linear.output_mask != 0


def test_minizinc_preserves_semi_deterministic_differential_linear_composition():
    model = WordSemiDeterministicDifferentialLinearCPModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert trail.linear.output_mask != 0
    assert trail.middle_weight >= 0


def test_minizinc_preserves_semi_deterministic_truncated_speck_trail():
    output_pattern = "???????????????1???????????????1"
    model = SpeckSemiDeterministicTruncatedCPModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        output_pattern,
    )
    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=30).solve(model.cp_model())
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert str(trail.output_pattern) == output_pattern
    assert len(trail.transitions) == 2


def _test_solver(*, require_chuffed=False):
    listed = subprocess.run(
        ["minizinc", "--solvers"], text=True, capture_output=True, check=True
    ).stdout.lower()
    if require_chuffed:
        if "chuffed" not in listed:
            pytest.skip("this performance-sensitive regression requires Chuffed")
        return "chuffed"
    for solver in ("chuffed", "gecode", "cp-sat", "coin-bc"):
        if solver in listed:
            return solver
    raise AssertionError("the external test job must provide a MiniZinc solver")


def test_minizinc_all_solution_contract_requires_complete_exhaustion():
    solver = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=10)
    model = MiniZincModel(
        ("var bool: left;", "var bool: right;"),
        ("constraint left != right;",),
    )

    result = solver.solve_all(model).require_complete()

    assert result.status is CPStatus.SATISFIED
    assert result.termination == "exhausted"
    assert {(solution["left"], solution["right"]) for solution in result.solutions} == {
        (False, True),
        (True, False),
    }


def test_minizinc_solves_and_projects_named_values():
    assert shutil.which("minizinc") is not None, "the external test job must install MiniZinc"
    model = MiniZincModel(
        declarations=("var 0..3: x;", "array[1..3] of var 0..1: bits;"),
        constraints=(
            "constraint x = 2;",
            "constraint bits = [1, 0, 1];",
        ),
        provenance=("portable CP foundation fixture",),
    )

    result = MiniZincSolver(solver=_test_solver()).solve(model)

    assert result.status is CPStatus.SATISFIED
    assert result.values == {"x": 2, "bits": [1, 0, 1]}
    assert result.runtime_seconds >= 0


def test_minizinc_reports_unsatisfiable_models():
    model = MiniZincModel(
        declarations=("var 0..1: x;",),
        constraints=("constraint x = 0;", "constraint x = 1;"),
    )

    result = MiniZincSolver(solver=_test_solver()).solve(model)

    assert result.status is CPStatus.UNSATISFIABLE
    assert result.values is None


def test_minizinc_recovers_and_independently_verifies_reduced_speck_key():
    primitive = Speck(number_of_rounds=1)
    plaintext = 0x6574694C
    ciphertext = primitive.evaluate(plaintext, 0x1918111009080100)

    result = primitive.analyze().recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=ciphertext,
        solver=MiniZincSolver(solver=_test_solver(), timeout_seconds=30),
    )

    assert result.is_satisfiable
    assert primitive.evaluate(plaintext, result.value("key")) == ciphertext


def test_minizinc_reproduces_legacy_full_speck_missing_bits_result():
    primitive = Speck(number_of_rounds=22)
    problem = AnalysisProblem(
        primitive,
        (
            FixedValue(primitive.input("plaintext"), 0x6574694C),
            FixedValue(primitive.input("key"), 0x1918111009080100),
        ),
        {"ciphertext": primitive.output},
    )

    result = primitive.analyze().solve(
        problem,
        MiniZincSolver(solver=_test_solver(), timeout_seconds=60),
    )

    assert result.is_satisfiable
    assert result.value("ciphertext") == 0xA86842F2
    assert primitive.evaluate(0x6574694C, 0x1918111009080100) == result.value("ciphertext")


def test_minizinc_proves_present_two_round_differential_optimum():
    primitive = Present(number_of_rounds=2)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=60)
    below = PresentDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=3,
            provenance=("PRESENT-2 legacy lower bound",),
        )
    )
    optimum = PresentDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=4,
            provenance=("PRESENT-2 legacy optimum",),
        )
    )

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 4
    assert check_present_smt_trail(primitive, trail)


def test_minizinc_proves_present_three_round_linear_optimum_with_signs():
    primitive = Present(number_of_rounds=3)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=60)
    below = PresentLinearCPModel(
        PropagationProblem(
            primitive,
            XOR_LINEAR,
            maximum_weight=3,
            provenance=("PRESENT-3 legacy linear lower bound",),
        )
    )
    optimum = PresentLinearCPModel(
        PropagationProblem(
            primitive,
            XOR_LINEAR,
            maximum_weight=4,
            provenance=("PRESENT-3 legacy linear optimum",),
        )
    )

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 4
    assert all(step.transition.sign in (-1, 1) for step in trail.steps)
    assert check_present_linear_smt_trail(primitive, trail)


def test_minizinc_reproduces_legacy_speck_truncated_round_fixture():
    primitive = Speck(number_of_rounds=2)
    model = SpeckTruncatedCPModel(
        PropagationProblem(
            primitive,
            DETERMINISTIC_TRUNCATED_XOR,
            provenance=("legacy Speck deterministic-truncated fixture",),
        ),
        TruncatedXorDifference.parse("00000000011111001110000000000000"),
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    output = model.decode_output(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert str(output) == "????100000000000????100000000011"


def test_minizinc_proves_impossible_and_possible_present_sbox_pairs():
    primitive = Present(number_of_rounds=1)
    problem = PropagationProblem(
        primitive,
        XOR_DIFFERENTIAL,
        provenance=("exhaustive PRESENT S-box DDT",),
    )
    impossible = SBoxDifferenceCPModel(problem, "sbox_1_0", 1, 1)
    possible = SBoxDifferenceCPModel(problem, "sbox_1_0", 1, 3)
    solver = MiniZincSolver(solver=_test_solver())

    assert solver.solve(impossible.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(possible.cp_model())
    transition = problem.provider_for(possible.component).transition((1,), 3)

    assert solved.status is CPStatus.SATISFIED
    assert transition.is_possible
    assert transition.weight == 2


def test_minizinc_preserves_exact_present_boomerang_connectivity_entries():
    primitive = Present(number_of_rounds=1)
    component = next(item for item in primitive.components if item.component_id == "sbox_1_0")
    solver = MiniZincSolver(solver=_test_solver())

    impossible = SBoxBoomerangCPModel(component, 1, 1)
    possible = SBoxBoomerangCPModel(component, 1, 2)

    assert solver.solve(impossible.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(possible.cp_model())
    entry = possible.decode(solved.assignment)
    assert solved.status is CPStatus.SATISFIED
    assert entry.count == 4
    assert entry.weight == 2


@pytest.mark.emulation_sensitive
def test_minizinc_proves_legacy_speck_five_round_differential_optimum():
    primitive = Speck(number_of_rounds=5)
    solver = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=30)
    below = SpeckDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=8,
            provenance=("legacy Speck32/64-5 lower bound",),
        )
    )
    optimum = SpeckDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=9,
            provenance=("legacy Speck32/64-5 optimum",),
        )
    )

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 9
    assert len(trail.steps) == 5


@pytest.mark.parametrize(
    "input_difference,output_difference,weight",
    [
        (0x00400000, 0x8000840A, 3),
        (0x02110A04, 0x80008000, 6),
    ],
)
def test_minizinc_preserves_legacy_fixed_speck_three_round_differential(
    input_difference,
    output_difference,
    weight,
):
    """sat_model_test.py dictionary-based differential fixture, zero key difference."""
    primitive = Speck(number_of_rounds=3)
    model = SpeckDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=weight,
            provenance=("legacy sat_model_test.py fixed Speck-3 witness",),
        ),
        input_difference=input_difference,
        output_difference=output_difference,
    )
    solved = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=10).solve(
        model.cp_model()
    )
    assert solved.status is CPStatus.SATISFIED
    trail = model.decode_trail(solved.assignment)
    assert trail.input_pattern.value == input_difference
    assert trail.output_pattern.value == output_difference
    assert trail.total_weight == weight


def test_minizinc_preserves_differential_boundary_comparison_sat_unsat():
    """sat_model_test.py::test_fix_variables_value_constraints differential cases."""
    primitive = Speck(number_of_rounds=3)
    problem = PropagationProblem(primitive, XOR_DIFFERENTIAL, maximum_weight=45)
    solver = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=10)
    for relation in ("equal", "not_equal"):
        model = SpeckDifferentialCPModel(problem, boundary_relation=relation)
        result = solver.solve(model.cp_model())
        assert result.status is CPStatus.SATISFIED
        trail = model.decode_trail(result.assignment)
        assert (trail.input_pattern.value == trail.output_pattern.value) == (relation == "equal")
    contradictory = SpeckDifferentialCPModel(
        problem,
        input_difference=1,
        output_difference=1,
        boundary_relation="not_equal",
    )
    assert solver.solve(contradictory.cp_model()).status is CPStatus.UNSATISFIABLE


def test_minizinc_preserves_legacy_mixed_exact_truncated_speck_feasibility():
    """sat_model_test.py::test_build_generic_sat_model_from_dictionary.

    Typed phase composition supersedes per-component method-name strings:
    first two data rounds exact, last data round deterministic truncated.
    """
    from claasp.analysis import SpeckHybridDifferentialProblem

    problem = SpeckHybridDifferentialProblem(
        Speck(number_of_rounds=3),
        exact_rounds=2,
        input_difference=0x00400000,
    )
    result = problem.solve(
        MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=10)
    )
    assert result is not None
    assert problem.check(result)
    assert result.exact_prefix.input_pattern.value == 0x00400000
    assert len(result.truncated_boundaries) == 2


@pytest.mark.emulation_sensitive
def test_minizinc_preserves_legacy_speck_five_round_bounded_trail_count():
    primitive = Speck(number_of_rounds=5)
    solver = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=120)
    representation = SpeckDifferentialCPModel(
        PropagationProblem(
            primitive,
            XOR_DIFFERENTIAL,
            maximum_weight=10,
            provenance=("legacy SMT Speck32/64-5 bounded enumeration",),
        )
    )

    result = solver.solve_all(representation.cp_model()).require_complete()
    trails = tuple(representation.decode_trail(solution) for solution in result.solutions)

    assert result.status is CPStatus.SATISFIED
    assert len(trails) == 28
    assert {trail.total_weight for trail in trails} == {9.0, 10.0}
    assert len({(trail.input_pattern.value, trail.output_pattern.value) for trail in trails}) == 28


@pytest.mark.parametrize(
    "left,right,output,carry,expected_cost",
    (
        (
            "00000000000000000000000000000000",
            "00000000?1000000?????10000001110",
            "000??????1000????????10000000010",
            "000??????0000????????00000001100",
            309,
        ),
        (
            "0000000100000000",
            "1000000000000010",
            "?111111100000010",
            None,
            700,
        ),
    ),
)
def test_minizinc_preserves_legacy_probabilistic_truncated_modadd_costs(
    left, right, output, carry, expected_cost
):
    model = ProbabilisticTruncatedModularAddCPModel(
        TruncatedXorDifference.parse(left),
        TruncatedXorDifference.parse(right),
        TruncatedXorDifference.parse(output),
        None if carry is None else TruncatedXorDifference.parse(carry),
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    transition = model.decode_transition(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert transition.scaled_weight == expected_cost
    assert check_probabilistic_truncated_modular_add(transition)


@pytest.mark.parametrize(
    "rounds,input_pattern,output_pattern,expected_weight",
    (
        (
            2,
            "00000000011111001110000000000000",
            "???????????????1???????????????1",
            1.0,
        ),
        (
            3,
            "00000000011000000000000000000000",
            "???????????????0???????????????1",
            0.0,
        ),
    ),
)
def test_minizinc_preserves_legacy_speck_probabilistic_truncated_trails(
    rounds, input_pattern, output_pattern, expected_weight
):
    primitive = Speck(number_of_rounds=rounds)
    model = SpeckProbabilisticTruncatedCPModel(
        PropagationProblem(
            primitive,
            PROBABILISTIC_TRUNCATED_XOR,
            provenance=("legacy semi-deterministic Speck fixture",),
        ),
        TruncatedXorDifference.parse(input_pattern),
        TruncatedXorDifference.parse(output_pattern),
    )

    solved = MiniZincSolver(solver=_test_solver(), timeout_seconds=60).solve(model.cp_model())
    trail = model.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert str(trail.output_pattern) == output_pattern
    assert trail.weight == expected_weight
    assert len(trail.transitions) == rounds


def test_minizinc_projects_native_wordwise_states_to_typed_values():
    words = (
        WordwiseXorDifference(8, WordwiseDifferenceKind.ZERO),
        WordwiseXorDifference.known(8, 0x53),
        WordwiseXorDifference(8, WordwiseDifferenceKind.NONZERO),
        WordwiseXorDifference(8, WordwiseDifferenceKind.UNKNOWN),
    )
    model = WordwiseDifferenceCPModel(words)

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())

    assert solved.status is CPStatus.SATISFIED
    assert model.decode(solved.assignment) == words


def test_minizinc_projects_wordwise_aes_single_byte_diffusion_fixture():
    words = propagate_single_active_aes_byte(AES(number_of_rounds=1), 0)
    model = WordwiseDifferenceCPModel(words)

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    decoded = model.decode(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert tuple(word.kind for word in decoded[:4]) == (WordwiseDifferenceKind.NONZERO,) * 4
    assert all(word.kind is WordwiseDifferenceKind.ZERO for word in decoded[4:])


def test_minizinc_proves_and_decodes_an_impossible_middle_boundary():
    model = ImpossibleBoundaryCPModel(
        ImpossiblePropagationBoundary(
            TruncatedXorDifference.parse("01??0"),
            TruncatedXorDifference.parse("00?11"),
        )
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    boundary = model.decode_boundary(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert boundary.contradictory_positions == (1, 4)


def test_minizinc_rejects_a_compatible_middle_boundary():
    model = ImpossibleBoundaryCPModel(
        ImpossiblePropagationBoundary(
            TruncatedXorDifference.parse("01??0"),
            TruncatedXorDifference.parse("?1?00"),
        )
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())

    assert solved.status is CPStatus.UNSATISFIABLE


def test_minizinc_preserves_legacy_speck_seven_round_impossible_unsat():
    model = SpeckImpossibleCPModel(Speck(number_of_rounds=7), middle_round=3)

    solved = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=30).solve(
        model.cp_model()
    )

    assert solved.status is CPStatus.UNSATISFIABLE
    assert model.cp_model().provenance == (
        "legacy MznImpossibleXorDifferentialModel Speck32/64 fixture",
        "7 rounds, split after round 3, zero key difference",
    )


def test_minizinc_preserves_legacy_simon_eleven_round_impossible_fixture():
    model = SimonImpossibleCPModel(
        Simon(number_of_rounds=11),
        TruncatedXorDifference.parse("00000000000000000000000000000001"),
        TruncatedXorDifference.parse("000000?0?00000000000000000000000"),
        middle_round=6,
    )

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    boundary = model.decode_boundary(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert str(boundary.forward).replace("?", "2") == "22222222222222220222222122222202"
    assert str(boundary.backward).replace("?", "2") == "22222222002222202222222022222222"
    assert boundary.contradictory_positions == (23,)
