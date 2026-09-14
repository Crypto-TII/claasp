import shutil
import subprocess

import pytest

from claasp_next.drivers.solvers import CPStatus, MiniZincSolver
from claasp_next.analysis import AnalysisProblem, FixedValue
from claasp_next.primitives import AES, Simon, Speck
from claasp_next.representations.constraints.cp import MiniZincModel
from claasp_next.semantics import (
    DETERMINISTIC_TRUNCATED_XOR,
    PROBABILISTIC_TRUNCATED_XOR,
    XOR_DIFFERENTIAL,
    XOR_LINEAR,
)
from claasp_next.semantics.cryptanalysis import PropagationProblem
from claasp_next.representations.constraints.cp import (
    PresentDifferentialCPModel,
    ImpossibleBoundaryCPModel,
    PresentLinearCPModel,
    SBoxDifferenceCPModel,
    SBoxBoomerangCPModel,
    ProbabilisticTruncatedModularAddCPModel,
    SpeckDifferentialCPModel,
    SpeckImpossibleCPModel,
    SimonImpossibleCPModel,
    SpeckProbabilisticTruncatedCPModel,
    SpeckTruncatedCPModel,
    WordwiseDifferenceCPModel,
)
from claasp_next.semantics.cryptanalysis import (
    TruncatedXorDifference, check_probabilistic_truncated_modular_add,
    ImpossiblePropagationBoundary,
    WordwiseDifferenceKind, WordwiseXorDifference,
    propagate_single_active_aes_byte,
)
from claasp_next.representations.constraints.smt.trails import (
    check_present_linear_smt_trail,
    check_present_smt_trail,
)
from claasp_next.primitives import Present


pytestmark = pytest.mark.external


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
    below = PresentDifferentialCPModel(PropagationProblem(
        primitive,
        XOR_DIFFERENTIAL,
        maximum_weight=3,
        provenance=("PRESENT-2 legacy lower bound",),
    ))
    optimum = PresentDifferentialCPModel(PropagationProblem(
        primitive,
        XOR_DIFFERENTIAL,
        maximum_weight=4,
        provenance=("PRESENT-2 legacy optimum",),
    ))

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 4
    assert check_present_smt_trail(primitive, trail)


def test_minizinc_proves_present_three_round_linear_optimum_with_signs():
    primitive = Present(number_of_rounds=3)
    solver = MiniZincSolver(solver=_test_solver(), timeout_seconds=60)
    below = PresentLinearCPModel(PropagationProblem(
        primitive,
        XOR_LINEAR,
        maximum_weight=3,
        provenance=("PRESENT-3 legacy linear lower bound",),
    ))
    optimum = PresentLinearCPModel(PropagationProblem(
        primitive,
        XOR_LINEAR,
        maximum_weight=4,
        provenance=("PRESENT-3 legacy linear optimum",),
    ))

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


def test_minizinc_proves_legacy_speck_five_round_differential_optimum():
    primitive = Speck(number_of_rounds=5)
    solver = MiniZincSolver(solver=_test_solver(require_chuffed=True), timeout_seconds=30)
    below = SpeckDifferentialCPModel(PropagationProblem(
        primitive, XOR_DIFFERENTIAL, maximum_weight=8,
        provenance=("legacy Speck32/64-5 lower bound",),
    ))
    optimum = SpeckDifferentialCPModel(PropagationProblem(
        primitive, XOR_DIFFERENTIAL, maximum_weight=9,
        provenance=("legacy Speck32/64-5 optimum",),
    ))

    assert solver.solve(below.cp_model()).status is CPStatus.UNSATISFIABLE
    solved = solver.solve(optimum.cp_model())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert trail.total_weight == 9
    assert len(trail.steps) == 5


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
            primitive, PROBABILISTIC_TRUNCATED_XOR,
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
    model = ImpossibleBoundaryCPModel(ImpossiblePropagationBoundary(
        TruncatedXorDifference.parse("01??0"),
        TruncatedXorDifference.parse("00?11"),
    ))

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())
    boundary = model.decode_boundary(solved.assignment)

    assert solved.status is CPStatus.SATISFIED
    assert boundary.contradictory_positions == (1, 4)


def test_minizinc_rejects_a_compatible_middle_boundary():
    model = ImpossibleBoundaryCPModel(ImpossiblePropagationBoundary(
        TruncatedXorDifference.parse("01??0"),
        TruncatedXorDifference.parse("?1?00"),
    ))

    solved = MiniZincSolver(solver=_test_solver()).solve(model.cp_model())

    assert solved.status is CPStatus.UNSATISFIABLE


def test_minizinc_preserves_legacy_speck_seven_round_impossible_unsat():
    model = SpeckImpossibleCPModel(Speck(number_of_rounds=7), middle_round=3)

    solved = MiniZincSolver(
        solver=_test_solver(require_chuffed=True), timeout_seconds=30
    ).solve(model.cp_model())

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
