"""Recovered deterministic-truncated SAT transition through canonical solvers."""

import pytest

from claasp.drivers.solvers import (
    CryptoMiniSatSolver,
    KissatSolver,
    MinisatSolver,
    SatStatus,
)
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints.sat import (
    ImpossibleBoundarySATModel,
    ModularAddDeterministicTruncatedSATModel,
    ModularSubtractDeterministicTruncatedSATModel,
    SpeckImpossibleSATModel,
    WordDeterministicTruncatedSATModel,
)
from claasp.transformations import invert_primitive

pytestmark = pytest.mark.external


def _fixed(model, prefix, pattern):
    return {
        f"{prefix}_{bit}_{field}": value
        for bit, encoded in enumerate(model.encode_pattern(pattern))
        for field, value in zip(("unknown", "value"), encoded)
    }


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_truncated_modadd_accepts_only_the_semantic_output(solver_type):
    model = ModularAddDeterministicTruncatedSATModel(4)
    formula = model.cnf_formula()
    boundary = _fixed(model, "left", "0001") | _fixed(model, "right", "0001")
    accepted = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "???0")
    )
    assert accepted.status is SatStatus.SATISFIABLE
    left, right, output = model.decode_transition(accepted.assignment)
    assert tuple(map(str, (left, right, output))) == ("0001", "0001", "???0")

    rejected = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "0000")
    )
    assert rejected.status is SatStatus.UNSATISFIABLE


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_truncated_modsub_accepts_only_the_semantic_output(solver_type):
    model = ModularSubtractDeterministicTruncatedSATModel(4)
    formula = model.cnf_formula()
    boundary = _fixed(model, "left", "0001") | _fixed(model, "right", "0001")
    accepted = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "???0")
    )
    assert accepted.status is SatStatus.SATISFIABLE
    assert tuple(map(str, model.decode_transition(accepted.assignment))) == (
        "0001",
        "0001",
        "???0",
    )

    rejected = solver_type(timeout_seconds=10).solve(
        formula, boundary | _fixed(model, "output", "0000")
    )
    assert rejected.status is SatStatus.UNSATISFIABLE


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_truncated_inverse_toy_speck_uses_modular_subtract(solver_type):
    inverse = invert_primitive(
        ToySpeck(2), recover_input="plaintext", retained_inputs=("key",)
    ).primitive
    model = WordDeterministicTruncatedSATModel(
        inverse, fixed_input_patterns={"output": "00000001", "key": "0" * 16}
    )
    result = solver_type(timeout_seconds=10).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_characteristic(result.assignment)
    assert str(trail.output_pattern) == "?????00?"
    assert model.check_characteristic(trail)


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_deterministic_truncated_toy_speck_trail_is_solver_independent(solver_type):
    options = {
        "fixed_input_patterns": {"plaintext": "00000001", "key": "0" * 16},
        "output_pattern": "???0????",
    }
    model = WordDeterministicTruncatedSATModel(ToySpeck(2), **options)
    result = solver_type(timeout_seconds=10).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_characteristic(result.assignment)
    assert str(trail.output_pattern) == "???0????"
    assert model.check_characteristic(trail)

    rejected = WordDeterministicTruncatedSATModel(
        ToySpeck(2),
        fixed_input_patterns=options["fixed_input_patterns"],
        output_pattern="00000000",
    )
    result = solver_type(timeout_seconds=10).solve(rejected.cnf_formula())
    assert result.status is SatStatus.UNSATISFIABLE


def test_deterministic_truncated_enumeration_blocks_semantic_patterns():
    model = WordDeterministicTruncatedSATModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
    )
    result = model.enumerate_trails(MinisatSolver(timeout_seconds=10), limit=2)
    assert result.complete and len(result.trails) == 1
    assert str(result.trails[0].output_pattern) == "???0????"


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_impossible_boundary_sat_recovers_exact_contradiction_positions(solver_type):
    model = ImpossibleBoundarySATModel(5, forward_pattern="01??0", backward_pattern="00?11")
    result = solver_type(timeout_seconds=10).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    boundary = model.decode_boundary(result.assignment)
    assert boundary.contradictory_positions == (1, 4)

    compatible = ImpossibleBoundarySATModel(5, forward_pattern="01??0", backward_pattern="01?00")
    result = solver_type(timeout_seconds=10).solve(compatible.cnf_formula())
    assert result.status is SatStatus.UNSATISFIABLE


@pytest.mark.parametrize("solver_type", (MinisatSolver, KissatSolver, CryptoMiniSatSolver))
def test_speck_impossible_sat_decodes_both_directional_graphs(solver_type):
    model = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1)
    result = solver_type(timeout_seconds=30).solve(model.cnf_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(result.assignment)
    assert trail.boundary.is_impossible
    assert trail.boundary.forward == trail.forward.output_pattern
    assert trail.boundary.backward == trail.backward.output_pattern


def test_speck_impossible_sat_rejects_zero_external_differences():
    model = SpeckImpossibleSATModel(
        Speck(number_of_rounds=3),
        middle_round=1,
        input_pattern="0" * 32,
        output_pattern="0" * 32,
    )
    result = MinisatSolver(timeout_seconds=30).solve(model.cnf_formula())
    assert result.status is SatStatus.UNSATISFIABLE
