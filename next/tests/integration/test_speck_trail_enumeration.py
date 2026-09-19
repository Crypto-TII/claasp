"""Legacy reduced Speck linear evidence, independently recounted after Z3."""

import shutil

import pytest

from claasp_next.analysis.arx import check_speck_linear_trail
from claasp_next.drivers.solvers import SatStatus, Z3Solver
from claasp_next.primitives import Speck, ToySpeck
from claasp_next.representations.constraints.smt import SpeckLinearSMTModel, WordLinearSMTModel

pytestmark = pytest.mark.external


def test_z3_preserves_cp_fixed_speck_linear_boundaries():
    """mzn_model_test.py dictionary-based linear fixture, data-path only."""
    primitive = Speck(number_of_rounds=3)
    model = SpeckLinearSMTModel(
        primitive,
        fixed_weight=5,
        input_mask=0x03805224,
        output_mask=0x40A000C1,
    )
    solved = Z3Solver(timeout_seconds=10).solve(model.smt_formula())
    assert solved.status is SatStatus.SATISFIABLE
    trail = model.decode_trail(solved.assignment)
    assert trail.input_pattern.value == 0x03805224
    assert trail.output_pattern.value == 0x40A000C1
    assert trail.total_weight == 5
    assert check_speck_linear_trail(primitive, trail)


@pytest.mark.parametrize("weight,count", [(2, 8), (3, 73)])
def test_toy_speck_nonzero_key_linear_enumeration_preserves_legacy_counts(weight, count):
    """SMT (bound 2) and SAT (bound 3) Speck8/16 four-round legacy fixtures."""
    model = WordLinearSMTModel(ToySpeck(), maximum_weight=weight, nonzero_input="key")
    if weight == 2:
        result = (
            model.primitive.analyze()
            .enumerate_xor_linear_trails(
                weight,
                solver=Z3Solver(timeout_seconds=10),
                nonzero_input="key",
                limit=100,
            )
            .require_complete()
        )
        model.smt_formula()
    else:
        result = model.enumerate_trails(Z3Solver(timeout_seconds=10), limit=100).require_complete()
    assert len(result.trails) == count
    assert all(dict(trail.input_masks)["key"] != 0 for trail in result.trails)
    assert all(model.check_characteristic(trail) for trail in result.trails)
    assert len({trail.semantic_assignment for trail in result.trails}) == count
    metadata = dict(result.reproducibility)
    assert metadata["primitive"] == "toy_speck"
    assert metadata["version"].startswith("Z3 version")
    assert len(metadata["graph_sha256"]) == 64


def test_cp_toy_three_round_single_key_linear_counts_are_preserved():
    """mzn_xor_linear_model_test.py fixes counts 12 at weight 1 and 13 through 1."""
    result = (
        ToySpeck(3)
        .analyze()
        .enumerate_xor_linear_trails(
            1,
            solver=Z3Solver(timeout_seconds=10),
            limit=20,
        )
        .require_complete()
    )
    assert len(result.trails) == 13
    assert sum(trail.total_weight == 1 for trail in result.trails) == 12
    assert sum(trail.total_weight == 0 for trail in result.trails) == 1
    assert all(dict(trail.input_masks)["key"] == 0 for trail in result.trails)


def test_z3_preserves_cms_four_round_speck_linear_optimum():
    """CMS cms_xor_linear_model_test.py fixes optimum 3, not just feasibility."""
    primitive = Speck(number_of_rounds=4)
    solver = Z3Solver(timeout_seconds=10)
    below = SpeckLinearSMTModel(primitive, maximum_weight=2)
    assert solver.solve(below.smt_formula()).status is SatStatus.UNSATISFIABLE
    optimum = SpeckLinearSMTModel(primitive, maximum_weight=3)
    result = solver.solve(optimum.smt_formula())
    assert result.status is SatStatus.SATISFIABLE
    trail = optimum.decode_trail(result.assignment)
    assert check_speck_linear_trail(primitive, trail)
    assert trail.total_weight == 3


def test_z3_preserves_three_round_speck_linear_optimum_and_fixed_weight():
    """Preserve SmtXorLinearModel's optimum 1 and feasible weight 7.

    Provenance: tests/unit/cipher_modules/models/smt/smt_models/
    smt_xor_linear_model_test.py, lowest-weight and fixed-weight tests.
    """
    assert shutil.which("z3") is not None, "the external job must install Z3"
    primitive = Speck(number_of_rounds=3)
    solver = Z3Solver(timeout_seconds=10)
    below = SpeckLinearSMTModel(primitive, maximum_weight=0)
    assert solver.solve(below.smt_formula()).status is SatStatus.UNSATISFIABLE
    for model, weight in (
        (SpeckLinearSMTModel(primitive, maximum_weight=1), 1),
        (SpeckLinearSMTModel(primitive, fixed_weight=7), 7),
    ):
        result = solver.solve(model.smt_formula())
        assert result.status is SatStatus.SATISFIABLE
        trail = model.decode_trail(result.assignment)
        assert check_speck_linear_trail(primitive, trail)
        assert trail.total_weight == weight
        changed = dict(result.assignment)
        changed["state_0_0"] ^= 1
        with pytest.raises(ValueError, match="assignment disagrees"):
            model.decode_trail(changed)


@pytest.mark.parametrize("weight", [0, 17])
def test_z3_exact_weight_handles_zero_and_out_of_range(weight):
    model = SpeckLinearSMTModel(Speck(number_of_rounds=1), fixed_weight=weight)
    result = Z3Solver(timeout_seconds=10).solve(model.smt_formula())
    if weight == 0:
        assert result.status is SatStatus.SATISFIABLE
        assert model.decode_trail(result.assignment).total_weight == 0
    else:
        assert result.status is SatStatus.UNSATISFIABLE
