"""One-witness queries validate input and never turn uncertainty into UNSAT."""

from types import SimpleNamespace

import pytest

from claasp.analysis._trail_queries import first_characteristic
from claasp.drivers.solvers import SatResult, SatStatus
from claasp.primitives import ToySpeck


class ForbiddenSolver:
    def solve(self, formula):
        raise AssertionError("invalid queries must fail before solver execution")


@pytest.mark.parametrize("kind", ["differential", "linear"])
@pytest.mark.parametrize("weight", [None, -1, False, float("nan"), float("inf")])
def test_invalid_fixed_or_upper_weights_are_rejected_before_execution(kind, weight):
    analysis = ToySpeck(1).analysis
    for name in (
        f"find_one_xor_{kind}_trail_with_fixed_weight",
        f"find_all_xor_{kind}_trails_with_weight_at_most",
    ):
        with pytest.raises(ValueError):
            getattr(analysis, name)(weight, solver=ForbiddenSolver())


def test_nonzero_input_cannot_be_fixed_to_zero():
    with pytest.raises(ValueError, match="cannot be fixed to zero"):
        ToySpeck(1).analysis.find_one_xor_differential_trail(
            fixed_input_differences={"plaintext": 0}, solver=ForbiddenSolver()
        )


def test_invalid_solver_contract_is_actionable():
    with pytest.raises(TypeError, match="solve\\(formula\\)"):
        first_characteristic(None, object())


@pytest.mark.parametrize("assignment", [None, {}])
def test_sat_requires_a_decodable_and_independently_checked_witness(assignment):
    candidate = object()

    class Model:
        def smt_formula(self):
            from claasp.representations.constraints.smt import SMTFormula

            return SMTFormula((), (), ())

        def decode_characteristic(self, values):
            assert values == {}
            return candidate

        def check_characteristic(self, result):
            assert result is candidate
            return False

    driver = SimpleNamespace(
        solve=lambda formula: SatResult(SatStatus.SATISFIABLE, assignment, 0.0, "", "")
    )
    with pytest.raises(RuntimeError, match="assignment|independent graph validation"):
        first_characteristic(Model(), driver)


@pytest.mark.parametrize("kind", ("linear", "differential"))
def test_unknown_enumeration_retains_incompleteness_and_uses_portable_cnf(kind):
    from claasp.representations.constraints.sat import CNFFormula

    class Unknown:
        def solve(self, formula):
            assert isinstance(formula, CNFFormula)
            return SimpleNamespace(status="unknown", assignment=None, runtime_seconds=0.0)

    result = getattr(ToySpeck(1).analysis, f"enumerate_xor_{kind}_trails")(1, solver=Unknown())
    assert not result.complete and not result.trails
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
