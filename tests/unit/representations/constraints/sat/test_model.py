"""Plain Boolean consumers cannot silently discard native parity constraints."""

from itertools import product

import pytest

from claasp.representations.constraints.cp import BooleanMiniZincLowerer
from claasp.representations.constraints.milp import cnf_to_milp
from claasp.representations.constraints.sat import CNFFormula, NativeXorCNFFormula
from claasp.representations.constraints.sat.exporters import DimacsExporter
from claasp.representations.constraints.sat.model import _require_plain_cnf
from claasp.representations.constraints.smt import SMTFormula

CONSUMERS = (
    SMTFormula.from_cnf,
    DimacsExporter().export,
    cnf_to_milp,
    BooleanMiniZincLowerer().lower,
)


@pytest.mark.parametrize("consume", CONSUMERS)
def test_plain_consumers_reject_a_contradiction_hidden_in_native_parity(consume):
    formula = NativeXorCNFFormula(("x",), ((-1,),), ("zero",), (), ((1,),), ("one",))
    assert not any(formula.is_satisfied({"x": bit}) for bit in (0, 1))
    with pytest.raises(TypeError, match="native XOR.*CryptoMiniSatSolver.*expanded_cnf"):
        consume(formula)
    # An explicitly requested, lossless expansion is accepted.
    consume(formula.expanded_cnf())


def test_expansion_preserves_signed_parity_and_clause_provenance():
    formula = NativeXorCNFFormula(("a", "b"), ((1, 2),), ("clause",), (), ((1, -2),), ("xor",))
    expanded = SMTFormula.from_cnf(formula.expanded_cnf()).to_cnf()
    for bits in product((0, 1), repeat=2):
        assignment = dict(zip(formula.variables, bits))
        assert expanded.is_satisfied(assignment) == formula.is_satisfied(assignment)
    assert "xor" in expanded.provenance


@pytest.mark.parametrize("invalid", (object(),))
def test_plain_requirement_accepts_no_extra_constraints_and_rejects_wrong_types(invalid):
    _require_plain_cnf(CNFFormula((), (), ()))
    _require_plain_cnf(NativeXorCNFFormula((), (), ()))
    with pytest.raises(TypeError, match="CNFFormula"):
        _require_plain_cnf(invalid)
