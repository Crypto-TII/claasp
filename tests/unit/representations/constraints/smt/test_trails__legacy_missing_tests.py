"""Current-legacy test additions reviewed against the typed v5 boundary."""

from claasp.primitives import Speck
from claasp.representations.constraints.sat import CNFFormula
from claasp.representations.constraints.smt import SMTFormula, WordDeterministicTruncatedSMTModel


def test_standard_speck_truncated_model_is_supported_instead_of_the_legacy_stub():
    # The current legacy regression asserts NotImplementedError here. v5 has
    # an actual implementation, so retaining that assertion would regress it.
    formula = WordDeterministicTruncatedSMTModel(
        Speck(number_of_rounds=2),
        fixed_input_patterns={"key": "0" * 64},
        nonzero_input="plaintext",
    ).smt_formula()
    assert formula.assertion_count > 0
    assert formula.variables


def test_typed_smt_boundary_preserves_boolean_literals_and_assertion_labels():
    cnf = CNFFormula(("a", "b"), ((1, -2), (-1, 2)), ("left", "right"))
    smt = SMTFormula.from_cnf(cnf)
    assert smt.variables == cnf.variables
    assert smt.assertions == cnf.clauses
    assert smt.provenance == cnf.provenance
