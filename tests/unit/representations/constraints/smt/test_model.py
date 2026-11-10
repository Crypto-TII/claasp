"""Boolean conversion preserves every named clause and encoding declaration."""

from itertools import product

from claasp.representations.constraints import ConstraintModelApplication
from claasp.representations.constraints.sat import CNFFormula, WordXorLinearSATModel
from claasp.representations.constraints.smt import SMTFormula


def test_boolean_roundtrip_preserves_truth_table_and_provenance():
    records = (ConstraintModelApplication(WordXorLinearSATModel.model_provenance),)
    original = SMTFormula(
        ("a", "b", "c"), ((1, -2), (3,), (-1, 2, 3)), ("left", "right", "third"), records
    )
    converted = original.to_cnf()
    assert type(converted) is CNFFormula
    assert converted.variables == original.variables
    assert converted.clauses == original.assertions
    assert converted.provenance == original.provenance
    assert converted.constraint_models == records
    assert SMTFormula.from_cnf(converted) == original
    for bits in product((0, 1), repeat=3):
        assignment = dict(zip(original.variables, bits))
        expected = all(
            any(bool(bits[abs(literal) - 1]) == (literal > 0) for literal in clause)
            for clause in original.assertions
        )
        assert converted.is_satisfied(assignment) == expected
