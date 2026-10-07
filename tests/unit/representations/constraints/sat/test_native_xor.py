"""Native-XOR container, lowering, and exporter parity."""

from itertools import product

import pytest

from claasp.primitives import Simon, Speck
from claasp.representations.constraints.sat import (
    BooleanCNFModel,
    BooleanNativeXorModel,
    CryptoMiniSatDimacsExporter,
    NativeXorCNFFormula,
)
from claasp.representations.execution import ScalarEvaluator


def test_signed_native_xor_matches_its_independent_cnf_expansion():
    formula = NativeXorCNFFormula(
        ("a", "b", "c", "y"),
        ((1, -2),),
        ("ordinary",),
        (),
        ((1, -2, 3, -4),),
        ("parity",),
    )
    expanded = formula.expanded_cnf()
    for values in product((0, 1), repeat=4):
        assignment = dict(zip(formula.variables, values))
        assert formula.is_satisfied(assignment) == expanded.is_satisfied(assignment)


@pytest.mark.parametrize("primitive", (Speck(number_of_rounds=1), Simon(number_of_rounds=1)))
def test_native_xor_graph_lowering_matches_ordinary_cnf(primitive):
    ordinary = BooleanCNFModel(primitive)
    native = BooleanNativeXorModel(primitive)
    ordinary_formula = ordinary.cnf_formula()
    native_formula = native.cnf_formula()
    assert native_formula.native_xor_count > 0
    assert native_formula.clause_count < ordinary_formula.clause_count
    canonical = lambda clauses: {tuple(sorted(clause, key=abs)) for clause in clauses}
    assert canonical(native_formula.expanded_cnf().clauses) == canonical(ordinary_formula.clauses)

    inputs = {
        name: tuple(0 for _ in range(port.value_type.unit_count))
        for name, port in primitive.input_ports.items()
    }
    evaluation = ScalarEvaluator().evaluate(primitive, inputs)
    assert native_formula.is_satisfied(native.witness(evaluation))
    assert ordinary_formula.is_satisfied(ordinary.witness(evaluation))


def test_cryptominisat_export_uses_documented_extended_dimacs_records():
    formula = NativeXorCNFFormula(("a", "b", "y"), ((1,),), ("fixed",), (), ((1, 2, -3),), ("xor",))
    text = CryptoMiniSatDimacsExporter().export(formula, include_variable_map=False)
    assert text == "p cnf 3 2\n1 0\nx1 2 -3 0\n"
