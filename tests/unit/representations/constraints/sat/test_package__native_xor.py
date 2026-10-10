"""Native-XOR container, lowering, and exporter parity."""

from itertools import product

import pytest

from claasp.drivers.solvers import MinisatSolver
from claasp.primitives import Simon, Speck, ToySpeck
from claasp.primitives.single_component_primitives import ModularMultiply, ModularSubtract
from claasp.representations.constraints.sat import (
    BooleanCNFModel,
    BooleanNativeXorModel,
    CryptoMiniSatDimacsExporter,
    NativeXorCNFFormula,
    NWindowSATStrategy,
    WordDeterministicTruncatedNativeXorSATModel,
    WordDeterministicTruncatedSATModel,
    WordDifferentialNativeXorSATModel,
    WordDifferentialSATModel,
    WordLinearNativeXorSATModel,
    WordLinearSATModel,
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


@pytest.mark.parametrize(
    "primitive",
    (
        Speck(number_of_rounds=1),
        Simon(number_of_rounds=1),
        ModularMultiply(word_bit_size=4, number_of_inputs=3),
        ModularSubtract(word_bit_size=4, number_of_inputs=3),
    ),
)
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
        name: tuple(0 for _ in range(port.array_type.unit_count))
        for name, port in primitive.graph.input_ports.items()
    }
    evaluation = ScalarEvaluator().evaluate(primitive, inputs)
    assert native_formula.is_satisfied(native.witness(evaluation))
    assert ordinary_formula.is_satisfied(ordinary.witness(evaluation))


def test_cryptominisat_export_uses_documented_extended_dimacs_records():
    formula = NativeXorCNFFormula(("a", "b", "y"), ((1,),), ("fixed",), (), ((1, 2, -3),), ("xor",))
    text = CryptoMiniSatDimacsExporter().export(formula, include_variable_map=False)
    assert text == "p cnf 3 2\n1 0\nx1 2 -3 0\n"


@pytest.mark.parametrize(
    "ordinary,native,expected_native_count",
    (
        (
            WordDifferentialSATModel(
                ToySpeck(2),
                fixed_weight=1,
                nonzero_input="plaintext",
                fixed_input_differences={"key": 0},
            ),
            WordDifferentialNativeXorSATModel(
                ToySpeck(2),
                fixed_weight=1,
                nonzero_input="plaintext",
                fixed_input_differences={"key": 0},
            ),
            60,
        ),
        (
            WordLinearSATModel(
                ToySpeck(3),
                maximum_weight=1,
                nonzero_input="plaintext",
                fixed_inputs={"key": 0},
            ),
            WordLinearNativeXorSATModel(
                ToySpeck(3),
                maximum_weight=1,
                nonzero_input="plaintext",
                fixed_inputs={"key": 0},
            ),
            197,
        ),
    ),
)
def test_native_xor_trails_expand_exactly_to_ordinary_cnf(ordinary, native, expected_native_count):
    ordinary_formula = ordinary.cnf_formula()
    native_formula = native.cnf_formula()
    expanded = native_formula.expanded_cnf()
    canonical = lambda clauses: {frozenset(clause) for clause in clauses}
    assert native_formula.native_xor_count == expected_native_count
    assert canonical(expanded.clauses) == canonical(ordinary_formula.clauses)
    assert expanded.clause_count == ordinary_formula.clause_count


def test_native_xor_reencoding_composes_with_n_window_and_rejects_other_solvers():
    options = {
        "fixed_weight": 1,
        "nonzero_input": "plaintext",
        "fixed_input_differences": {"key": 0},
        "n_window": NWindowSATStrategy(1),
    }
    ordinary = WordDifferentialSATModel(ToySpeck(2), **options).cnf_formula()
    model = WordDifferentialNativeXorSATModel(ToySpeck(2), **options)
    native = model.cnf_formula()
    canonical = lambda clauses: {frozenset(clause) for clause in clauses}
    assert canonical(native.expanded_cnf().clauses) == canonical(ordinary.clauses)
    with pytest.raises(TypeError, match="CryptoMiniSatSolver"):
        model.enumerate_trails(MinisatSolver(), limit=1)


def test_native_xor_truncated_expansion_reconstructs_ordinary_cnf():
    options = {
        "fixed_input_patterns": {"plaintext": "00000001", "key": "0" * 16},
        "output_pattern": "???0????",
    }
    ordinary = WordDeterministicTruncatedSATModel(ToySpeck(2), **options).cnf_formula()
    model = WordDeterministicTruncatedNativeXorSATModel(ToySpeck(2), **options)
    native = model.cnf_formula()
    canonical = lambda clauses: {frozenset(clause) for clause in clauses}
    assert native.native_xor_count == 48
    assert native.clause_count == 733
    assert canonical(native.expanded_cnf().clauses) == canonical(ordinary.clauses)
    with pytest.raises(TypeError, match="CryptoMiniSatSolver"):
        model.enumerate_trails(MinisatSolver(), limit=1)
