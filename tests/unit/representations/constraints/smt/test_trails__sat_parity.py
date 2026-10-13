"""Exact SAT/SMT parity for the shared word-level Boolean formulations."""

from claasp.primitives import ToySpeck
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel
from claasp.representations.constraints.smt import WordDifferentialSMTModel, WordLinearSMTModel


def _assert_same_formula(smt_formula, sat_formula):
    assert sat_formula.variables == smt_formula.variables
    assert sat_formula.clauses == smt_formula.assertions
    assert sat_formula.provenance == smt_formula.provenance


def test_word_differential_sat_is_exact_cnf_view_of_smt():
    options = {
        "fixed_weight": 1,
        "nonzero_input": "plaintext",
        "fixed_input_differences": {"key": 0},
    }
    primitive = ToySpeck(2)
    smt = WordDifferentialSMTModel(primitive, **options).smt_formula()
    sat = WordDifferentialSATModel(primitive, **options).cnf_formula()
    _assert_same_formula(smt, sat)


def test_word_linear_sat_is_exact_cnf_view_of_smt():
    options = {
        "maximum_weight": 2,
        "nonzero_input": "plaintext",
        "fixed_input_masks": {"key": 0},
        "fixed_inputs": {"key": 0},
    }
    primitive = ToySpeck(2)
    smt = WordLinearSMTModel(primitive, **options).smt_formula()
    sat = WordLinearSATModel(primitive, **options).cnf_formula()
    _assert_same_formula(smt, sat)
