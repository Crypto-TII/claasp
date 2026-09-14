import pytest

from claasp_next.primitives import Speck
from claasp_next.drivers.solvers.minizinc import (
    CPEnumerationResult, CPStatus, _parse_all_output, _parse_output,
)
from claasp_next.representations.constraints.cp import (
    BooleanMiniZincLowerer, MiniZincModel, SpeckDifferentialCPModel,
)
from claasp_next.representations.constraints.sat import CNFFormula
from claasp_next.semantics import XOR_DIFFERENTIAL
from claasp_next.semantics.cryptanalysis import PropagationProblem


def test_minizinc_model_serializes_sections_in_language_order():
    model = MiniZincModel(
        includes=('include "alldifferent.mzn";',),
        declarations=("var 0..3: x;",),
        constraints=("constraint x = 2;",),
        solve="solve minimize x;",
        outputs=('output ["x=", show(x)];',),
        provenance=("unit fixture",),
    )

    assert model.source() == (
        'include "alldifferent.mzn";\n'
        "var 0..3: x;\n"
        "constraint x = 2;\n"
        "solve minimize x;\n"
        'output ["x=", show(x)];\n'
    )


def test_minizinc_json_and_terminal_statuses_are_backend_neutral():
    assert _parse_output('{\n  "x": 2, "bits": [0, 1]\n}\n----------\n') == (
        CPStatus.SATISFIED,
        {"x": 2, "bits": [0, 1]},
    )
    assert _parse_output("=====UNSATISFIABLE=====\n") == (CPStatus.UNSATISFIABLE, None)
    assert _parse_output("=====UNKNOWN=====\n") == (CPStatus.UNKNOWN, None)


def test_minizinc_all_solution_parser_requires_exhaustion_for_proof():
    complete = _parse_all_output(
        '{"x": false}\n----------\n{"x": true}\n----------\n==========\n'
    )
    partial = _parse_all_output('{"x": false}\n----------\n=====UNKNOWN=====\n')

    assert complete == (
        CPStatus.SATISFIED, ({"x": False}, {"x": True}), True, "exhausted"
    )
    assert partial == (CPStatus.UNKNOWN, ({"x": False},), False, "unknown")
    result = CPEnumerationResult(
        partial[0], partial[1], partial[2], partial[3], 0.1, "test", "", ""
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()


def test_minizinc_all_solution_parser_preserves_completed_unsat():
    assert _parse_all_output("=====UNSATISFIABLE=====\n") == (
        CPStatus.UNSATISFIABLE, (), True, "exhausted_unsat"
    )


def test_minizinc_model_and_driver_validate_public_boundaries():
    with pytest.raises(ValueError, match="solve item"):
        MiniZincModel((), (), "satisfy;")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        _parse_output("not-json\n----------\n")


def test_boolean_lowering_preserves_cnf_names_signs_and_provenance():
    formula = CNFFormula(
        ("left_0", "right_0"),
        ((1, -2), (-1, 2)),
        ("forward", "backward"),
    )

    model = BooleanMiniZincLowerer().lower(formula)

    assert model.declarations == ("var bool: v_left_0;", "var bool: v_right_0;")
    assert model.constraints == (
        "constraint v_left_0 \\/ not v_right_0;",
        "constraint not v_left_0 \\/ v_right_0;",
    )
    assert model.provenance == formula.provenance
    assert model.name_mapping == (("v_left_0", "left_0"), ("v_right_0", "right_0"))


def test_speck_differential_cp_lowering_has_exact_relation_and_bound():
    primitive = Speck(number_of_rounds=5)
    lowered = SpeckDifferentialCPModel(PropagationProblem(
        primitive, XOR_DIFFERENTIAL, maximum_weight=9,
        provenance=("legacy Speck32/64-5 optimum",),
    )).cp_model()

    assert "predicate modular_addition_xor_difference" in lowered.declarations[0]
    assert sum("modular_addition_xor_difference" in item for item in lowered.constraints) == 5
    assert lowered.constraints[-1].endswith("<= 9;")
    assert lowered.provenance == ("legacy Speck32/64-5 optimum",)
