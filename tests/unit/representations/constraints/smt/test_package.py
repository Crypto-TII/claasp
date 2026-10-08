import pytest

from claasp import Bit, Primitive, ValueType
from claasp.components import Add
from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.representations.constraints.smt import BooleanSMTModel, SMTFormula
from claasp.representations.constraints.smt.exporter import SMTLibExporter


def _xor_primitive():
    primitive = Primitive("xor", {"x": ValueType(Bit(), (1,)), "y": ValueType(Bit(), (1,))})
    primitive._builder.add_round()
    primitive._builder.set_output(
        primitive._builder.add_component(
            Add((primitive.graph.input("x"), primitive.graph.input("y")))
        )
    )
    return primitive


def test_boolean_smt_lowering_and_export_are_deterministic():
    formula = BooleanSMTModel(_xor_primitive()).smt_formula()
    text = SMTLibExporter().export(formula)

    assert formula.assertion_count == 4
    assert "(declare-fun x_0 () Bool)" in text
    assert "(assert (or (not x_0) (not y_0)" in text
    assert text.endswith("(get-value (x_0 y_0 add_0_0_0))\n")


def test_smt_formula_reuses_validated_boolean_literal_contract():
    with pytest.raises(ValueError, match="undeclared"):
        SMTFormula(("x",), ((2,),), ("bad",))


def test_z3_output_parser_maps_named_values_and_unsat():
    assert Z3Solver._parse_output("sat\n((x true)\n (y false))\n", ("x", "y"))[1] == {
        "x": 1,
        "y": 0,
    }
    assert Z3Solver._parse_output("unsat\n", ("x",)) == (
        SatStatus.UNSATISFIABLE,
        None,
    )
