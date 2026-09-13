import pytest

from claasp_next import Bit, Cipher, ValueType
from claasp_next.components import Add
from claasp_next.drivers.solvers import SatStatus
from claasp_next.representations.constraints.smt import BooleanSMTModel, SMTFormula
from claasp_next.representations.constraints.smt.exporter import SMTLibExporter
from claasp_next.drivers.solvers import Z3Solver


def _xor_cipher():
    cipher = Cipher("xor", {"x": ValueType(Bit(), (1,)), "y": ValueType(Bit(), (1,))})
    cipher.add_round()
    cipher.set_output(cipher.add_component(Add((cipher.input("x"), cipher.input("y")))))
    return cipher


def test_boolean_smt_lowering_and_export_are_deterministic():
    formula = BooleanSMTModel(_xor_cipher()).smt_formula()
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
