from itertools import product

import pytest

from claasp_next import bits_from_int
from claasp_next.representations.constraints.sat import BooleanCNFModel, CNFFormula
from claasp_next.representations.constraints.sat.exporters import DimacsExporter
from claasp_next.primitives import MiMC, Present80, Speck
from claasp_next.components import Add
from claasp_next.graph import Primitive, ValueType
from claasp_next.domains import Bit
from claasp_next.representations.execution import ScalarEvaluator


def _xor_primitive(operand_count=2):
    primitive = Primitive("xor", {name: ValueType(Bit(), (1,)) for name in "abc"[:operand_count]})
    primitive.add_round()
    output = primitive.add_component(Add(
        tuple(primitive.input(name) for name in "abc"[:operand_count]), component_id="sum"
    ))
    primitive.set_output(output)
    return primitive


def test_xor_cnf_has_exact_truth_table():
    formula = BooleanCNFModel(_xor_primitive()).cnf_formula()
    assert formula.variable_count == 3
    assert formula.clause_count == 4
    for left, right, output in product((0, 1), repeat=3):
        assignment = {"a_0": left, "b_0": right, "sum_0": output}
        assert formula.is_satisfied(assignment) is (output == left ^ right)


def test_multi_operand_xor_witness_includes_auxiliaries():
    primitive = _xor_primitive(3)
    model = BooleanCNFModel(primitive)
    result = ScalarEvaluator().evaluate(primitive, {"a": (1,), "b": (1,), "c": (1,)})
    witness = model.witness(result)
    assert witness["__aux_sum_0_1"] == 0
    assert model.cnf_formula().is_satisfied(witness)


def test_present_scalar_execution_produces_satisfying_cnf_witness():
    primitive = Present80(number_of_rounds=1)
    inputs = {"plaintext": bits_from_int(0x0123456789ABCDEF, 64), "key": bits_from_int(0, 80)}
    result = ScalarEvaluator().evaluate(primitive, inputs)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    witness = model.witness(result)
    assert formula.is_satisfied(witness)

    wrong = dict(witness)
    wrong["sbox_1_0_0"] ^= 1
    assert not formula.is_satisfied(wrong)


def test_word_arx_execution_produces_satisfying_cnf_witness():
    primitive = Speck(number_of_rounds=1)
    inputs = {
        "plaintext": (0x6574, 0x694C),
        "key": (0x1918, 0x1110, 0x0908, 0x0100),
    }
    evaluation = ScalarEvaluator().evaluate(primitive, inputs)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()

    assert formula.is_satisfied(model.witness(evaluation))
    assert "plaintext_0_0" in formula.variables
    assert "plaintext_1_15" in formula.variables


def test_non_boolean_encodable_graph_is_rejected_explicitly():
    with pytest.raises(ValueError, match="requires the Bit or Word domain"):
        BooleanCNFModel(MiMC(17, 3, (1,))).cnf_formula()


def test_unsupported_bit_component_is_rejected_explicitly():
    from claasp_next.components import Multiply

    primitive = Primitive("and", {"x": ValueType(Bit(), (1,)), "y": ValueType(Bit(), (1,))})
    primitive.add_round()
    primitive.add_component(Multiply(
        (primitive.input("x"), primitive.input("y")), component_id="product"
    ))
    with pytest.raises(NotImplementedError, match="Multiply"):
        BooleanCNFModel(primitive).cnf_formula()


def test_dimacs_export_is_deterministic_and_preserves_variable_map():
    formula = CNFFormula(("left", "out"), ((-1, 2), (1, -2)), ("wire", "wire"))
    exported = DimacsExporter().export(formula)
    assert exported == "c 1 left\nc 2 out\np cnf 2 2\n-1 2 0\n1 -2 0\n"
    assert DimacsExporter().export(formula, include_variable_map=False).startswith("p cnf 2 2\n")


def test_cnf_rejects_incomplete_assignments_and_invalid_literals():
    formula = CNFFormula(("x",), ((1,),), ("constant",))
    with pytest.raises(ValueError, match="missing"):
        formula.is_satisfied({})
    with pytest.raises(ValueError, match="undeclared"):
        CNFFormula(("x",), ((2,),), ("bad",))
