from itertools import product

import pytest

from claasp_next import bits_from_int
from claasp_next.representations.constraints.sat import BooleanCNFModel, CNFFormula
from claasp_next.representations.constraints.sat.exporters import DimacsExporter
from claasp_next.primitives import MiMC, Present80, Simon, Speck
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


def test_simon_and_rotation_graph_has_an_independently_checked_cnf_witness():
    primitive = Simon(number_of_rounds=3)
    evaluation = ScalarEvaluator().evaluate(primitive, {
        "plaintext": (0x6565, 0x6877), "key": (0x1918, 0x1110, 0x0908, 0x0100),
    })
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    witness = model.witness(evaluation)
    assert formula.is_satisfied(witness)
    and_component = next(item for item in primitive.components if type(item).__name__ == "BitwiseAnd")
    changed = dict(witness)
    changed[f"{and_component.component_id}_0_0"] ^= 1
    assert not formula.is_satisfied(changed)


def test_legacy_three_input_or_relation_retains_the_complete_truth_table():
    from claasp_next.components import BitVectorSBox
    primitive = Primitive("or_lookup", {"x": ValueType(Bit(), (3,))})
    primitive.add_round()
    output = primitive.add_component(BitVectorSBox(primitive.input("x"),
        (0, 1, 1, 1, 1, 1, 1, 1), component_id="or"))
    primitive.set_output(output)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for input_value, output_value in product(range(8), repeat=2):
        assignment = {f"{prefix}_{bit}": (value >> (2 - bit)) & 1
                      for prefix, value in (("x", input_value), ("or", output_value))
                      for bit in range(3)}
        assert formula.is_satisfied(assignment) is (output_value == int(input_value != 0))


def test_legacy_xor_sequence_preserves_all_three_operand_assignments():
    primitive = _xor_primitive(3)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for a, b, c in product((0, 1), repeat=3):
        evaluation = ScalarEvaluator().evaluate(primitive, {"a": (a,), "b": (b,), "c": (c,)})
        witness = model.witness(evaluation)
        assert witness["sum_0"] == a ^ b ^ c
        assert formula.is_satisfied(witness)
        changed = dict(witness)
        changed["sum_0"] ^= 1
        assert not formula.is_satisfied(changed)


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
