from itertools import product

import pytest

from claasp import bits_from_int
from claasp.components import Add
from claasp.components import ModularMultiply as ModularMultiplyComponent
from claasp.domains import Bit, Word
from claasp.graph import ArrayType, Primitive
from claasp.primitives import MiMC, Present80, Simon, Speck
from claasp.primitives.single_component_primitives import (
    BitwiseNot,
    BitwiseOr,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Shift,
    VariableRotate,
    VariableShift,
)
from claasp.representations.constraints.sat import BooleanCNFModel, CNFFormula
from claasp.representations.constraints.sat.exporters import DimacsExporter
from claasp.representations.execution import ScalarEvaluator


def _xor_primitive(operand_count=2):
    primitive = Primitive("xor", {name: ArrayType(Bit(), (1,)) for name in "abc"[:operand_count]})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        Add(
            tuple(primitive.graph.input(name) for name in "abc"[:operand_count]), component_id="sum"
        )
    )
    primitive._builder.set_output(output)
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
    evaluation = ScalarEvaluator().evaluate(
        primitive,
        {
            "plaintext": (0x6565, 0x6877),
            "key": (0x1918, 0x1110, 0x0908, 0x0100),
        },
    )
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    witness = model.witness(evaluation)
    assert formula.is_satisfied(witness)
    and_component = next(
        item for item in primitive.graph.components if type(item).__name__ == "BitwiseAnd"
    )
    changed = dict(witness)
    changed[f"{and_component.component_id}_0_0"] ^= 1
    assert not formula.is_satisfied(changed)


@pytest.mark.parametrize(
    ("primitive", "inputs"),
    (
        (BitwiseOr(8, 3), (0x81, 0x24, 0x18)),
        (BitwiseNot(8), (0xA5,)),
        (Shift(8, 3, "left"), (0xA5,)),
        (Shift(8, 3, "right"), (0xA5,)),
        (Shift(8, 12, "left"), (0xA5,)),
    ),
)
def test_additional_legacy_word_operations_have_exact_functional_witnesses(primitive, inputs):
    evaluation = primitive.evaluate_with_trace(*inputs)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    witness = model.witness(evaluation)
    assert formula.is_satisfied(witness)
    output_name = next(
        name
        for name in formula.variables
        if name.startswith("bitwise_") or name.startswith("shift_")
    )
    changed = dict(witness)
    changed[output_name] ^= 1
    assert not formula.is_satisfied(changed)


def test_multi_operand_modular_subtract_witnesses_are_exhaustive_at_three_bits():
    primitive = ModularSubtract(word_bit_size=3, number_of_inputs=3)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for left, middle, right in product(range(8), repeat=3):
        evaluation = primitive.evaluate_with_trace(left, middle, right)
        witness = model.witness(evaluation)
        assert primitive.evaluate(left, middle, right) == (left - middle - right) % 8
        assert formula.is_satisfied(witness)
        changed = dict(witness)
        changed["modular_subtract_0_0_0_0"] ^= 1
        assert not formula.is_satisfied(changed)


@pytest.mark.parametrize(
    "primitive",
    (
        VariableRotate(bit_size=5, amount_bit_size=3, direction="left"),
        VariableRotate(bit_size=5, amount_bit_size=3, direction="right"),
        VariableShift(bit_size=5, amount_bit_size=3, direction="left"),
        VariableShift(bit_size=5, amount_bit_size=3, direction="right"),
    ),
)
def test_variable_shift_and_rotation_witnesses_are_exhaustive(primitive):
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for value, amount in product(range(32), range(8)):
        evaluation = primitive.evaluate_with_trace(value, amount)
        witness = model.witness(evaluation)
        assert formula.is_satisfied(witness)
        changed = dict(witness)
        output_name = next(name for name in formula.variables if name.startswith("variable_"))
        changed[output_name] ^= 1
        assert not formula.is_satisfied(changed)


def test_legacy_three_input_or_relation_retains_the_complete_truth_table():
    from claasp.components import BitVectorSBox

    primitive = Primitive("or_lookup", {"x": ArrayType(Bit(), (3,))})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        BitVectorSBox(primitive.graph.input("x"), (0, 1, 1, 1, 1, 1, 1, 1), component_id="or")
    )
    primitive._builder.set_output(output)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for input_value, output_value in product(range(8), repeat=2):
        assignment = {
            f"{prefix}_{bit}": (value >> (2 - bit)) & 1
            for prefix, value in (("x", input_value), ("or", output_value))
            for bit in range(3)
        }
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


def test_bit_multiply_witnesses_are_exhaustive():
    primitive = Multiply(unit_count=3, number_of_inputs=3)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for operands in product(range(8), repeat=3):
        evaluation = primitive.evaluate_with_trace(*operands)
        witness = model.witness(evaluation)
        assert formula.is_satisfied(witness)


def test_modular_multiply_witnesses_are_exhaustive_at_three_bits():
    primitive = ModularMultiply(word_bit_size=3, number_of_inputs=3)
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    for operands in product(range(8), repeat=3):
        evaluation = primitive.evaluate_with_trace(*operands)
        witness = model.witness(evaluation)
        assert primitive.evaluate(*operands) == operands[0] * operands[1] * operands[2] % 8
        assert formula.is_satisfied(witness)
        changed = dict(witness)
        changed["modular_multiply_0_0_0_0"] ^= 1
        assert not formula.is_satisfied(changed)


def test_non_power_of_two_modular_multiply_is_rejected_explicitly():
    primitive = Primitive(
        "modmul_13", {name: ArrayType(Word(4), (1,)) for name in ("left", "right")}
    )
    primitive._builder.add_round()
    primitive._builder.set_output(
        primitive._builder.add_component(
            ModularMultiplyComponent(primitive.graph.inputs(), modulus=13, component_id="product")
        )
    )
    with pytest.raises(NotImplementedError, match=r"modulus 2\*\*word_width"):
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
