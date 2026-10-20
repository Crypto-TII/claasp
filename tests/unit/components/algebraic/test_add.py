"""Addition and XOR share the same public operand calling convention."""

import pytest

from claasp import PrimitiveBuilder, UnitArrayType
from claasp.components import Add, ModularAdd, Xor
from claasp.unit_types import PrimeField, Word


@pytest.mark.parametrize("component_type, expected", [(Add, 4), (ModularAdd, 5), (Xor, 9)])
@pytest.mark.parametrize("style", ["arguments", "tuple", "list", "generator", "positional_id"])
def test_operand_calling_conventions_evaluate_identically(component_type, expected, style):
    word = UnitArrayType(PrimeField(17) if component_type is Add else Word(4), (1,))
    builder = PrimitiveBuilder("ThreeOperands", {name: word for name in "abc"})
    builder.add_round()
    operands = tuple(builder.input(name) for name in "abc")
    if style == "arguments":
        component = component_type(*operands, component_id="operation")
    elif style == "positional_id":
        component = component_type(operands, "operation")
    else:
        values = {"tuple": operands, "list": list(operands), "generator": iter(operands)}
        component = component_type(values[style], component_id="operation")
    output = builder.add_component(component)
    primitive = builder.build(output)
    assert primitive.evaluate(a=15, b=2, c=4) == expected
    assert component.component_id == "operation"


@pytest.mark.parametrize("component_type", [Add, ModularAdd, Xor])
def test_variadic_inputs_preserve_validation(component_type):
    word = UnitArrayType(Word(4), (1,))
    other = UnitArrayType(Word(8), (1,))
    builder = PrimitiveBuilder("Validation", {"a": word, "b": word, "c": other})
    a, b, c = (builder.input(name) for name in "abc")
    for operands in [(), (a,), ((a,),)]:
        with pytest.raises(ValueError, match="at least two inputs"):
            component_type(*operands)
    with pytest.raises(ValueError, match="identical array types"):
        component_type(a, c)
    with pytest.raises(TypeError, match="supplied twice"):
        component_type(a, b, "first", component_id="second")


def test_variadic_modular_add_preserves_explicit_modulus():
    word = UnitArrayType(Word(4), (1,))
    builder = PrimitiveBuilder("Modulo13", {"a": word, "b": word})
    builder.add_round()
    output = builder.add_component(ModularAdd(builder.input("a"), builder.input("b"), modulus=13))
    assert builder.build(output).evaluate(a=11, b=7) == 5
