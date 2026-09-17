import pytest

from claasp_next import CompositeBuilder, Primitive, PrimeField, ValueType
from claasp_next.components import Add


def _double_then_add_definition():
    value_type = ValueType(PrimeField(17), (1,))
    builder = CompositeBuilder("DoubleThenAdd", {"value": value_type, "addend": value_type})
    value, addend = builder.inputs("value", 1)
    builder.add_round()
    doubled = builder.add_component(
        Add((value, value), component_id="double")
    )
    output = builder.add_component(Add((doubled, addend), component_id="sum"))
    builder.set_output("doubled", doubled)
    builder.set_output("output", output)
    return builder.build(provenance={"source": "test construction"})


def test_definition_is_immutable_and_projects_to_an_ordinary_primitive():
    definition = _double_then_add_definition()
    assert definition.evaluate(5, 4) == 14
    assert definition.evaluate(5, 4, output="doubled") == 10
    assert definition.provenance == (("source", "test construction"),)
    with pytest.raises(AttributeError):
        definition.name = "changed"


def test_instantiation_lowers_namespaced_leaves_and_retains_scope_outputs():
    definition = _double_then_add_definition()
    value_type = ValueType(PrimeField(17), (1,))
    primitive = Primitive("parent", {"left": value_type, "right": value_type})
    primitive_round = primitive.add_round()
    instance = primitive.add_composite(
        definition,
        {"value": primitive.input("left"), "addend": primitive.input("right")},
        scope_id="block",
    )
    primitive.set_output(instance.output())

    assert tuple(component.component_id for component in primitive.components) == (
        "block/double", "block/sum"
    )
    assert primitive.scope("block") is instance
    assert primitive_round.scopes == (instance,)
    assert instance.output("doubled").source.owner_id == "block/double"
    assert instance.output[0].source.owner_id == "block/double"
    assert instance.output[1].source.owner_id == "block/sum"
    assert primitive.evaluate(5, 4) == 14
    assert instance.evaluate(5, 4) == 14


def test_nested_scopes_survive_flat_lowering_with_deterministic_paths():
    child = _double_then_add_definition()
    value_type = ValueType(PrimeField(17), (1,))
    builder = CompositeBuilder("ParentBlock", {"left": value_type, "right": value_type})
    builder.add_round()
    nested = builder.add_composite(
        child,
        {"value": builder.input("left"), "addend": builder.input("right")},
        scope_id="inner",
    )
    builder.set_output("output", nested.output())
    parent = builder.build()

    primitive = Primitive("outer", {"left": value_type, "right": value_type})
    primitive.add_round()
    outer = primitive.add_composite(
        parent,
        {"left": primitive.input("left"), "right": primitive.input("right")},
        scope_id="outer_block",
    )
    primitive.set_output(outer.output())

    assert primitive.scope("outer_block/inner").path == "outer_block/inner"
    assert outer.scope("inner").component_ids == (
        "outer_block/inner/double", "outer_block/inner/sum"
    )
    assert primitive.evaluate(7, 1) == 15


def test_composite_bindings_are_exact_and_typed():
    definition = _double_then_add_definition()
    primitive = Primitive("bad", {"value": ValueType(PrimeField(19), (1,))})
    primitive.add_round()
    with pytest.raises(ValueError, match="bindings do not match"):
        primitive.add_composite(definition, {"value": primitive.input("value")})
    with pytest.raises(ValueError, match="has type"):
        primitive.add_composite(
            definition,
            {"value": primitive.input("value"), "addend": primitive.input("value")},
        )
