import pytest

from claasp import ArrayType, CompositeBuilder, Primitive
from claasp.components import Add
from claasp.domains import PrimeField


def _double_then_add_definition():
    array_type = ArrayType(PrimeField(17), (1,))
    builder = CompositeBuilder("DoubleThenAdd", {"value": array_type, "addend": array_type})
    value, addend = builder.inputs("value", 1)
    builder.add_round()
    doubled = builder.add_component(Add((value, value), component_id="double"))
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
    array_type = ArrayType(PrimeField(17), (1,))
    primitive = Primitive("parent", {"left": array_type, "right": array_type})
    primitive_round = primitive._builder.add_round()
    instance = primitive._builder.add_composite(
        definition,
        {"value": primitive.graph.input("left"), "addend": primitive.graph.input("right")},
        scope_id="block",
    )
    primitive._builder.set_output(instance.output())

    assert tuple(component.component_id for component in primitive.graph.components) == (
        "block/double",
        "block/sum",
    )
    assert primitive.graph.scope("block") is instance
    assert primitive_round.scopes == (instance,)
    assert instance.output("doubled").source.owner_id == "block/double"
    assert instance.output[0].source.owner_id == "block/double"
    assert instance.output[1].source.owner_id == "block/sum"
    assert primitive.evaluate(5, 4) == 14
    assert instance.evaluate(5, 4) == 14


def test_nested_scopes_survive_flat_lowering_with_deterministic_paths():
    child = _double_then_add_definition()
    array_type = ArrayType(PrimeField(17), (1,))
    builder = CompositeBuilder("ParentBlock", {"left": array_type, "right": array_type})
    builder.add_round()
    nested = builder.add_composite(
        child,
        {"value": builder.input("left"), "addend": builder.input("right")},
        scope_id="inner",
    )
    builder.set_output("output", nested.output())
    parent = builder.build()

    primitive = Primitive("outer", {"left": array_type, "right": array_type})
    primitive._builder.add_round()
    outer = primitive._builder.add_composite(
        parent,
        {"left": primitive.graph.input("left"), "right": primitive.graph.input("right")},
        scope_id="outer_block",
    )
    primitive._builder.set_output(outer.output())

    assert primitive.graph.scope("outer_block/inner").path == "outer_block/inner"
    assert outer.scope("inner").component_ids == (
        "outer_block/inner/double",
        "outer_block/inner/sum",
    )
    assert primitive.evaluate(7, 1) == 15


def test_composite_bindings_are_exact_and_typed():
    definition = _double_then_add_definition()
    primitive = Primitive("bad", {"value": ArrayType(PrimeField(19), (1,))})
    primitive._builder.add_round()
    with pytest.raises(ValueError, match="bindings do not match"):
        primitive._builder.add_composite(definition, {"value": primitive.graph.input("value")})
    with pytest.raises(ValueError, match="has type"):
        primitive._builder.add_composite(
            definition,
            {"value": primitive.graph.input("value"), "addend": primitive.graph.input("value")},
        )
