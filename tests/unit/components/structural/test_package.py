import pytest

from claasp import Bit, PrimeField, Primitive, ScalarEvaluator, ValueType
from claasp.components import Constant, Identity, Permutation


@pytest.mark.parametrize(
    "domain,values",
    [
        (Bit(), (0, 1, 1)),
        (PrimeField(17), (3, 12, 16)),
    ],
)
def test_same_permutation_operates_on_different_domains(domain, values):
    value_type = ValueType(domain, (3,))
    primitive = Primitive("permutation", {"state": value_type})
    primitive._builder.add_round()
    permutation = Permutation(primitive.input("state"), (2, 0, 1), component_id="permutation_0_0")
    primitive._builder.add_component(permutation)

    result = ScalarEvaluator().evaluate(primitive, {"state": values})

    assert result.value_of("permutation_0_0") == (values[2], values[0], values[1])
    assert result.output is None


def test_selection_identity_and_concatenation_use_logical_units():
    field = PrimeField(257)
    state_type = ValueType(field, (4,))
    primitive = Primitive("selection", {"state": state_type})
    primitive._builder.add_round()
    high = Identity(primitive.input("state")[3, 2], component_id="identity_0_0")
    low = Identity(primitive.input("state")[1, 0], component_id="identity_0_1")
    high_port = primitive._builder.add_component(high)
    low_port = primitive._builder.add_component(low)
    joined = primitive._builder.join(high_port, low_port)
    primitive._builder.set_output(joined)

    result = ScalarEvaluator().evaluate(primitive, {"state": (10, 20, 30, 40)})

    assert result.output == (40, 30, 20, 10)
    assert len(primitive.components) == 2
    assert len(primitive.bindings) == 1


def test_primitive_output_accepts_multi_source_structural_wiring():
    field = PrimeField(257)
    primitive = Primitive(
        "wired_output",
        {
            "left": ValueType(field, (2,)),
            "right": ValueType(field, (2,)),
        },
    )
    primitive._builder.add_round()
    primitive._builder.set_output((primitive.input("left"), primitive.input("right")[1, 0]))

    assert primitive.evaluate((1, 2), (3, 4)) == (1, 2, 4, 3)
    assert primitive.components == ()
    assert len(primitive.bindings) == 1


def test_join_keeps_one_source_as_wiring_and_normalizes_multiple_sources():
    field = PrimeField(17)
    primitive = Primitive("wiring", {"state": ValueType(field, (2,))})
    primitive._builder.add_round()
    state = primitive.input("state")

    assert primitive._builder.join(state).source == state
    joined = primitive._builder.join(state[1], state[0])
    assert joined.owner_id == "__join_0"
    with pytest.raises(ValueError, match="at least one"):
        primitive._builder.join()


def test_structural_binding_resolution_is_not_limited_by_python_recursion_depth():
    primitive = Primitive("deep_wiring", {"state": ValueType(Bit(), (1,))})
    primitive._builder.add_round()
    state = primitive.input("state")
    for _ in range(1_100):
        state = primitive._builder.view(state)
    primitive._builder.set_output(state)

    assert primitive.evaluate(1) == 1


def test_constant_has_no_graph_inputs_and_is_domain_checked():
    field = PrimeField(17)
    primitive = Primitive("constant", {"state": ValueType(field, (1,))})
    primitive._builder.add_round()
    constant = Constant(ValueType(field, (3,)), (1, 2, 16), component_id="constant_0_0")
    primitive._builder.add_component(constant)

    result = ScalarEvaluator().evaluate(primitive, {"state": (0,)})

    assert result.value_of("constant_0_0") == (1, 2, 16)

    with pytest.raises(ValueError, match="canonical element"):
        Constant(ValueType(field, (1,)), (17,), component_id="bad")


def test_scalar_evaluator_validates_primitive_inputs():
    primitive = Primitive("typed", {"state": ValueType(Bit(), (2,))})

    with pytest.raises(ValueError, match="requires 2 logical units"):
        ScalarEvaluator().evaluate(primitive, {"state": (1,)})

    with pytest.raises(ValueError, match="canonical element"):
        ScalarEvaluator().evaluate(primitive, {"state": (0, 2)})


def test_scalar_evaluator_rejects_unsupported_base_component():
    from claasp import Component

    value_type = ValueType(Bit(), (1,))
    primitive = Primitive("unsupported", {"state": value_type})
    primitive._builder.add_round()
    primitive._builder.add_component(
        Component("unknown_0_0", (primitive.input("state").select_all(),), value_type)
    )

    with pytest.raises(NotImplementedError, match="does not support Component"):
        ScalarEvaluator().evaluate(primitive, {"state": (0,)})
