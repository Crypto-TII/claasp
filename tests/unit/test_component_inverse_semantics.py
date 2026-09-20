import itertools

import pytest

from claasp import (
    BinaryExtensionField,
    Bit,
    PrimeField,
    Primitive,
    TransformationError,
    TransformationFailureReason,
    ValueType,
    Word,
    invert_component,
)
from claasp.components import (
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    FeedbackRegister,
    FeedbackRegisterSpec,
    FeedbackTerm,
    IDEAMultiply,
    LinearMap,
    ModularAdd,
    ModularSubtract,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    Xor,
)


def test_permutation_and_rotation_inverse_semantics_are_independent_components():
    source = Primitive("source", {"bits": ValueType(Bit(), (4,)), "word": ValueType(Word(8), (1,))})
    permutation = Permutation(source.input("bits"), (2, 0, 3, 1), "authored")
    rotation = Rotate(source.input("word"), 3, "left", "authored_rotate")
    destination = Primitive(
        "destination", {"bits": ValueType(Bit(), (4,)), "word": ValueType(Word(8), (1,))}
    )

    inverse_permutation = invert_component(permutation, destination.input("bits"), recover_input=0)
    inverse_rotation = invert_component(rotation, destination.input("word"), recover_input=0)

    assert inverse_permutation.mapping == (1, 3, 0, 2)
    assert inverse_rotation.direction == "right"
    assert inverse_permutation.component_id is inverse_rotation.component_id is None


@pytest.mark.parametrize("component_type", (SBox, BitVectorSBox))
def test_bijective_substitution_inverse_round_trips_exhaustively(component_type):
    value_type = ValueType(Word(2), (1,)) if component_type is SBox else ValueType(Bit(), (2,))
    source = Primitive("source", {"x": value_type})
    component = component_type(source.input("x"), (2, 0, 3, 1))
    destination = Primitive("destination", {"y": component.output_type})
    destination.add_round()
    inverse = destination.add_component(
        invert_component(component, destination.input("y"), recover_input=0)
    )
    destination.set_output(inverse)

    for value in range(4):
        forward = component.table[value]
        recovered = destination.evaluate(forward)
        assert recovered == value


def test_linear_and_binary_affine_inverse_round_trip_independent_evaluation():
    bit_graph = Primitive("linear", {"x": ValueType(Bit(), (3,))})
    linear = LinearMap(bit_graph.input("x"), ((1, 1, 0), (0, 1, 1), (1, 1, 1)))
    inverse_graph = Primitive("linear_inverse", {"y": linear.output_type})
    inverse_graph.add_round()
    inverse_graph.set_output(
        inverse_graph.add_component(
            invert_component(linear, inverse_graph.input("y"), recover_input=0)
        )
    )

    for bits in itertools.product((0, 1), repeat=3):
        forward = tuple(
            sum(coefficient & value for coefficient, value in zip(row, bits)) & 1
            for row in linear.matrix
        )
        assert (
            inverse_graph._decode_boundary(
                inverse_graph.evaluate(forward), inverse_graph.output.value_type
            )
            == bits
        )

    field = BinaryExtensionField(4, 0b10011)
    affine_source = Primitive("affine", {"x": ValueType(field, (1,))})
    affine = BinaryAffineMap(
        affine_source.input("x"),
        ((1, 1, 0, 0), (0, 1, 1, 0), (0, 0, 1, 1), (0, 0, 0, 1)),
        0b1010,
    )
    affine_inverse = Primitive("affine_inverse", {"y": affine.output_type})
    affine_inverse.add_round()
    affine_inverse.set_output(
        affine_inverse.add_component(
            invert_component(affine, affine_inverse.input("y"), recover_input=0)
        )
    )
    forward_graph = Primitive("affine_forward", {"x": ValueType(field, (1,))})
    forward_graph.add_round()
    forward_graph.set_output(
        forward_graph.add_component(
            BinaryAffineMap(forward_graph.input("x"), affine.matrix, affine.offset)
        )
    )
    for value in range(16):
        assert affine_inverse.evaluate(forward_graph.evaluate(value)) == value


@pytest.mark.parametrize(
    ("domain", "exponent"),
    ((PrimeField(7), 5), (BinaryExtensionField(3, 0b1011), 5)),
)
def test_power_inverse_round_trips_finite_fields(domain, exponent):
    source = Primitive("power", {"x": ValueType(domain, (1,))})
    component = Power(source.input("x"), exponent)
    forward = Primitive("forward", {"x": ValueType(domain, (1,))})
    forward.add_round()
    forward.set_output(forward.add_component(Power(forward.input("x"), exponent)))
    inverse = Primitive("inverse", {"y": ValueType(domain, (1,))})
    inverse.add_round()
    inverse.set_output(
        inverse.add_component(invert_component(component, inverse.input("y"), recover_input=0))
    )
    cardinality = domain.modulus if isinstance(domain, PrimeField) else 1 << domain.degree
    assert tuple(
        inverse.evaluate(forward.evaluate(value)) for value in range(cardinality)
    ) == tuple(range(cardinality))


@pytest.mark.parametrize("component_type", (Xor, ModularAdd))
def test_multi_input_recovery_uses_retained_auxiliaries(component_type):
    source = Primitive("source", {name: ValueType(Word(4), (1,)) for name in ("a", "b", "c")})
    component = component_type(source.inputs())
    inverse = Primitive(
        "inverse",
        {
            "output": ValueType(Word(4), (1,)),
            "a": ValueType(Word(4), (1,)),
            "c": ValueType(Word(4), (1,)),
        },
    )
    inverse.add_round()
    recovered = invert_component(
        component,
        inverse.input("output"),
        recover_input=1,
        auxiliary_inputs={0: inverse.input("a"), 2: inverse.input("c")},
    )
    inverse.set_output(inverse.add_component(recovered))

    operation = (
        (lambda a, b, c: a ^ b ^ c) if component_type is Xor else (lambda a, b, c: (a + b + c) & 15)
    )
    for a, b, c in itertools.product(range(16), repeat=3):
        assert inverse.evaluate(operation(a, b, c), a, c) == b


def test_modular_subtract_recovers_each_operand():
    source = Primitive("source", {name: ValueType(Word(4), (1,)) for name in ("a", "b", "c")})
    component = ModularSubtract(source.inputs())
    for recover in range(3):
        names = tuple(name for index, name in enumerate(("a", "b", "c")) if index != recover)
        inverse = Primitive(
            "inverse",
            {
                "output": ValueType(Word(4), (1,)),
                **{name: ValueType(Word(4), (1,)) for name in names},
            },
        )
        inverse.add_round()
        auxiliaries = {
            index: inverse.input(name)
            for index, name in enumerate(("a", "b", "c"))
            if index != recover
        }
        inverse.set_output(
            inverse.add_component(
                invert_component(
                    component,
                    inverse.input("output"),
                    recover_input=recover,
                    auxiliary_inputs=auxiliaries,
                )
            )
        )
        values = (9, 3, 2)
        output = (values[0] - values[1] - values[2]) & 15
        arguments = (output, *(values[index] for index in range(3) if index != recover))
        assert inverse.evaluate(*arguments) == values[recover]


def test_idea_multiply_recovers_each_operand_exhaustively():
    source = Primitive("source", {name: ValueType(Word(4), (1,)) for name in ("a", "b", "c")})
    component = IDEAMultiply(source.inputs())
    for recover in range(3):
        retained = tuple(name for index, name in enumerate(("a", "b", "c")) if index != recover)
        inverse = Primitive(
            "inverse",
            {
                "output": ValueType(Word(4), (1,)),
                **{name: ValueType(Word(4), (1,)) for name in retained},
            },
        )
        inverse.add_round()
        auxiliaries = {
            index: inverse.input(name)
            for index, name in enumerate(("a", "b", "c"))
            if index != recover
        }
        recovered = invert_component(
            component,
            inverse.input("output"),
            recover_input=recover,
            auxiliary_inputs=auxiliaries,
        )
        inverse.set_output(inverse.add_component(recovered))
        for values in itertools.product(range(16), repeat=3):
            encoded = tuple(16 if value == 0 else value for value in values)
            output = encoded[0] * encoded[1] * encoded[2] % 17
            output = 0 if output == 16 else output
            arguments = (output, *(values[index] for index in range(3) if index != recover))
            assert inverse.evaluate(*arguments) == values[recover]


def test_reversible_feedback_register_inverse_round_trips_all_states():
    source = Primitive("source", {"state": ValueType(Bit(), (4,))})
    component = FeedbackRegister(
        source.input("state"),
        (FeedbackRegisterSpec(4, (FeedbackTerm((0,)), FeedbackTerm((1,)))),),
        clocks=3,
    )
    forward = Primitive("forward", {"state": ValueType(Bit(), (4,))})
    forward.add_round()
    forward.set_output(
        forward.add_component(
            FeedbackRegister(
                forward.input("state"),
                component.registers,
                component.clocks,
            )
        )
    )
    inverse = Primitive("inverse", {"state": ValueType(Bit(), (4,))})
    inverse.add_round()
    recovered = invert_component(component, inverse.input("state"), recover_input=0)
    inverse.set_output(inverse.add_component(recovered))

    for state in range(16):
        assert inverse.evaluate(forward.evaluate(state)) == state


def test_nonreversible_feedback_register_reports_information_loss():
    source = Primitive("source", {"state": ValueType(Bit(), (4,))})
    component = FeedbackRegister(
        source.input("state"),
        (FeedbackRegisterSpec(4, (FeedbackTerm((1,)), FeedbackTerm((2,)))),),
    )
    with pytest.raises(TransformationError) as caught:
        invert_component(component, source.input("state"), recover_input=0)
    assert caught.value.reason is TransformationFailureReason.INFORMATION_LOSS


def test_variable_rotation_only_recovers_value_with_retained_amount():
    source = Primitive(
        "source", {"x": ValueType(Word(8), (1,)), "amount": ValueType(Word(8), (1,))}
    )
    component = VariableRotate(source.input("x"), source.input("amount"), "left", "rotate")
    destination = Primitive(
        "destination", {"y": ValueType(Word(8), (1,)), "amount": ValueType(Word(8), (1,))}
    )
    inverse = invert_component(
        component,
        destination.input("y"),
        recover_input=0,
        auxiliary_inputs={1: destination.input("amount")},
    )
    assert isinstance(inverse, VariableRotate) and inverse.direction == "right"

    with pytest.raises(TransformationError, match="information_loss") as caught:
        invert_component(
            component,
            destination.input("y"),
            recover_input=1,
            auxiliary_inputs={0: destination.input("y")},
        )
    assert caught.value.reason is TransformationFailureReason.INFORMATION_LOSS


def test_failure_reasons_distinguish_ambiguity_missing_auxiliary_and_loss():
    source = Primitive("source", {"a": ValueType(Word(4), (1,)), "b": ValueType(Word(4), (1,))})
    xor = Xor(source.inputs(), "xor")
    shift = Shift(source.input("a"), 1, "left", "shift")
    bitwise_and = BitwiseAnd(source.inputs(), "and")

    with pytest.raises(TransformationError) as ambiguous:
        invert_component(xor, source.input("a"))
    assert ambiguous.value.reason is TransformationFailureReason.MULTIPLE_PREDECESSORS

    with pytest.raises(TransformationError) as missing:
        invert_component(xor, source.input("a"), recover_input=0)
    assert missing.value.reason is TransformationFailureReason.MISSING_AUXILIARY_VALUE

    for component in (shift, bitwise_and):
        auxiliaries = {1: source.input("b")} if component is bitwise_and else None
        with pytest.raises(TransformationError) as lost:
            invert_component(
                component, source.input("a"), recover_input=0, auxiliary_inputs=auxiliaries
            )
        assert lost.value.reason is TransformationFailureReason.INFORMATION_LOSS


def test_singular_maps_and_nonbijective_tables_report_information_loss():
    source = Primitive(
        "source",
        {
            "bits": ValueType(Bit(), (2,)),
            "word": ValueType(Word(2), (1,)),
            "field": ValueType(PrimeField(7), (1,)),
        },
    )
    components = (
        LinearMap(source.input("bits"), ((1, 0), (1, 0)), "singular"),
        SBox(source.input("word"), (0, 0, 1, 1), "nonbijective"),
        Power(source.input("field"), 2, "power"),
    )
    outputs = (source.input("bits"), source.input("word"), source.input("field"))
    for component, output in zip(components, outputs):
        with pytest.raises(TransformationError) as caught:
            invert_component(component, output, recover_input=0)
        assert caught.value.reason is TransformationFailureReason.INFORMATION_LOSS
