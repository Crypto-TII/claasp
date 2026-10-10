from claasp.analysis.component_properties import (
    ComponentProperty,
    DiagnosticCode,
    PropertyDomain,
    PropertyRequest,
    analyze_component_property,
)
from claasp.components import (
    BitwiseAnd,
    BitwiseNot,
    FeedbackRegister,
    FeedbackRegisterSpec,
    FeedbackTerm,
    ModularAdd,
    Rotate,
    Shift,
    Xor,
)
from claasp.domains import Bit, Word
from claasp.graph import ArrayType, Port


def _word_component(component, property_):
    return analyze_component_property(
        component, PropertyRequest(property_, PropertyDomain.WORD_OPERATION)
    )


def _ports(width=3):
    array_type = ArrayType(Word(width), (1,))
    return Port("x", array_type), Port("y", array_type)


def test_xor_and_not_rotate_shift_exact_anf_properties():
    left, right = _ports()
    xor = Xor((left, right))
    bitwise_and = BitwiseAnd((left, right))
    bitwise_not = BitwiseNot(left)
    rotate = Rotate(left, 1, "left")
    shift = Shift(left, 1, "right")

    assert _word_component(xor, ComponentProperty.ALGEBRAIC_DEGREE).value == 1
    assert _word_component(xor, ComponentProperty.TERM_COUNT).value == (2, 2, 2)
    assert _word_component(xor, ComponentProperty.LINEAR).value is True
    assert _word_component(bitwise_and, ComponentProperty.ALGEBRAIC_DEGREE).value == 2
    assert _word_component(bitwise_not, ComponentProperty.LINEAR).value is False
    assert _word_component(bitwise_not, ComponentProperty.INVERTIBLE).value is True
    assert _word_component(rotate, ComponentProperty.ORDER).value == 3
    assert _word_component(shift, ComponentProperty.TERM_COUNT).value == (0, 1, 1)


def test_reduced_modular_add_exact_anf_degree_and_variables():
    left, right = _ports(3)
    component = ModularAdd((left, right))

    assert _word_component(component, ComponentProperty.ALGEBRAIC_DEGREE).value == 3
    assert _word_component(component, ComponentProperty.VARIABLE_COUNT).value == (6, 4, 2)
    assert _word_component(component, ComponentProperty.LINEAR).value is False


def test_linear_feedback_structure_and_connection_polynomial_are_typed():
    state = Port("state", ArrayType(Bit(), (4,)))
    component = FeedbackRegister(
        state,
        (FeedbackRegisterSpec(4, (FeedbackTerm(0), FeedbackTerm(3))),),
    )
    request = lambda property_: PropertyRequest(property_, PropertyDomain.FEEDBACK_REGISTER)

    assert analyze_component_property(component, request(ComponentProperty.LINEAR)).value is True
    assert analyze_component_property(
        component, request(ComponentProperty.ALGEBRAIC_DEGREE)
    ).value == (1,)
    polynomial = analyze_component_property(
        component, request(ComponentProperty.CONNECTION_POLYNOMIAL)
    ).value
    assert polynomial[0]["degree"] == 4
    assert polynomial[0]["terms"] == ((0, 1), (3, 1))


def test_nonlinear_or_clocked_feedback_rejects_connection_polynomial():
    state = Port("state", ArrayType(Bit(), (4,)))
    component = FeedbackRegister(
        state,
        (
            FeedbackRegisterSpec(
                4,
                (FeedbackTerm((0, 1)), FeedbackTerm(3)),
                clock=(FeedbackTerm(2),),
            ),
        ),
    )
    result = analyze_component_property(
        component,
        PropertyRequest(ComponentProperty.CONNECTION_POLYNOMIAL, PropertyDomain.FEEDBACK_REGISTER),
    )

    assert not result.is_available
    assert result.diagnostic.code is DiagnosticCode.INAPPLICABLE_DOMAIN
    degree = analyze_component_property(
        component,
        PropertyRequest(ComponentProperty.ALGEBRAIC_DEGREE, PropertyDomain.FEEDBACK_REGISTER),
    )
    assert degree.value == (2,)
