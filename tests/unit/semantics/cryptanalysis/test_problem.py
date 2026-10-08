import pytest

from claasp.components import BitVectorSBox
from claasp.primitives import DES, Present, Speck
from claasp.semantics import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp.semantics.cryptanalysis import (
    ComponentSemanticsBinding,
    PropagationProblem,
    SBoxTransitionSemantics,
)


def test_default_registry_resolves_exact_graph_derived_sbox_semantics():
    primitive = Present(number_of_rounds=1)
    component = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
    problem = PropagationProblem(
        primitive,
        XOR_DIFFERENTIAL,
        component_ids=(component.component_id,),
        maximum_weight=4,
        provenance=("unit-test",),
    )

    transition = problem.provider_for(component).transition((1,), 3)
    assert transition.is_possible
    assert transition.weight == 2
    assert problem.components == (component,)


def test_default_registry_preserves_rectangular_des_sbox_widths():
    primitive = DES(number_of_rounds=1)
    component = next(item for item in primitive.components if isinstance(item, BitVectorSBox))
    assert component.component_id is not None
    problem = PropagationProblem(
        primitive,
        XOR_DIFFERENTIAL,
        component_ids=(component.component_id,),
    )

    transition = problem.provider_for(component).transition((0x34,), 0x2)

    assert (transition.input_pattern.width, transition.output_pattern.width) == (6, 4)
    assert transition.numerator == sum(
        component.table[value] ^ component.table[value ^ 0x34] == 0x2 for value in range(64)
    )
    assert SBoxTransitionSemantics(component.table, output_width=component.output_bit_size).check(
        transition
    )
    expected_possible = any(
        component.table[value] ^ component.table[value ^ 0x34] == 0x2 for value in range(64)
    )
    assert (
        primitive.analysis.is_xor_differential_transition_possible(
            component.component_id, 0x34, 0x2
        )
        is expected_possible
    )
    with pytest.raises(ValueError, match="output pattern"):
        primitive.analysis.is_xor_differential_transition_possible(
            component.component_id, 0x34, 0x10
        )


def test_default_registry_resolves_modular_add_linear_semantics():
    primitive = Speck(number_of_rounds=1)
    component = next(item for item in primitive.components if "modular_add" in item.component_id)
    problem = PropagationProblem(primitive, XOR_LINEAR, component_ids=(component.component_id,))

    transition = problem.provider_for(component).transition((0x0800, 0x0800), 0x0C00)
    assert transition.weight == 1
    assert transition.sign == -1


def test_per_component_binding_overrides_global_semantics_immutably():
    primitive = Present(number_of_rounds=1)
    components = tuple(item for item in primitive.components if isinstance(item, BitVectorSBox))
    base = PropagationProblem(primitive, XOR_DIFFERENTIAL).registry

    class ImpossibleProvider:
        def transition(self, input_patterns, output_pattern):
            return base.provider(components[0], XOR_DIFFERENTIAL).transition((0,), 1)

    overridden = base.register(
        ComponentSemanticsBinding(
            XOR_DIFFERENTIAL,
            BitVectorSBox,
            lambda component: ImpossibleProvider(),
            component_id=components[0].component_id,
        )
    )
    problem = PropagationProblem(primitive, XOR_DIFFERENTIAL, registry=overridden)

    assert not problem.provider_for(components[0]).transition((1,), 3).is_possible
    assert problem.provider_for(components[1]).transition((1,), 3).is_possible
    assert len(overridden.bindings) == len(base.bindings) + 1


def test_propagation_problem_rejects_unknown_scope_and_out_of_scope_access():
    primitive = Present(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown propagation"):
        PropagationProblem(primitive, XOR_DIFFERENTIAL, component_ids=("missing",))
    problem = PropagationProblem(primitive, XOR_DIFFERENTIAL, component_ids=())
    with pytest.raises(ValueError, match="outside"):
        problem.provider_for(primitive.components[0])
