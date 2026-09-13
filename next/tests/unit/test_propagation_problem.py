import pytest

from claasp_next.ciphers import PresentBlockCipher, SpeckBlockCipher
from claasp_next.components import BitVectorSBox
from claasp_next.interpretations import XOR_DIFFERENTIAL, XOR_LINEAR
from claasp_next.interpretations.cryptanalysis import (
    ComponentSemanticsBinding, PropagationProblem,
)


def test_default_registry_resolves_exact_graph_derived_sbox_semantics():
    cipher = PresentBlockCipher(number_of_rounds=1)
    component = next(item for item in cipher.components if isinstance(item, BitVectorSBox))
    problem = PropagationProblem(
        cipher, XOR_DIFFERENTIAL, component_ids=(component.component_id,),
        maximum_weight=4, provenance=("unit-test",),
    )

    transition = problem.provider_for(component).transition((1,), 3)
    assert transition.is_possible
    assert transition.weight == 2
    assert problem.components == (component,)


def test_default_registry_resolves_modular_add_linear_semantics():
    cipher = SpeckBlockCipher(number_of_rounds=1)
    component = next(item for item in cipher.components if "modular_add" in item.component_id)
    problem = PropagationProblem(cipher, XOR_LINEAR, component_ids=(component.component_id,))

    transition = problem.provider_for(component).transition((0x0800, 0x0800), 0x0C00)
    assert transition.weight == 1
    assert transition.sign == -1


def test_per_component_binding_overrides_global_semantics_immutably():
    cipher = PresentBlockCipher(number_of_rounds=1)
    components = tuple(item for item in cipher.components if isinstance(item, BitVectorSBox))
    base = PropagationProblem(cipher, XOR_DIFFERENTIAL).registry

    class ImpossibleProvider:
        def transition(self, input_patterns, output_pattern):
            return base.provider(components[0], XOR_DIFFERENTIAL).transition((0,), 1)

    overridden = base.register(ComponentSemanticsBinding(
        XOR_DIFFERENTIAL, BitVectorSBox, lambda component: ImpossibleProvider(),
        component_id=components[0].component_id,
    ))
    problem = PropagationProblem(cipher, XOR_DIFFERENTIAL, registry=overridden)

    assert not problem.provider_for(components[0]).transition((1,), 3).is_possible
    assert problem.provider_for(components[1]).transition((1,), 3).is_possible
    assert len(overridden.bindings) == len(base.bindings) + 1


def test_propagation_problem_rejects_unknown_scope_and_out_of_scope_access():
    cipher = PresentBlockCipher(number_of_rounds=1)
    with pytest.raises(ValueError, match="unknown propagation"):
        PropagationProblem(cipher, XOR_DIFFERENTIAL, component_ids=("missing",))
    problem = PropagationProblem(cipher, XOR_DIFFERENTIAL, component_ids=())
    with pytest.raises(ValueError, match="outside"):
        problem.provider_for(cipher.components[0])
