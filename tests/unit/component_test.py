import pytest

from claasp.component import Component
from claasp.input import Input


class DummyComponent(Component):
    def sat_constraints(self):
        return ["dummy_var"], ["dummy_constraint"]


def make_component():
    component_input = Input(4, ["input"], [[0, 1, 2, 3]])
    return Component("component_0_0", "word_operation", component_input, 4, ["DUMMY", 1])


def test_unimplemented_component_method_raises_not_implemented_error():
    component = make_component()

    with pytest.raises(NotImplementedError, match="does not implement method 'sat_constraints'"):
        component.sat_constraints()


def test_alias_method_falls_back_to_unimplemented_error_message():
    component = make_component()

    with pytest.raises(NotImplementedError, match="does not implement method 'sat_constraints'"):
        component.sat_xor_differential_propagation_constraints()


def test_alias_method_uses_common_base_implementation_when_available():
    component_input = Input(4, ["input"], [[0, 1, 2, 3]])
    component = DummyComponent("dummy_0_0", "word_operation", component_input, 4, ["DUMMY", 1])

    assert component.sat_xor_differential_propagation_constraints() == (["dummy_var"], ["dummy_constraint"])
