import pytest

from claasp_next import Bit, Cipher, PrimeField, ScalarEvaluator, ValueType
from claasp_next.components import Concatenate, Constant, Identity, Permutation


@pytest.mark.parametrize(
    "domain,values",
    [
        (Bit(), (0, 1, 1)),
        (PrimeField(17), (3, 12, 16)),
    ],
)
def test_same_permutation_operates_on_different_domains(domain, values):
    value_type = ValueType(domain, (3,))
    cipher = Cipher("permutation", {"state": value_type})
    cipher.add_round()
    permutation = Permutation(cipher.input("state"), (2, 0, 1), component_id="permutation_0_0")
    cipher.add_component(permutation)

    result = ScalarEvaluator().evaluate(cipher, {"state": values})

    assert result.value_of("permutation_0_0") == (values[2], values[0], values[1])
    assert result.output is None


def test_selection_identity_and_concatenation_use_logical_units():
    field = PrimeField(257)
    state_type = ValueType(field, (4,))
    cipher = Cipher("selection", {"state": state_type})
    cipher.add_round()
    high = Identity(cipher.input("state")[3, 2], component_id="identity_0_0")
    low = Identity(cipher.input("state")[1, 0], component_id="identity_0_1")
    high_port = cipher.add_component(high)
    low_port = cipher.add_component(low)
    joined = Concatenate((high_port, low_port), component_id="concatenate_0_2")
    cipher.add_component(joined)

    result = ScalarEvaluator().evaluate(cipher, {"state": (10, 20, 30, 40)})

    assert result.value_of("concatenate_0_2") == (40, 30, 20, 10)


def test_constant_has_no_graph_inputs_and_is_domain_checked():
    field = PrimeField(17)
    cipher = Cipher("constant", {"state": ValueType(field, (1,))})
    cipher.add_round()
    constant = Constant(ValueType(field, (3,)), (1, 2, 16), component_id="constant_0_0")
    cipher.add_component(constant)

    result = ScalarEvaluator().evaluate(cipher, {"state": (0,)})

    assert result.value_of("constant_0_0") == (1, 2, 16)

    with pytest.raises(ValueError, match="canonical element"):
        Constant(ValueType(field, (1,)), (17,), component_id="bad")


def test_scalar_evaluator_validates_cipher_inputs():
    cipher = Cipher("typed", {"state": ValueType(Bit(), (2,))})

    with pytest.raises(ValueError, match="requires 2 logical units"):
        ScalarEvaluator().evaluate(cipher, {"state": (1,)})

    with pytest.raises(ValueError, match="canonical element"):
        ScalarEvaluator().evaluate(cipher, {"state": (0, 2)})


def test_scalar_evaluator_rejects_unsupported_base_component():
    from claasp_next import Component

    value_type = ValueType(Bit(), (1,))
    cipher = Cipher("unsupported", {"state": value_type})
    cipher.add_round()
    cipher.add_component(Component("unknown_0_0", (cipher.input("state").select_all(),), value_type))

    with pytest.raises(NotImplementedError, match="does not support Component"):
        ScalarEvaluator().evaluate(cipher, {"state": (0,)})
