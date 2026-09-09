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
    permutation = Permutation("permutation_0_0", cipher.input("state").select_all(), (2, 0, 1))
    cipher.add_component(permutation)

    result = ScalarEvaluator().evaluate(cipher, {"state": values})

    assert result.value_of("permutation_0_0") == (values[2], values[0], values[1])


def test_selection_identity_and_concatenation_use_logical_units():
    field = PrimeField(257)
    state_type = ValueType(field, (4,))
    cipher = Cipher("selection", {"state": state_type})
    cipher.add_round()
    high = Identity("identity_0_0", cipher.input("state").select(3, 2))
    low = Identity("identity_0_1", cipher.input("state").select(1, 0))
    high_port = cipher.add_component(high)
    low_port = cipher.add_component(low)
    joined = Concatenate("concatenate_0_2", (high_port.select_all(), low_port.select_all()))
    cipher.add_component(joined)

    result = ScalarEvaluator().evaluate(cipher, {"state": (10, 20, 30, 40)})

    assert result.value_of("concatenate_0_2") == (40, 30, 20, 10)


def test_constant_has_no_graph_inputs_and_is_domain_checked():
    field = PrimeField(17)
    cipher = Cipher("constant", {"state": ValueType(field, (1,))})
    cipher.add_round()
    constant = Constant("constant_0_0", ValueType(field, (3,)), (1, 2, 16))
    cipher.add_component(constant)

    result = ScalarEvaluator().evaluate(cipher, {"state": (0,)})

    assert result.value_of("constant_0_0") == (1, 2, 16)

    with pytest.raises(ValueError, match="canonical element"):
        Constant("bad", ValueType(field, (1,)), (17,))


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
