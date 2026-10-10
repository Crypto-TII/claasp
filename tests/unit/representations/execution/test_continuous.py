import pytest

from claasp.primitives import AES, Simon, Speck
from claasp.primitives.single_component_primitives import (
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    ModularSubtract,
    Shift,
    VariableRotate,
    VariableShift,
)
from claasp.semantics.cryptanalysis import continuous_speck32


@pytest.mark.parametrize(
    ("primitive", "inputs", "expected"),
    [
        (BitwiseAnd(1), {"input_0": (-1.0,), "input_1": (1.0,)}, (-1.0,)),
        (BitwiseOr(1), {"input_0": (-1.0,), "input_1": (1.0,)}, (1.0,)),
        (BitwiseNot(2), {"input": (-1.0, 1.0)}, (1.0, -1.0)),
        (Shift(4, 1, "left"), {"input": (-1.0, 0.0, 0.5, 1.0)}, (0.0, 0.5, 1.0, -1.0)),
        (
            ModularSubtract(2),
            {"input_0": (-1.0, -1.0), "input_1": (-1.0, -1.0)},
            (-1.0, -1.0),
        ),
    ],
)
def test_graph_continuous_driver_recovers_basic_legacy_operations(primitive, inputs, expected):
    result = primitive.analysis.continuous_evaluate(inputs)

    assert result.output == expected
    assert result.claim_kind == "heuristic"


def test_graph_continuous_sbox_matches_fixed_concrete_values():
    primitive = BitVectorSBox(2, [3, 2, 1, 0])

    result = primitive.analysis.continuous_evaluate({"input": (-1.0, 1.0)})

    assert result.output == (1.0, -1.0)


def test_graph_continuous_speck_matches_preserved_specialized_equations():
    primitive = Speck(number_of_rounds=1)
    left = tuple(-1.0 + index / 20 for index in range(16))
    right = tuple(1.0 - index / 20 for index in range(16))

    result = primitive.analysis.continuous_evaluate(
        {"plaintext": left + right, "key": (-1.0,) * 64}
    )

    assert result.output == pytest.approx(continuous_speck32(left, right, rounds=1).values)


def test_graph_continuous_supports_and_based_simon():
    result = Simon(number_of_rounds=1).analysis.continuous_evaluate(
        {"plaintext": (0.0,) * 32, "key": (-1.0,) * 64}
    )

    assert result.output is not None
    assert len(result.output) == 32
    assert all(-1.0 <= value <= 1.0 for value in result.output)


def test_graph_continuous_supports_binary_field_aes_graph():
    result = AES(number_of_rounds=1).analysis.continuous_evaluate(
        {"plaintext": (0.0,) * 128, "key": (-1.0,) * 128}
    )

    assert result.output is not None
    assert len(result.output) == 128


@pytest.mark.parametrize(
    ("primitive", "amount", "expected"),
    [
        (VariableRotate(8, 3, "right"), 2, 0x60),
        (VariableRotate(8, 3, "left"), 2, 0x06),
        (VariableShift(8, 3, "right"), 2, 0x20),
        (VariableShift(8, 3, "left"), 2, 0x04),
    ],
)
def test_graph_continuous_variable_movement_matches_scalar_at_boolean_endpoints(
    primitive, amount, expected
):
    bits = tuple(1.0 if (0x81 >> shift) & 1 else -1.0 for shift in reversed(range(8)))
    amount_bits = tuple(1.0 if (amount >> shift) & 1 else -1.0 for shift in reversed(range(3)))

    output = primitive.analysis.continuous_evaluate({"input": bits, "amount": amount_bits}).output

    assert output is not None
    decoded = sum((value == 1.0) << shift for value, shift in zip(output, reversed(range(8))))
    assert decoded == expected == primitive.evaluate(0x81, amount)


def test_graph_continuous_variable_shift_preserves_legacy_fractional_fixture():
    result = VariableShift(3, 2, "left").analysis.continuous_evaluate(
        {"input": (0.01, 0.02, 0.004), "amount": (0.01, 0.02)}
    )

    assert result.output is not None
    assert result.output[2] == pytest.approx(-0.44658816949)
