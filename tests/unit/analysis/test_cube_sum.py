"""Direct verification of preserved cube-superpoly evidence."""

import pytest

from claasp.analysis import evaluate_cube_sum
from claasp.primitives import Simon


@pytest.mark.parametrize("key", (0, 1 << 14, 1 << 63, 0x1918111009080100))
def test_cube_sum_verifies_legacy_simon_k49_superpoly(key):
    primitive = Simon(number_of_rounds=2)
    result = evaluate_cube_sum(
        primitive,
        {"plaintext": 0, "key": key},
        variable_input="plaintext",
        cube_positions=(0, 9),
        output_bit=0,
    )
    expected_k49 = (key >> (63 - 49)) & 1
    assert result.parity == expected_k49
    assert result.evaluations == 4
    assert result.complete


def test_cube_sum_ignores_supplied_values_of_cube_bits():
    primitive = Simon(number_of_rounds=2)
    zero = evaluate_cube_sum(
        primitive,
        {"plaintext": 0, "key": 0},
        variable_input="plaintext",
        cube_positions=(0, 9),
        output_bit=0,
    )
    set_cube = evaluate_cube_sum(
        primitive,
        {"plaintext": (1 << 31) | (1 << 22), "key": 0},
        variable_input="plaintext",
        cube_positions=(0, 9),
        output_bit=0,
    )
    assert zero == set_cube
