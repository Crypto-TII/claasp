import pytest
from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import (
    sbox_inequalities,
    sbox_valid_transitions,
)


def test_generate_sbox_inequalities_for_trail_search():
    SBox_PRESENT = SBox([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])
    sbox_ineqs = sbox_inequalities(SBox_PRESENT)

    assert str(sbox_ineqs[2][1]) == "An inequality (0, 0, 0, 1, 1, 0, 1, 0) x - 1 >= 0"


def test_sbox_valid_transitions():
    SBox_PRESENT = SBox([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])

    differential = sbox_valid_transitions(SBox_PRESENT)
    assert len(differential) == 96
    assert (1, 3, 4) in differential
    assert all(delta_in != 0 for delta_in, _, _ in differential)
    assert all(isinstance(count, int) and count > 0 for _, _, count in differential)

    linear = sbox_valid_transitions(SBox_PRESENT, analysis="linear")
    assert len(linear) == 132

    with pytest.raises(TypeError):
        sbox_valid_transitions(SBox_PRESENT, analysis="invalid")
