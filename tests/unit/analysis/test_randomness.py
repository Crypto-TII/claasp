from math import erfc, sqrt

import pytest

from claasp.analysis import frequency_test


def test_monobit_balanced_and_biased_data():
    assert frequency_test([0, 1] * 50).p_value == 1
    assert frequency_test([1] * 100).passed is False
    result = frequency_test([1] * 55 + [0] * 45)
    assert result.p_value == pytest.approx(erfc(10 / sqrt(200)))
    assert result.ones == 55
    assert result.bit_count == 100
    assert result.passed is True


def test_short_sequences_do_not_claim_valid_statistical_decisions():
    assert frequency_test([1]).passed is None
    assert not frequency_test([1]).applicable


@pytest.mark.parametrize("alpha", [0, 1, -1, float("nan"), float("inf")])
def test_invalid_levels_are_rejected(alpha):
    with pytest.raises(ValueError):
        frequency_test([0, 1], alpha=alpha)
