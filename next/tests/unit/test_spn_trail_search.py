import pytest

from claasp_next.analysis.spn import check_spn_trail
from claasp_next.ciphers import PresentBlockCipher, SpeckBlockCipher


def test_two_round_present_reproduces_legacy_optimum_and_checks_every_step():
    cipher = PresentBlockCipher(number_of_rounds=2)

    result = cipher.analyze().find_lowest_weight_xor_differential_trail()

    assert result.trail.total_weight == 4.0
    assert result.lower_bound == 4.0
    assert result.is_optimal
    assert result.trail.input_pattern.value != 0
    assert check_spn_trail(cipher, result.trail)
    assert "legacy CLAASP" in result.provenance


def test_spn_search_rejects_unreviewed_graphs_explicitly():
    with pytest.raises(NotImplementedError, match="two-round Speck32/64"):
        SpeckBlockCipher(number_of_rounds=3).analyze().find_lowest_weight_xor_differential_trail()
