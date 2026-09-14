"""Validation for portable monomial parity enumeration."""

import pytest

from claasp_next.analysis import enumerate_optimal_monomial_parity


def test_parity_enumerator_rejects_nonpositive_path_limit():
    with pytest.raises(ValueError, match="positive integer"):
        enumerate_optimal_monomial_parity(None, None, max_paths=0)
