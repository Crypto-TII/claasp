"""Legacy CP table activity result, without Sage or a solver."""

import pytest

from claasp_next.semantics.cryptanalysis import (
    branch_number_activity_table, possible_active_sbox_counts,
)


def test_legacy_aes_mix_column_branch_table_matches_every_fixed_row():
    import ast
    from pathlib import Path
    # Parse (never import) the fixed Sage-dependent legacy assertion.
    source = Path(__file__).resolve().parents[3] / "tests/unit/cipher_modules/models/cp/mzn_model_test.py"
    module = ast.parse(source.read_text())
    function = next(node for node in module.body
                    if isinstance(node, ast.FunctionDef) and node.name == "test_build_mix_column_truncated_table")
    assertion = next(node for node in function.body if isinstance(node, ast.Assert))
    text = ast.literal_eval(assertion.test.comparators[0])
    entries = tuple(map(int, text.split("[")[-1].split("]")[0].split(",")))
    rows = branch_number_activity_table(4, 4, 5)
    assert len(rows) == 94
    assert tuple(value for row in rows for value in row) == entries


def test_activity_table_does_not_silently_assume_mds():
    assert len(branch_number_activity_table(4, 4, 3)) == 220
    with pytest.raises(ValueError, match="16"):
        branch_number_activity_table(9, 9, 5)
    with pytest.raises(ValueError, match="combined"):
        branch_number_activity_table(2, 2, 5)


def test_legacy_midori_weight_nine_active_sbox_counts():
    # Midori's Sb0, also used by the legacy default 64-bit configuration.
    table = (12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6)
    assert possible_active_sbox_counts([table], 9) == {3, 4}
    assert possible_active_sbox_counts([table], 0) == {0}


def test_probability_one_active_transitions_need_an_explicit_bound():
    with pytest.raises(ValueError, match="maximum_active"):
        possible_active_sbox_counts([(0, 1)], 0)
    assert possible_active_sbox_counts([(0, 1)], 0, maximum_active=3) == {0, 1, 2, 3}
    assert possible_active_sbox_counts([(0, 1)], 1, maximum_active=3) == set()


@pytest.mark.parametrize("weight", [-1, True, 1.5])
def test_invalid_activity_weight(weight):
    with pytest.raises(ValueError, match="weight"):
        possible_active_sbox_counts([], weight)
