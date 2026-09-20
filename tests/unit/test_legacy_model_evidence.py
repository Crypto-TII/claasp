"""Fixed qualified evidence awaiting its catalogue primitive."""

from claasp.analysis import ublock_three_round_legacy_cluster


def test_ublock_three_round_cluster_is_preserved_without_false_reproof():
    evidence = ublock_three_round_legacy_cluster()

    assert evidence.primitive_family == "uBlock"
    assert evidence.rounds == 3
    assert evidence.input_difference == 0x04400000000000000044400000000000
    assert evidence.output_difference == 0x00044004444404004400444044400040
    assert evidence.maximum_weight == 31
    assert evidence.trail_count == 8
    assert evidence.aggregate_weight == 25.7146
    assert evidence.claim_kind == "legacy-solver-regression"
