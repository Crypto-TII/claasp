"""Two-subset tables cross-checked using independent direct ANF coefficients."""

from types import SimpleNamespace

import pytest

from claasp.analysis import TwoSubsetDivisionProperty, two_subset_transition_table
from claasp.drivers.solvers import MILPStatus
from claasp.primitives import Present
from claasp.primitives.block_ciphers.ublock.primitive import SBOX


def _direct_relation(table, output_width):
    relation = set()
    for u in range(len(table)):
        reachable = []
        for v in range(1 << output_width):
            for w in range(len(table)):
                if w & u != u:
                    continue
                coefficient = (
                    sum(int(table[x] & v == v) for x in range(len(table)) if x & w == x) % 2
                )
                if coefficient:
                    reachable.append(v)
                    break
        for v in reachable:
            if not any(other != v and other & v == other for other in reachable):
                relation.add((u, v))
    return relation


@pytest.mark.parametrize(
    "table,width",
    [
        (tuple(SBOX), 4),
        ((0, 1, 2, 3), 2),
        ((0, 1, 1, 0), 1),
        ((0, 1, 1, 2, 1, 2, 2, 3), 2),
        ((0, 0, 0, 0), 2),
    ],
)
def test_two_subset_table_matches_direct_coefficients(table, width):
    assert two_subset_transition_table(table, width) == _direct_relation(table, width)


def test_original_ublock_and_full_adder_transition_counts():
    assert len(two_subset_transition_table(SBOX)) == 42
    # Full adder: output order is (sum, carry).
    full_adder = tuple(((x.bit_count() & 1) << 1) | (x.bit_count() >= 2) for x in range(8))
    assert len(two_subset_transition_table(full_adder, 2)) == 11


def test_empty_cube_is_not_mistaken_for_an_integral_distinguisher():
    with pytest.raises(ValueError, match="at least one active bit"):
        TwoSubsetDivisionProperty(Present(number_of_rounds=1)).milp_model([])


def test_unknown_solver_status_does_not_certify_balance():
    class Unknown:
        def solve(self, model):
            return SimpleNamespace(status=MILPStatus.UNKNOWN)

    with pytest.raises(RuntimeError, match="unknown"):
        TwoSubsetDivisionProperty(Present(number_of_rounds=1)).is_balanced_over_cube_scan(
            [0], [0], solver=Unknown()
        )


def test_scan_compiles_once_and_fixes_each_requested_target():
    models = []

    class Feasible:
        def solve(self, model):
            models.append(model)
            return SimpleNamespace(status=MILPStatus.FEASIBLE)

    analysis = TwoSubsetDivisionProperty(Present(number_of_rounds=1))
    assert analysis.is_balanced_over_cube_scan([0, 3], [0, 1], solver=Feasible()) == {
        0: False,
        3: False,
    }
    assert models[0].variables is models[1].variables
    assert models[0].constraints != models[1].constraints


def test_modular_key_injection_is_not_silently_dropped():
    from claasp.primitives import HIGHT

    with pytest.raises(ValueError, match="only for XOR"):
        TwoSubsetDivisionProperty(HIGHT(number_of_rounds=2), key_schedule="removed")
    assert (
        TwoSubsetDivisionProperty(
            HIGHT(number_of_rounds=2), key_schedule="independent"
        ).key_schedule
        == "independent"
    )
