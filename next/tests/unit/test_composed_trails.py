from math import isclose

import pytest

from claasp_next.semantics.cryptanalysis import (
    BoomerangSwitchBoundary, BoomerangTrail, DifferentialLinearTrail,
    ProbabilisticTruncatedTrail, Trail, TrailKind, TruncatedXorDifference,
    XorDifference, XorMask,
    SBoxBoomerangSemantics,
    ModularAddBoomerangSemantics,
)
from claasp_next.ciphers import PresentBlockCipher


def _trail(kind, source, target, width=4):
    pattern = XorDifference if kind is TrailKind.XOR_DIFFERENTIAL else XorMask
    return Trail(kind, pattern(source, width), pattern(target, width), ())


def test_boomerang_composition_checks_typed_boundaries_and_weight():
    upper = _trail(TrailKind.XOR_DIFFERENTIAL, 1, 2)
    lower = _trail(TrailKind.XOR_DIFFERENTIAL, 4, 8)
    switch = BoomerangSwitchBoundary(
        XorDifference(2, 4), XorDifference(3, 4),
        XorDifference(5, 4), XorDifference(4, 4), 1.5,
    )

    assert BoomerangTrail(upper, switch, lower).total_weight == 1.5
    with pytest.raises(ValueError, match="upper trail"):
        BoomerangTrail(_trail(TrailKind.XOR_DIFFERENTIAL, 1, 3), switch, lower)


def test_differential_linear_composition_uses_exact_legacy_formula():
    connector = ProbabilisticTruncatedTrail(
        TruncatedXorDifference.parse("0000"),
        TruncatedXorDifference.parse("????"), (),
    )
    composed = DifferentialLinearTrail(
        _trail(TrailKind.XOR_DIFFERENTIAL, 1, 2), connector,
        _trail(TrailKind.XOR_LINEAR, 4, 8),
    )

    assert isclose(composed.total_weight, 0.0)
    with pytest.raises(TypeError, match="prefix"):
        DifferentialLinearTrail(_trail(TrailKind.XOR_LINEAR, 1, 2), connector,
                                _trail(TrailKind.XOR_LINEAR, 4, 8))


def test_present_boomerang_connectivity_is_counted_exhaustively():
    cipher = PresentBlockCipher(number_of_rounds=1)
    component = next(item for item in cipher.components if item.component_id == "sbox_1_0")
    semantics = SBoxBoomerangSemantics(component.table)

    possible = semantics.connectivity(1, 2)
    impossible = semantics.connectivity(1, 1)

    assert possible.count == 4
    assert possible.weight == 2
    assert impossible.count == 0
    assert not impossible.is_possible


def test_boomerang_connectivity_rejects_non_bijections():
    with pytest.raises(ValueError, match="bijective"):
        SBoxBoomerangSemantics((0, 0, 1, 2))


def test_modular_add_boomerang_oracle_counts_full_quartets():
    semantics = ModularAddBoomerangSemantics(4)

    certain = semantics.connectivity(0, 0, 0, 0)
    half = semantics.connectivity(1, 0, 1, 0)
    impossible = semantics.connectivity(3, 5, 7, 9)

    assert (certain.count, certain.weight) == (256, 0)
    assert (half.count, half.weight) == (128, 1)
    assert not impossible.is_possible


def test_modular_add_boomerang_oracle_rejects_unreviewable_widths():
    with pytest.raises(ValueError, match="widths 1 through 8"):
        ModularAddBoomerangSemantics(16)
