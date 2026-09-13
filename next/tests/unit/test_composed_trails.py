from math import isclose

import pytest

from claasp_next.semantics.cryptanalysis import (
    BoomerangSwitchBoundary, BoomerangTrail, DifferentialLinearTrail,
    ProbabilisticTruncatedTrail, Trail, TrailKind, TruncatedXorDifference,
    XorDifference, XorMask,
)


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
