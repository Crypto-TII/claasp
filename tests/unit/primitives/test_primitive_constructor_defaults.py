"""Canonical optional parameters for catalogue primitive constructors."""

import inspect

import pytest

from claasp.primitives import (
    CHAM,
    HIGHT,
    LEA,
    MSX,
    SPARX,
    TEA,
    XTEA,
    Ballet,
    Blake,
    Blake2,
    LowMC,
    Midori,
    Raiden,
    Threefish,
    Ublock,
)

ROUND_CONFIGURED_PRIMITIVES = (
    Ballet,
    Blake,
    Blake2,
    CHAM,
    HIGHT,
    LEA,
    LowMC,
    MSX,
    Midori,
    Raiden,
    SPARX,
    TEA,
    Threefish,
    Ublock,
    XTEA,
)


def test_omitted_round_counts_use_none_instead_of_a_numeric_sentinel():
    for primitive_class in ROUND_CONFIGURED_PRIMITIVES:
        parameter = inspect.signature(primitive_class).parameters["number_of_rounds"]
        assert parameter.default is None

    assert inspect.signature(LowMC).parameters["number_of_sboxes"].default is None
    assert inspect.signature(SPARX).parameters["steps"].default is None


@pytest.mark.parametrize("primitive_class", ROUND_CONFIGURED_PRIMITIVES)
def test_explicit_zero_round_counts_are_rejected(primitive_class):
    with pytest.raises(ValueError, match="positive|between 1"):
        primitive_class(number_of_rounds=0)


def test_explicit_zero_lowmc_sboxes_and_sparx_steps_are_rejected():
    with pytest.raises(ValueError, match="number_of_sboxes must be a positive integer"):
        LowMC(number_of_sboxes=0)
    with pytest.raises(ValueError, match="steps must be a positive integer"):
        SPARX(steps=0)
