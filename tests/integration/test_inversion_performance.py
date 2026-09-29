"""Bounded catalogue-scale regression tests for graph-native inversion."""

from time import perf_counter

import pytest

from claasp.primitives import Gimli, KatanFSR, Norx


@pytest.fixture(scope="module")
def katan64_inversion_result() -> tuple[int, int, float]:
    """Build and evaluate the full KATAN-64 inverse once for this module."""
    primitive = KatanFSR(block_bit_size=64, key_bit_size=80, number_of_rounds=254)

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF0123
    recovered = inverse.evaluate(primitive.evaluate(plaintext, key), key)
    return recovered, plaintext, elapsed


@pytest.fixture(scope="module")
def gimli_inversion_result() -> tuple[int, int, float]:
    """Build and evaluate the full Gimli inverse once for this module."""
    primitive = Gimli()

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    state = 0x0123456789ABCDEF
    recovered = inverse.evaluate(primitive.evaluate(state))
    return recovered, state, elapsed


@pytest.fixture(scope="module")
def norx_inversion_result() -> tuple[int, int, float]:
    """Build and evaluate the full NORX inverse once for this module."""
    primitive = Norx(word_size=32)

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    state = 0x0123456789ABCDEF
    recovered = inverse.evaluate(primitive.evaluate(state))
    return recovered, state, elapsed


def test_dependency_driven_inversion_scales_to_full_katan64_fsr(
    katan64_inversion_result: tuple[int, int, float],
):
    recovered, plaintext, _elapsed = katan64_inversion_result
    assert recovered == plaintext


def test_full_gimli_triangular_inverse_round_trips(
    gimli_inversion_result: tuple[int, int, float],
):
    recovered, state, _elapsed = gimli_inversion_result
    assert recovered == state


def test_full_norx_triangular_inverse_round_trips(
    norx_inversion_result: tuple[int, int, float],
):
    recovered, state, _elapsed = norx_inversion_result
    assert recovered == state


@pytest.mark.performance
def test_full_katan64_inverse_stays_within_native_integration_budget(
    katan64_inversion_result: tuple[int, int, float],
):
    assert katan64_inversion_result[2] < 10


@pytest.mark.performance
def test_full_gimli_inverse_stays_within_native_integration_budget(
    gimli_inversion_result: tuple[int, int, float],
):
    assert gimli_inversion_result[2] < 10


@pytest.mark.performance
def test_full_norx_inverse_stays_within_native_integration_budget(
    norx_inversion_result: tuple[int, int, float],
):
    assert norx_inversion_result[2] < 10
