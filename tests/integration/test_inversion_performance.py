"""Bounded catalogue-scale regression tests for graph-native inversion."""

from time import perf_counter

from claasp.primitives import Gimli, KatanFSR, Norx


def test_dependency_driven_inversion_scales_to_full_katan64_fsr():
    primitive = KatanFSR(block_bit_size=64, key_bit_size=80, number_of_rounds=254)

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF0123
    assert inverse.evaluate(primitive.evaluate(plaintext, key), key) == plaintext
    assert elapsed < 10


def test_full_gimli_triangular_inverse_stays_within_integration_budget():
    primitive = Gimli()

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    state = 0x0123456789ABCDEF
    assert inverse.evaluate(primitive.evaluate(state)) == state
    assert elapsed < 10


def test_full_norx_triangular_inverse_stays_within_integration_budget():
    primitive = Norx(word_size=32)

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    state = 0x0123456789ABCDEF
    assert inverse.evaluate(primitive.evaluate(state)) == state
    assert elapsed < 10
