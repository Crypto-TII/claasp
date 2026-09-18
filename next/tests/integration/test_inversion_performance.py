"""Bounded catalogue-scale regression tests for graph-native inversion."""

from time import perf_counter

from claasp_next.primitives import KatanFSR


def test_dependency_driven_inversion_scales_to_full_katan64_fsr():
    primitive = KatanFSR(block_bit_size=64, key_bit_size=80, number_of_rounds=254)

    started = perf_counter()
    inverse = primitive.inverse().primitive
    elapsed = perf_counter() - started

    plaintext = 0x0123456789ABCDEF
    key = 0x0123456789ABCDEF0123
    assert inverse.evaluate(primitive.evaluate(plaintext, key), key) == plaintext
    assert elapsed < 10
