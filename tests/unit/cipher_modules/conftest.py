"""
Shared reference objects for the tests of ``claasp/cipher_modules``: a reference S-box layer evaluation,
independent of CLAASP's components.
"""
import numpy as np
import pytest


def _apply_sbox_layer(points, sboxes):
    """Image of every row of ``points`` (an (N, n) bit array) by an S-box layer ``((positions, table), ...)``."""
    points = np.asarray(points, dtype=np.uint8)
    image = points.copy()
    for positions, table in (sbox[:2] for sbox in sboxes):  # an Sbox, or a (positions, table) pair
        word = np.zeros(points.shape[0], dtype=np.int64)
        for position in positions:
            word = (word << 1) | points[:, position]
        output = np.asarray(table, dtype=np.int64)[word]
        for k, position in enumerate(positions):
            image[:, position] = (output >> (len(positions) - 1 - k)) & 1
    return image


@pytest.fixture(scope="session")
def apply_sbox_layer():
    return _apply_sbox_layer
