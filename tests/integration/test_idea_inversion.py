"""End-to-end IDEA graph inversion checks."""

from claasp.primitives import IDEA


def test_full_idea_inverse_recovers_plaintext_with_retained_key():
    primitive = IDEA()
    inverse = primitive.edit.inverse("plaintext").primitive
    plaintext = 0x0001000200030004
    key = 0x00010002000300040005000600070008

    ciphertext = primitive.evaluate(plaintext, key)

    assert inverse.evaluate(ciphertext, key) == plaintext
