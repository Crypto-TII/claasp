"""Regression checks for SCARF's split public state boundary."""

from claasp_next.primitives import SCARF


def test_scarf_uses_and_recovers_both_plaintext_halves():
    primitive = SCARF()
    inverse = primitive.inverse("plaintext").primitive
    key = 0x0123456789ABCDEF0123456789ABCDEF
    tweak = 0x123456789ABC
    plaintexts = (0x001, 0x020, 0x155, 0x2AA, 0x3FF)
    outputs = [primitive.evaluate(plaintext, key, tweak) for plaintext in plaintexts]

    assert len(set(outputs)) == len(plaintexts)
    assert [inverse.evaluate(output, key, tweak) for output in outputs] == list(plaintexts)
