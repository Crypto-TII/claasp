from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import sbox_inequalities


def test_generate_sbox_inequalities_for_trail_search():
    SBox_PRESENT = SBox([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])
    sbox_ineqs = sbox_inequalities(SBox_PRESENT)

    assert str(sbox_ineqs[2][1]) == 'An inequality (0, 0, 0, 1, 1, 0, 1, 0) x - 1 >= 0'
