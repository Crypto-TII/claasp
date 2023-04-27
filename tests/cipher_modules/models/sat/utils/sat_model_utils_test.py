from claasp.cipher_modules.models.sat.utils.utils import (cnf_or, cnf_xor_seq)


def test_cnf_or():
    assert cnf_or('r', ['a', 'b', 'c']) == ['r -a', 'r -b', 'r -c', '-r a b c']


def test_cnf_xor_seq():
    xor_seq = cnf_xor_seq(['i_0', 'i_1', 'r_7'], ['a_7', 'b_7', 'c_7', 'd_7'])

    assert xor_seq[0] == '-i_0 a_7 b_7'
    assert xor_seq[1] == 'i_0 -a_7 b_7'
    assert xor_seq[2] == 'i_0 a_7 -b_7'
    assert xor_seq[-3] == 'r_7 -i_1 d_7'
    assert xor_seq[-2] == 'r_7 i_1 -d_7'
    assert xor_seq[-1] == '-r_7 -i_1 -d_7'
