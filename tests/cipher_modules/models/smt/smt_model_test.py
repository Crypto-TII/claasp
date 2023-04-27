import pytest

from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.cipher_modules.models.utils import set_fixed_variables, integer_to_bit_list


def test_fix_variables_value_constraints():
    speck = SpeckBlockCipher(number_of_rounds=3)
    smt = SmtModel(speck)
    fixed_variables = [set_fixed_variables('plaintext', 'equal', range(4), integer_to_bit_list(5, 4, 'big'))]
    assert smt.fix_variables_value_constraints(fixed_variables) == ['(assert (not plaintext_0))',
                                                                    '(assert plaintext_1)',
                                                                    '(assert (not plaintext_2))',
                                                                    '(assert plaintext_3)']

    fixed_variables = [set_fixed_variables('plaintext', 'not_equal', range(4), integer_to_bit_list(5, 4, 'big'))]
    assert smt.fix_variables_value_constraints(fixed_variables) == [
        '(assert (or plaintext_0 (not plaintext_1) plaintext_2 (not plaintext_3)))']


def test_model_constraints():
    with pytest.raises(Exception):
        speck = SpeckBlockCipher(number_of_rounds=4)
        smt = SmtModel(speck)
        smt.model_constraints()
