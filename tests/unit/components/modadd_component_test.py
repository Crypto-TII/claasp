from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=2)
    modadd_component = fancy.get_component_from_id("modadd_1_9")
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = modadd_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == "modadd_1_9_c0_0"
    assert str(algebraic_polynomials[1]) == "modadd_1_9_o0_0 + modadd_1_9_c0_0 + modadd_1_9_x6 + modadd_1_9_x0"
    assert str(algebraic_polynomials[-2]) == "modadd_1_9_o0_4*modadd_1_9_c1_4 + modadd_1_9_x16*modadd_1_9_c1_4 + " \
                                             "modadd_1_9_x16*modadd_1_9_o0_4 + modadd_1_9_c1_5"
    assert str(algebraic_polynomials[-1]) == "modadd_1_9_c1_5 + modadd_1_9_o0_5 + modadd_1_9_y5 + modadd_1_9_x17"
