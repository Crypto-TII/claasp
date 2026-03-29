"""
Usage-focused doctests for single component ciphers.

These examples intentionally focus on construction and simple evaluation calls
so usage remains clear while property-heavy checks stay in pytest.

EXAMPLES::

    sage: import warnings
    sage: warnings.filterwarnings("ignore", category=SyntaxWarning)

    sage: from claasp.ciphers.single_component_ciphers.and_cipher import AndCipher
    sage: AndCipher(word_bit_size=4, number_of_inputs=2).evaluate([0b1010, 0b1100])
    8

    sage: from claasp.ciphers.single_component_ciphers.or_cipher import OrCipher
    sage: OrCipher(word_bit_size=4, number_of_inputs=2).evaluate([0b1010, 0b1100])
    14

    sage: from claasp.ciphers.single_component_ciphers.xor_cipher import XorCipher
    sage: XorCipher(word_bit_size=4, number_of_inputs=2).evaluate([0b1010, 0b1100])
    6

    sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
    sage: ModaddCipher(word_bit_size=4, number_of_inputs=2).evaluate([11, 7])
    2

    sage: from claasp.ciphers.single_component_ciphers.modsub_cipher import ModsubCipher
    sage: ModsubCipher(word_bit_size=4, number_of_inputs=2).evaluate([11, 7])
    4

    sage: from claasp.ciphers.single_component_ciphers.modmul_cipher import ModmulCipher
    sage: ModmulCipher(word_bit_size=4, number_of_inputs=2).evaluate([3, 5])
    15

    sage: from claasp.ciphers.single_component_ciphers.idea_modmul_cipher import IdeaModmulCipher
    sage: IdeaModmulCipher(word_bit_size=16, number_of_inputs=2).evaluate([0x1234, 2])
    9320

    sage: from claasp.ciphers.single_component_ciphers.not_cipher import NotCipher
    sage: NotCipher(bit_size=4).evaluate([0b1010])
    5

    sage: from claasp.ciphers.single_component_ciphers.rotate_cipher import RotateCipher
    sage: RotateCipher(bit_size=8, parameter=1).evaluate([0b00000001])
    128

    sage: from claasp.ciphers.single_component_ciphers.reverse_cipher import ReverseCipher
    sage: ReverseCipher(bit_size=4).evaluate([0b1101])
    11

    sage: from claasp.ciphers.single_component_ciphers.shift_cipher import ShiftCipher
    sage: ShiftCipher(bit_size=8, parameter=1).type
    'hash_function'

    sage: from claasp.ciphers.single_component_ciphers.identity_cipher import IdentityCipher
    sage: IdentityCipher(block_bit_size=8).evaluate([0x5A])
    90

    sage: from claasp.ciphers.single_component_ciphers.constant_cipher import ConstantCipher
    sage: ConstantCipher(output_bit_size=8, value=0x5A).evaluate([])
    90

    sage: from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
    sage: PermutationCipher(bit_size=4, permutation_description=[3,2,1,0]).evaluate([0b1010])
    5

    sage: from claasp.ciphers.single_component_ciphers.linear_layer_cipher import LinearLayerCipher
    sage: LinearLayerCipher(bit_size=4).evaluate([0b1010])
    10

    sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
    sage: SboxCipher(bit_size=4).evaluate([0b1010])
    10

    sage: from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher
    sage: isinstance(ShiftRowsCipher(word_bit_size=8, rotation_amount=1, number_of_words=4).evaluate([0x12345678]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.sigma_cipher import SigmaCipher
    sage: isinstance(SigmaCipher(bit_size=8, rotation_amounts_parameter=[1,2]).evaluate([0xA5]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.theta_gaston_cipher import ThetaGastonCipher
    sage: isinstance(ThetaGastonCipher(bit_size=320, rotation_amounts_parameter=[1,18,23,25,32,52,60,63]).evaluate([0]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.theta_keccak_cipher import ThetaKeccakCipher
    sage: isinstance(ThetaKeccakCipher(bit_size=25).evaluate([0]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.theta_xoodoo_cipher import ThetaXoodooCipher
    sage: isinstance(ThetaXoodooCipher(bit_size=384).evaluate([0]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.variable_rotate_cipher import VariableRotateCipher
    sage: VariableRotateCipher(bit_size=8, amount_bit_size=3, direction=1).evaluate([0xA5, 0])
    165

    sage: from claasp.ciphers.single_component_ciphers.variable_shift_cipher import VariableShiftCipher
    sage: VariableShiftCipher(bit_size=8, amount_bit_size=3, direction=1).evaluate([0xA5, 0])
    165

    sage: from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher
    sage: isinstance(WordPermutationCipher(word_size=2, number_of_words=2, permutation_description=[1,0]).evaluate([0b1010]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.mix_column_cipher import MixColumnCipher
    sage: isinstance(MixColumnCipher(word_size=4).evaluate([0xABCD]), int)
    True

    sage: from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher
    sage: isinstance(FsrCipher(register_size=4).evaluate([0b1010]), int)
    True
"""
