from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.ciphers.stream_ciphers.a5_1_stream_cipher import A51StreamCipher
from claasp.ciphers.stream_ciphers.trivium_stream_cipher import TriviumStreamCipher
from claasp.ciphers.stream_ciphers.snow3g_stream_cipher import Snow3GStreamCipher


def test_fsr_algebraic_polynomials():
    a51 = A51StreamCipher()
    fsr_component = a51.get_component_from_id("fsr_1_0")
    algebraic = AlgebraicModel(a51)
    A = fsr_component.algebraic_polynomials(algebraic)
    assert (
        str(A[0])
        == "fsr_1_0_x1*fsr_1_0_x30*fsr_1_0_x53 + fsr_1_0_x1*fsr_1_0_x10*fsr_1_0_x53 + fsr_1_0_x1*fsr_1_0_x10*fsr_1_0_x30 + fsr_1_0_x0*fsr_1_0_x30*fsr_1_0_x53 + fsr_1_0_x0*fsr_1_0_x10*fsr_1_0_x53 + fsr_1_0_x0*fsr_1_0_x10*fsr_1_0_x30 + fsr_1_0_x1*fsr_1_0_x10 + fsr_1_0_x0*fsr_1_0_x10 + fsr_1_0_y0 + fsr_1_0_x1"
    )

    trivium = TriviumStreamCipher(number_of_initialization_clocks=1, keystream_bit_len=1)
    fsr_component = trivium.get_component_from_id("fsr_0_2")
    algebraic = AlgebraicModel(trivium)
    T = fsr_component.algebraic_polynomials(algebraic)
    assert str(T[92]) == "fsr_0_2_x178*fsr_0_2_x179 + fsr_0_2_y92 + fsr_0_2_x222 + fsr_0_2_x177 + fsr_0_2_x24"

    snow = Snow3GStreamCipher(number_of_initialization_clocks=1, keystream_word_size=1)
    fsr_component = snow.get_component_from_id("fsr_0_714")
    algebraic = AlgebraicModel(snow)
    S = fsr_component.algebraic_polynomials(algebraic)
    assert str(S[480]) == "fsr_0_714_y480 + fsr_0_714_x352 + fsr_0_714_x64 + fsr_0_714_x0"
