from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher


def test_fsr_algebraic_polynomials():
    binary_cipher = FsrCipher(register_size=4)
    fsr_component = binary_cipher.get_component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(binary_cipher)
    binary_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in binary_polynomials] == [
        "fsr_0_0_y0 + fsr_0_0_x1",
        "fsr_0_0_y1 + fsr_0_0_x2",
        "fsr_0_0_y2 + fsr_0_0_x3",
        "fsr_0_0_y3 + fsr_0_0_x1 + fsr_0_0_x0",
    ]

    clocked_cipher = FsrCipher(register_size=4, description=[[[4, [[0], [1]], [[0]]]], 1])
    fsr_component = clocked_cipher.get_component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(clocked_cipher)
    clocked_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in clocked_polynomials] == [
        "fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y0",
        "fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y1 + fsr_0_0_x1",
        "fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_y2 + fsr_0_0_x2",
        "fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x0",
    ]

    word_cipher = FsrCipher(register_size=4, description=[[[2, [[1, [0]], [1, [1]]]]], 2])
    fsr_component = word_cipher.get_component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(word_cipher)
    word_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in word_polynomials] == [
        "fsr_0_0_y0 + fsr_0_0_x2",
        "fsr_0_0_y1 + fsr_0_0_x3",
        "fsr_0_0_y2 + fsr_0_0_x2 + fsr_0_0_x0",
        "fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x1",
    ]
