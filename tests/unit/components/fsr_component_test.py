import pytest

from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.ciphers.single_component_ciphers.fsr_cipher import FsrCipher


def test_fsr_algebraic_polynomials():
    binary_cipher = FsrCipher(register_size=4)
    fsr_component = binary_cipher.component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(binary_cipher)
    binary_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in binary_polynomials] == [
        "fsr_0_0_y0 + fsr_0_0_x1",
        "fsr_0_0_y1 + fsr_0_0_x2",
        "fsr_0_0_y2 + fsr_0_0_x3",
        "fsr_0_0_y3 + fsr_0_0_x1 + fsr_0_0_x0",
    ]

    clocked_cipher = FsrCipher(register_size=4, description=[[[4, [[0], [1]], [[0]]]], 1])
    fsr_component = clocked_cipher.component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(clocked_cipher)
    clocked_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in clocked_polynomials] == [
        "fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y0",
        "fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y1 + fsr_0_0_x1",
        "fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x2 + fsr_0_0_y2 + fsr_0_0_x2",
        "fsr_0_0_x0*fsr_0_0_x3 + fsr_0_0_x0*fsr_0_0_x1 + fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x0",
    ]

    word_cipher = FsrCipher(register_size=4, description=[[[2, [[1, [0]], [1, [1]]]]], 2])
    fsr_component = word_cipher.component_from_id("fsr_0_0")
    algebraic = AlgebraicModel(word_cipher)
    word_polynomials = fsr_component.algebraic_polynomials(algebraic)
    assert [str(polynomial) for polynomial in word_polynomials] == [
        "fsr_0_0_y0 + fsr_0_0_x2",
        "fsr_0_0_y1 + fsr_0_0_x3",
        "fsr_0_0_y2 + fsr_0_0_x2 + fsr_0_0_x0",
        "fsr_0_0_y3 + fsr_0_0_x3 + fsr_0_0_x1",
    ]


@pytest.mark.parametrize("feedback, expected", [([], 0), ([[]], 1), ([[], []], 0)])
@pytest.mark.parametrize("clock", [None, [], [[]], [[], []]])
def test_fsr_algebraic_polynomials_binary_constants(feedback, expected, clock):
    register = [2, feedback]
    if clock is not None:
        register.append(clock)
    cipher = FsrCipher(register_size=2, description=[[register], 1])
    component = cipher.component_from_id("fsr_0_0")
    model = AlgebraicModel(cipher)
    ring = model.ring()
    polynomials = component.algebraic_polynomials(model)
    for value in range(4):
        output = value if clock == [[], []] else ((value & 1) << 1) | expected
        assert cipher.evaluate([value]) == output
        assignment = {ring(f"fsr_0_0_{postfix}{i}"): (state >> (1 - i)) & 1
                      for postfix, state in [("x", value), ("y", output)] for i in range(2)}
        assert all(polynomial.subs(assignment) == 0 for polynomial in polynomials)
