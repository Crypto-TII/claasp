from claasp.components.permutation_component import Permutation
from claasp.ciphers.single_component_ciphers.permutation_cipher import PermutationCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel


PERMUTATION = [1, 3, 2, 0]


def make_permutation_component():
    return Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, PERMUTATION)


def test_constructor_builds_permutation_component():
    permutation_component = make_permutation_component()

    assert permutation_component.id == "permutation_0_0"
    assert permutation_component.type == "permutation"
    assert permutation_component.description == [[1, 3, 2, 0], 1]


def test_cp_constraints():
    permutation_component = make_permutation_component()
    declarations, constraints = permutation_component.cp_constraints()

    assert declarations == []
    assert constraints == [
        "constraint permutation_0_0[0] = input[3];",
        "constraint permutation_0_0[1] = input[0];",
        "constraint permutation_0_0[2] = input[2];",
        "constraint permutation_0_0[3] = input[1];",
    ]


def test_sat_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.sat_constraints()

    assert output_bit_ids == [
        "permutation_0_0_0",
        "permutation_0_0_1",
        "permutation_0_0_2",
        "permutation_0_0_3",
    ]
    assert constraints == [
        "permutation_0_0_0 -input_3",
        "input_3 -permutation_0_0_0",
        "permutation_0_0_1 -input_0",
        "input_0 -permutation_0_0_1",
        "permutation_0_0_2 -input_2",
        "input_2 -permutation_0_0_2",
        "permutation_0_0_3 -input_1",
        "input_1 -permutation_0_0_3",
    ]


def test_smt_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.smt_constraints()

    assert output_bit_ids == [
        "permutation_0_0_0",
        "permutation_0_0_1",
        "permutation_0_0_2",
        "permutation_0_0_3",
    ]
    assert constraints == [
        "(assert (= permutation_0_0_0 input_3))",
        "(assert (= permutation_0_0_1 input_0))",
        "(assert (= permutation_0_0_2 input_2))",
        "(assert (= permutation_0_0_3 input_1))",
    ]


def test_algebraic_polynomials():
    cipher = PermutationCipher(bit_size=4, permutation_description=[1, 3, 2, 0])
    permutation_component = cipher.component_from_id("permutation_0_0")
    algebraic = AlgebraicModel(cipher)
    algebraic_polynomials = permutation_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials) == '[permutation_0_0_y0 + permutation_0_0_x3,' \
                                         ' permutation_0_0_y1 + permutation_0_0_x0,' \
                                         ' permutation_0_0_y2 + permutation_0_0_x2,' \
                                         ' permutation_0_0_y3 + permutation_0_0_x1]'