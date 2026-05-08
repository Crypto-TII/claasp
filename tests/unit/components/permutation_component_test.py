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


def test_validation_zero_word_size():
    """Test that word_size=0 raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=0)
        assert False, "Expected ValueError for word_size=0"
    except ValueError as e:
        assert "word_size must be a positive integer" in str(e)


def test_validation_negative_word_size():
    """Test that negative word_size raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=-1)
        assert False, "Expected ValueError for negative word_size"
    except ValueError as e:
        assert "word_size must be a positive integer" in str(e)


def test_validation_non_integer_word_size():
    """Test that non-integer word_size raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [1, 3, 2, 0], word_size=1.5)
        assert False, "Expected ValueError for non-integer word_size"
    except ValueError as e:
        assert "word_size must be an integer" in str(e)


def test_validation_output_bit_size_not_divisible_by_word_size():
    """Test that output_bit_size not divisible by word_size raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4]], 5, [0], word_size=2)
        assert False, "Expected ValueError for output_bit_size not divisible by word_size"
    except ValueError as e:
        assert "output_bit_size" in str(e) and "divisible by word_size" in str(e)


def test_validation_permutation_description_wrong_length():
    """Test that permutation_description with wrong length raises ValueError."""
    try:
        # Expected length is 4 (8 bits / 2-bit words), but providing 3 entries
        Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [0, 1, 2], word_size=2)
        assert False, "Expected ValueError for wrong permutation_description length"
    except ValueError as e:
        assert "permutation_description length" in str(e) and "does not match expected length" in str(e)


def test_validation_permutation_description_duplicates():
    """Test that permutation_description with duplicates raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 1, 0])
        assert False, "Expected ValueError for duplicate values in permutation_description"
    except ValueError as e:
        assert "not a valid permutation" in str(e) and "duplicate values" in str(e)


def test_validation_permutation_description_out_of_range():
    """Test that permutation_description with out-of-range values raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 2, 5])
        assert False, "Expected ValueError for out-of-range values in permutation_description"
    except ValueError as e:
        assert "not a valid permutation" in str(e) and "out-of-range values" in str(e)


def test_validation_permutation_description_missing_values():
    """Test that permutation_description with missing values raises ValueError."""
    try:
        Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, [0, 1, 2, 2])
        assert False, "Expected ValueError for missing values in permutation_description"
    except ValueError as e:
        assert "not a valid permutation" in str(e) and "missing values" in str(e)


def test_validation_word_size_valid():
    """Test that valid word_size > 1 works correctly."""
    permutation_component = Permutation(0, 0, ["input"], [[0, 1, 2, 3, 4, 5, 6, 7]], 8, [1, 0], word_size=4)
    assert permutation_component.description == [[1, 0], 4]