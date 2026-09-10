from claasp.components.word_permutation_component import WordPermutation


def make_word_permutation_component():
    return WordPermutation(0, 0, ["plaintext"], [list(range(8))], 8, [1, 2, 3, 0], 2)


def test_constructor_builds_word_permutation_description():
    word_permutation_component = make_word_permutation_component()

    assert word_permutation_component.id == "permutation_0_0"
    assert word_permutation_component.type == "permutation"
    # permutation_description=[1, 2, 3, 0] uses the destination-takes-from-source convention
    # (output[i] = input[permutation_description[i]]); Permutation stores the inverted
    # source-to-destination description, i.e. [3, 0, 1, 2], together with the word size.
    assert word_permutation_component.description == [[3, 0, 1, 2], 2]


def test_cp_constraints():
    word_permutation_component = make_word_permutation_component()
    declarations, constraints = word_permutation_component.cp_constraints()

    assert declarations == []
    assert constraints[0] == "constraint permutation_0_0[0] = plaintext[2];"
    assert constraints[-1] == "constraint permutation_0_0[7] = plaintext[1];"


def test_sat_constraints():
    word_permutation_component = make_word_permutation_component()
    output_bit_ids, constraints = word_permutation_component.sat_constraints()

    assert output_bit_ids[0] == "permutation_0_0_0"
    assert output_bit_ids[-1] == "permutation_0_0_7"
    assert constraints[0] == "permutation_0_0_0 -plaintext_2"
    assert constraints[-1] == "plaintext_1 -permutation_0_0_7"


def test_smt_constraints():
    word_permutation_component = make_word_permutation_component()
    output_bit_ids, constraints = word_permutation_component.smt_constraints()

    assert output_bit_ids[0] == "permutation_0_0_0"
    assert output_bit_ids[-1] == "permutation_0_0_7"
    assert constraints[0] == "(assert (= permutation_0_0_0 plaintext_2))"
    assert constraints[-1] == "(assert (= permutation_0_0_7 plaintext_1))"


def test_algebraic_polynomials_word_size_greater_than_one():
    from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher
    from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel

    cipher = WordPermutationCipher(word_size=2, number_of_words=4, permutation_description=[1, 2, 3, 0])
    component = cipher.component_from_id("permutation_0_0")
    algebraic = AlgebraicModel(cipher)
    polynomials = component.algebraic_polynomials(algebraic)

    ring_r = algebraic.ring()
    x = [ring_r(f"{component.id}_x{i}") for i in range(component.input_bit_size)]
    y = [ring_r(f"{component.id}_y{i}") for i in range(component.output_bit_size)]
    # output[i] = input[permutation_description[i]] word-wise, expanded bit-wise via word_size=2.
    expected_input_bit_of_output = [2, 3, 4, 5, 6, 7, 0, 1]
    expected = [y[i] + x[expected_input_bit_of_output[i]] for i in range(component.output_bit_size)]
    assert polynomials == expected


def test_milp_constraints_word_size_greater_than_one():
    from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher
    from claasp.cipher_modules.models.milp.milp_model import MilpModel

    cipher = WordPermutationCipher(word_size=2, number_of_words=4, permutation_description=[1, 2, 3, 0])
    component = cipher.component_from_id("permutation_0_0")
    milp = MilpModel(cipher)
    milp.init_model_in_sage_milp_class()
    variables, constraints = component.milp_constraints(milp)

    assert len(variables) == component.input_bit_size + component.output_bit_size
    assert len(constraints) == component.output_bit_size
