from claasp.components.word_permutation_component import WordPermutation


def make_word_permutation_component():
    return WordPermutation(0, 0, ["plaintext"], [list(range(8))], 8, [1, 2, 3, 0], 2)


def test_constructor_builds_word_permutation_description():
    word_permutation_component = make_word_permutation_component()

    assert word_permutation_component.id == "mix_column_0_0"
    assert word_permutation_component.type == "mix_column"
    assert word_permutation_component.description[0] == [
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
        [1, 0, 0, 0],
    ]
    assert word_permutation_component.description[1] == 0
    assert word_permutation_component.description[2] == 2


def test_cp_constraints():
    word_permutation_component = make_word_permutation_component()
    declarations, constraints = word_permutation_component.cp_constraints()

    assert declarations == []
    assert constraints[0] == "constraint mix_column_0_0[0] = (plaintext[2]) mod 2;"
    assert constraints[-1] == "constraint mix_column_0_0[7] = (plaintext[1]) mod 2;"


def test_sat_constraints():
    word_permutation_component = make_word_permutation_component()
    output_bit_ids, constraints = word_permutation_component.sat_constraints()

    assert output_bit_ids[0] == "mix_column_0_0_0"
    assert output_bit_ids[-1] == "mix_column_0_0_7"
    assert constraints[0] == "-mix_column_0_0_0 plaintext_2"
    assert constraints[-1] == "mix_column_0_0_7 -plaintext_1"


def test_smt_constraints():
    word_permutation_component = make_word_permutation_component()
    output_bit_ids, constraints = word_permutation_component.smt_constraints()

    assert output_bit_ids[0] == "mix_column_0_0_0"
    assert output_bit_ids[-1] == "mix_column_0_0_7"
    assert constraints[0] == "(assert (= mix_column_0_0_0 plaintext_2))"
    assert constraints[-1] == "(assert (= mix_column_0_0_7 plaintext_1))"
