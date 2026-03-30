from claasp.components.shift_rows_component import ShiftRows
from claasp.ciphers.single_component_ciphers.shift_rows_cipher import ShiftRowsCipher


def make_shift_rows_component():
    return ShiftRows(0, 0, ["plaintext"], [list(range(8))], 8, 2)


def make_shift_rows_cipher():
    return ShiftRowsCipher(rotation_amount=1, word_bit_size=2, number_of_words=4)


def test_constructor_sets_shift_rows_identity():
    shift_rows_component = make_shift_rows_component()

    assert shift_rows_component.id == "shift_rows_0_0"
    assert shift_rows_component.type == "word_operation"
    assert shift_rows_component.description == ["ROTATE", 2]


def test_cp_constraints():
    cipher = make_shift_rows_cipher()
    shift_rows_component = cipher.component_from(0, 0)
    declarations, constraints = shift_rows_component.cp_constraints()

    assert declarations == []
    assert constraints[0] == "constraint shift_rows_0_0[0] = plaintext[6];"
    assert constraints[-1] == "constraint shift_rows_0_0[7] = plaintext[5];"


def test_sat_constraints():
    cipher = make_shift_rows_cipher()
    shift_rows_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = shift_rows_component.sat_constraints()

    assert output_bit_ids[0] == "shift_rows_0_0_0"
    assert output_bit_ids[-1] == "shift_rows_0_0_7"
    assert constraints[0] == "shift_rows_0_0_0 -plaintext_6"
    assert constraints[-1] == "plaintext_5 -shift_rows_0_0_7"


def test_smt_constraints():
    cipher = make_shift_rows_cipher()
    shift_rows_component = cipher.component_from(0, 0)
    output_bit_ids, constraints = shift_rows_component.smt_constraints()

    assert output_bit_ids[0] == "shift_rows_0_0_0"
    assert output_bit_ids[-1] == "shift_rows_0_0_7"
    assert constraints[0] == "(assert (= shift_rows_0_0_0 plaintext_6))"
    assert constraints[-1] == "(assert (= shift_rows_0_0_7 plaintext_5))"