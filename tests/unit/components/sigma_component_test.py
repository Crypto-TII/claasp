from claasp.components.sigma_component import Sigma


def make_sigma_component():
    return Sigma(0, 0, ["plaintext"], [list(range(8))], 8, [1, 2])


def test_constructor_sets_sigma_identity():
    sigma_component = make_sigma_component()

    assert sigma_component.id == "sigma_0_0"
    assert sigma_component.type == "linear_layer"
    assert sigma_component.input_bit_size == 8
    assert sigma_component.output_bit_size == 8


def test_cp_constraints():
    sigma_component = make_sigma_component()
    declarations, constraints = sigma_component.cp_constraints()

    assert declarations == []
    assert constraints[0] == "constraint sigma_0_0[0] = (plaintext[0] + plaintext[6] + plaintext[7]) mod 2;"
    assert constraints[-1] == "constraint sigma_0_0[7] = (plaintext[5] + plaintext[6] + plaintext[7]) mod 2;"


def test_sat_constraints():
    sigma_component = make_sigma_component()
    output_bit_ids, constraints = sigma_component.sat_constraints()

    assert output_bit_ids[0] == "sigma_0_0_0"
    assert output_bit_ids[-1] == "sigma_0_0_7"
    assert constraints[0] == "-sigma_0_0_0 plaintext_0 plaintext_6 plaintext_7"
    assert constraints[-1] == "sigma_0_0_7 -plaintext_5 -plaintext_6 -plaintext_7"


def test_smt_constraints():
    sigma_component = make_sigma_component()
    output_bit_ids, constraints = sigma_component.smt_constraints()

    assert output_bit_ids[0] == "sigma_0_0_0"
    assert output_bit_ids[-1] == "sigma_0_0_7"
    assert constraints[0] == "(assert (= sigma_0_0_0 (xor plaintext_0 plaintext_6 plaintext_7)))"
    assert constraints[-1] == "(assert (= sigma_0_0_7 (xor plaintext_5 plaintext_6 plaintext_7)))"
