from claasp.components.theta_keccak_component import ThetaKeccak


def make_theta_keccak_component():
    return ThetaKeccak(0, 0, ["plaintext"], [list(range(25))], 25)


def test_constructor_sets_theta_keccak_identity():
    theta_component = make_theta_keccak_component()

    assert theta_component.id == "theta_keccak_0_0"
    assert theta_component.type == "linear_layer"
    assert theta_component.input_bit_size == 25
    assert theta_component.output_bit_size == 25


def test_cp_constraints():
    theta_component = make_theta_keccak_component()
    declarations, constraints = theta_component.cp_constraints()

    assert declarations == []
    assert constraints[0].startswith("constraint theta_keccak_0_0[0] = (")
    assert constraints[-1].startswith("constraint theta_keccak_0_0[24] = (")


def test_sat_constraints():
    theta_component = make_theta_keccak_component()
    output_bit_ids, constraints = theta_component.sat_constraints()

    assert output_bit_ids[0] == "theta_keccak_0_0_0"
    assert output_bit_ids[-1] == "theta_keccak_0_0_24"
    assert constraints[0].startswith("-theta_keccak_0_0_0 plaintext_0")
    assert constraints[-1].startswith("theta_keccak_0_0_24 -plaintext_0")


def test_smt_constraints():
    theta_component = make_theta_keccak_component()
    output_bit_ids, constraints = theta_component.smt_constraints()

    assert output_bit_ids[0] == "theta_keccak_0_0_0"
    assert output_bit_ids[-1] == "theta_keccak_0_0_24"
    assert constraints[0].startswith("(assert (= theta_keccak_0_0_0 (xor plaintext_0")
    assert constraints[-1].startswith("(assert (= theta_keccak_0_0_24 (xor plaintext_0")
