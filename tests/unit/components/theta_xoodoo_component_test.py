from claasp.components.theta_xoodoo_component import ThetaXoodoo


def make_theta_xoodoo_component():
    return ThetaXoodoo(0, 0, ["plaintext"], [list(range(384))], 384)


def test_constructor_sets_theta_xoodoo_identity():
    theta_component = make_theta_xoodoo_component()

    assert theta_component.id == "theta_xoodoo_0_0"
    assert theta_component.type == "linear_layer"
    assert theta_component.input_bit_size == 384
    assert theta_component.output_bit_size == 384
    assert len(theta_component.description) == 384
