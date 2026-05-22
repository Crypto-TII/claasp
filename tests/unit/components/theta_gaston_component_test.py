from claasp.components.theta_gaston_component import ThetaGaston

ROTATIONS = [1, 18, 23, 25, 32, 52, 60, 63]


def make_theta_gaston_component():
    return ThetaGaston(0, 0, ["plaintext"], [list(range(320))], 320, ROTATIONS)


def test_constructor_sets_theta_gaston_identity():
    theta_component = make_theta_gaston_component()

    assert theta_component.id == "theta_gaston_0_0"
    assert theta_component.type == "linear_layer"
    assert theta_component.input_bit_size == 320
    assert theta_component.output_bit_size == 320
    assert len(theta_component.description) == 320
