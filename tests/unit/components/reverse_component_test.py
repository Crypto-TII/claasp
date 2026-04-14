from claasp.components.reverse_component import Reverse


def make_reverse_component():
    return Reverse(0, 0, ["input"], [[0, 1, 2, 3]], 4)


def test_constructor_builds_reverse_matrix():
    reverse_component = make_reverse_component()

    assert reverse_component.id == "linear_layer_0_0"
    assert reverse_component.type == "linear_layer"
    assert reverse_component.description == [
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [0, 1, 0, 0],
        [1, 0, 0, 0],
    ]


def test_cp_constraints():
    reverse_component = make_reverse_component()
    result = reverse_component.cp_constraints()
    declarations, constraints = result.declarations, result.constraints

    assert declarations == []
    assert constraints == [
        "constraint linear_layer_0_0[0] = (input[3]) mod 2;",
        "constraint linear_layer_0_0[1] = (input[2]) mod 2;",
        "constraint linear_layer_0_0[2] = (input[1]) mod 2;",
        "constraint linear_layer_0_0[3] = (input[0]) mod 2;",
    ]


def test_sat_constraints():
    reverse_component = make_reverse_component()
    output_bit_ids, constraints = reverse_component.sat_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "-linear_layer_0_0_0 input_3",
        "linear_layer_0_0_0 -input_3",
        "-linear_layer_0_0_1 input_2",
        "linear_layer_0_0_1 -input_2",
        "-linear_layer_0_0_2 input_1",
        "linear_layer_0_0_2 -input_1",
        "-linear_layer_0_0_3 input_0",
        "linear_layer_0_0_3 -input_0",
    ]


def test_smt_constraints():
    reverse_component = make_reverse_component()
    output_bit_ids, constraints = reverse_component.smt_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "(assert (= linear_layer_0_0_0 input_3))",
        "(assert (= linear_layer_0_0_1 input_2))",
        "(assert (= linear_layer_0_0_2 input_1))",
        "(assert (= linear_layer_0_0_3 input_0))",
    ]