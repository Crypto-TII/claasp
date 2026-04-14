from claasp.components.permutation_component import Permutation


PERMUTATION = [1, 3, 2, 0]


def make_permutation_component():
    return Permutation(0, 0, ["input"], [[0, 1, 2, 3]], 4, PERMUTATION)


def test_constructor_builds_permutation_matrix():
    permutation_component = make_permutation_component()

    assert permutation_component.id == "linear_layer_0_0"
    assert permutation_component.type == "linear_layer"
    assert permutation_component.description == [
        [0, 1, 0, 0],
        [0, 0, 0, 1],
        [0, 0, 1, 0],
        [1, 0, 0, 0],
    ]


def test_cp_constraints():
    permutation_component = make_permutation_component()
    result = permutation_component.cp_constraints()
    declarations, constraints = result.declarations, result.constraints

    assert declarations == []
    assert constraints == [
        "constraint linear_layer_0_0[0] = (input[3]) mod 2;",
        "constraint linear_layer_0_0[1] = (input[0]) mod 2;",
        "constraint linear_layer_0_0[2] = (input[2]) mod 2;",
        "constraint linear_layer_0_0[3] = (input[1]) mod 2;",
    ]


def test_sat_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.sat_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "-linear_layer_0_0_0 input_3",
        "linear_layer_0_0_0 -input_3",
        "-linear_layer_0_0_1 input_0",
        "linear_layer_0_0_1 -input_0",
        "-linear_layer_0_0_2 input_2",
        "linear_layer_0_0_2 -input_2",
        "-linear_layer_0_0_3 input_1",
        "linear_layer_0_0_3 -input_1",
    ]


def test_smt_constraints():
    permutation_component = make_permutation_component()
    output_bit_ids, constraints = permutation_component.smt_constraints()

    assert output_bit_ids == [
        "linear_layer_0_0_0",
        "linear_layer_0_0_1",
        "linear_layer_0_0_2",
        "linear_layer_0_0_3",
    ]
    assert constraints == [
        "(assert (= linear_layer_0_0_0 input_3))",
        "(assert (= linear_layer_0_0_1 input_0))",
        "(assert (= linear_layer_0_0_2 input_2))",
        "(assert (= linear_layer_0_0_3 input_1))",
    ]