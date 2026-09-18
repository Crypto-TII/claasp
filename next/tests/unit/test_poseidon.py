import pytest

from claasp_next.primitives import Poseidon
from claasp_next.representations.execution import ScalarEvaluator


def _direct_poseidon(state, modulus, exponent, full_rounds, partial_rounds, constants, matrix):
    result = list(state)
    first_half = full_rounds // 2
    for round_number, round_constants in enumerate(constants):
        result = [(value + constant) % modulus for value, constant in zip(result, round_constants)]
        is_full = round_number < first_half or round_number >= first_half + partial_rounds
        if is_full:
            result = [pow(value, exponent, modulus) for value in result]
        else:
            result[0] = pow(result[0], exponent, modulus)
        result = [
            sum(coefficient * value for coefficient, value in zip(row, result)) % modulus
            for row in matrix
        ]
    return tuple(result)


def test_toy_poseidon_matches_direct_round_function():
    modulus = 17
    exponent = 3
    full_rounds = 2
    partial_rounds = 1
    constants = ((1, 2, 3), (4, 5, 6), (7, 8, 9))
    matrix = ((2, 1, 1), (1, 2, 1), (1, 1, 2))
    state = (3, 5, 8)
    primitive = Poseidon(
        modulus,
        exponent,
        full_rounds,
        partial_rounds,
        constants,
        matrix,
    )

    result = ScalarEvaluator().evaluate(primitive, {"state": state})

    assert result.output == _direct_poseidon(
        state,
        modulus,
        exponent,
        full_rounds,
        partial_rounds,
        constants,
        matrix,
    )
    assert len(primitive.rounds) == 3
    assert [len(primitive_round.components) for primitive_round in primitive.rounds] == [4, 4, 4]


def test_poseidon_validates_structural_parameters():
    with pytest.raises(ValueError, match="positive even"):
        Poseidon(17, 3, 3, 1, ((0,),) * 4, ((1,),))

    with pytest.raises(ValueError, match="coprime"):
        Poseidon(17, 2, 2, 0, ((0,),) * 2, ((1,),))

    with pytest.raises(ValueError, match="square matrix"):
        Poseidon(17, 3, 2, 0, ((0, 0),) * 2, ((1, 0),))


def test_poseidon_width_one_partial_round_needs_no_concatenation():
    primitive = Poseidon(
        modulus=17,
        exponent=3,
        full_rounds=2,
        partial_rounds=1,
        round_constants=((1,), (2,), (3,)),
        linear_layer=((1,),),
    )

    result = ScalarEvaluator().evaluate(primitive, {"state": (4,)})

    assert result.output is not None
    assert all(not component.component_id.startswith("concatenate") for component in primitive.components)
