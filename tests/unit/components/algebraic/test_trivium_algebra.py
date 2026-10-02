"""Exact algebraic evidence for the reduced Trivium keystream function.

Every polynomial asserted here is newly derived in v5 by exact sparse ANF
expansion and is then re-checked by concrete evaluation of the same typed
graph, which shares no code with the symbolic evaluator.  The legacy Gurobi
suite stated comparable Trivium expectations, but each of its tests carries
``@pytest.mark.skip(reason="Requires Gurobi license")`` and therefore never ran,
so those literals are treated as claims to be confirmed, never as oracles.
"""

from random import Random

import pytest

from claasp.analysis import analyze_boolean_algebra, evaluate_cube_sum
from claasp.primitives import Trivium
from claasp.representations.execution import (
    BooleanDegreeEvaluator,
    BooleanSymbolicEvaluator,
)

#: Exact IV-only monomials of maximal IV degree in the Trivium-200 keystream
#: bit; each has cube coefficient ``1``.
TRIVIUM_200_TOP_IV_CUBES = (
    (20, 22, 23),
    (21, 22, 23),
    (21, 22, 36),
    (22, 23, 35),
)


def _bit(value, position, width=80):
    return (value >> (width - 1 - position)) & 1


@pytest.fixture(scope="module")
def trivium_13_anf():
    primitive = Trivium(number_of_initialization_clocks=13, keystream_bit_size=1)
    return primitive, BooleanSymbolicEvaluator().evaluate(primitive).output_anfs[0]


@pytest.fixture(scope="module")
def trivium_200():
    return Trivium(number_of_initialization_clocks=200, keystream_bit_size=1)


@pytest.fixture(scope="module")
def trivium_200_anf(trivium_200):
    return BooleanSymbolicEvaluator().evaluate(trivium_200).output_anfs[0]


def test_thirteen_clock_keystream_bit_has_an_exact_linear_anf(trivium_13_anf):
    _, polynomial = trivium_13_anf

    assert sorted(term.variables for term in polynomial.monomials) == [
        ("i24",),
        ("i9",),
        ("k0",),
        ("k27",),
    ]
    assert polynomial.degree == 1


def test_thirteen_clock_anf_is_confirmed_by_concrete_evaluation(trivium_13_anf):
    primitive, _ = trivium_13_anf
    random = Random(20250914)
    points = [(0, 0)] + [(random.getrandbits(80), random.getrandbits(80)) for _ in range(200)]

    for key, iv in points:
        expected = _bit(iv, 9) ^ _bit(iv, 24) ^ _bit(key, 0) ^ _bit(key, 27)
        assert primitive.evaluate(key=key, iv=iv) == expected


def test_two_hundred_clock_exact_anf_degree_and_size(trivium_200_anf):
    assert trivium_200_anf.degree == 3
    assert len(trivium_200_anf.monomials) == 58
    assert (
        max(
            sum(1 for variable in term.variables if variable.startswith("i"))
            for term in trivium_200_anf.monomials
        )
        == 3
    )


def test_two_hundred_clock_superpoly_of_the_single_iv_cube(trivium_200):
    evidence = analyze_boolean_algebra(
        trivium_200,
        cube=("i53",),
        fixed_variables={f"i{index}": 0 for index in range(80) if index != 53},
    )

    assert evidence.complete and evidence.method == "exact_sparse_anf"
    assert evidence.cube_degrees == (2,)
    assert sorted(term.variables for term in evidence.cube_coefficients[0].monomials) == [
        ("k39",),
        ("k40", "k41"),
        ("k66",),
    ]


def test_two_hundred_clock_superpoly_is_confirmed_by_exhaustive_cube_sums(trivium_200):
    support = (39, 40, 41, 66)
    random = Random(668)
    keys = [
        sum(
            ((assignment >> index) & 1) << (79 - position) for index, position in enumerate(support)
        )
        for assignment in range(1 << len(support))
    ] + [random.getrandbits(80) for _ in range(8)]

    for key in keys:
        checked = evaluate_cube_sum(
            trivium_200,
            {"key": key, "iv": 0},
            variable_input="iv",
            cube_positions=(53,),
            output_bit=0,
        )
        expected = _bit(key, 39) ^ (_bit(key, 40) & _bit(key, 41)) ^ _bit(key, 66)
        assert checked.complete and checked.evaluations == 2
        assert checked.parity == expected


@pytest.mark.parametrize("cube", TRIVIUM_200_TOP_IV_CUBES)
def test_top_iv_cubes_have_coefficient_one_for_every_key(trivium_200, trivium_200_anf, cube):
    names = tuple(f"i{position}" for position in cube)

    assert [term.variables for term in trivium_200_anf.cube_coefficient(names).monomials] == [()]
    for key in (0, 1 << 79, 0x0123456789ABCDEF0123, (1 << 80) - 1):
        checked = evaluate_cube_sum(
            trivium_200,
            {"key": key, "iv": 0},
            variable_input="iv",
            cube_positions=cube,
            output_bit=0,
        )
        assert checked.parity == 1 and checked.evaluations == 8


def test_an_absent_iv_cube_sums_to_zero(trivium_200, trivium_200_anf):
    absent = (20, 21, 22)

    assert trivium_200_anf.cube_coefficient(("i20", "i21", "i22")).degree == -1
    checked = evaluate_cube_sum(
        trivium_200,
        {"key": 0x0123456789ABCDEF0123, "iv": 0},
        variable_input="iv",
        cube_positions=absent,
        output_bit=0,
    )
    assert checked.parity == 0


def test_structural_iv_degree_bound_is_sound_but_not_tight(trivium_200, trivium_200_anf):
    bound = BooleanDegreeEvaluator().evaluate(trivium_200, "iv")
    exact = max(
        sum(1 for variable in term.variables if variable.startswith("i"))
        for term in trivium_200_anf.monomials
    )

    assert bound.output_bounds == (4,)
    assert bound.sound and not bound.complete
    assert exact == 3 < bound.output_bounds[0]
