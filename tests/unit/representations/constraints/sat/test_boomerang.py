from fractions import Fraction
from itertools import product

import pytest

from claasp.primitives import ChaChaPermutation, Present, Speck, ToySpeck
from claasp.representations.constraints.sat._boomerang_switch import _TABLE
from claasp.representations.constraints.sat.boomerang import BoomerangSATModel
from claasp.semantics.cryptanalysis import (
    ModularAddBoomerangAutomaton,
    ModularAddBoomerangSemantics,
)


def _legacy_accepts(width, values):
    state: tuple[bool, ...] = (True, False, False, False)
    halves = 0
    for bit in range(width - 1):
        bits = tuple((value >> bit) & 1 for value in values)
        columns = [next(row[4:8] for row in rows if tuple(row[:4]) == bits) for rows in _TABLE]
        matrix = [[columns[column][row] for column in range(4)] for row in range(4)]
        following = tuple(
            any(matrix[row][column] and state[column] for column in range(4)) for row in range(4)
        )
        if not any(following):
            return False
        half = any(state[j] and not matrix[j][j] for j in range(4))
        halves += half
        if halves > 1 or (
            not half and any(state[j] and (not matrix[j][j] or not following[j]) for j in range(4))
        ):
            return False
        state = following
    return True


@pytest.mark.parametrize("width", [1, 2, 3])
def test_every_small_legacy_switch_has_independently_counted_probability_at_least_half(width):
    exact = ModularAddBoomerangAutomaton(width)
    exhaustive = ModularAddBoomerangSemantics(width)
    accepted = 0
    for differences in product(range(1 << width), repeat=4):
        if not _legacy_accepts(width, differences):
            continue
        entry = exact.connectivity(*differences)
        assert entry.count == exhaustive.connectivity(*differences).count
        assert Fraction(entry.count, 1 << (2 * width)) >= Fraction(1, 2)
        accepted += 1
    assert accepted == {1: 16, 2: 160, 3: 2176}[width]


@pytest.mark.parametrize(
    "primitive,round_number,switches,state_words",
    [
        (ToySpeck(3), 1, 1, 2),
        (Speck(number_of_rounds=8), 4, 1, 2),
        (ChaChaPermutation(number_of_rounds=8, round_mode="half"), 4, 4, 16),
    ],
)
def test_automatic_cuts_cover_original_speck_and_parallel_chacha_experiments(
    primitive, round_number, switches, state_words
):
    model = BoomerangSATModel(primitive, switch_round=round_number)
    assert len(model.switches) == switches
    assert len(model.pre) == len(model.post) == state_words
    assert primitive.graph.secret_inputs == model.upper.graph.secret_inputs
    formula = model.cnf_formula(maximum_weight=2)
    assert formula.constraint_models[-1].component_ids == model.switches


def test_unsupported_or_dependent_middle_components_fail_explicitly():
    with pytest.raises(NotImplementedError, match="Word graph|does not support"):
        BoomerangSATModel(Present(number_of_rounds=2))
    with pytest.raises(ValueError, match="independent"):
        BoomerangSATModel(ToySpeck(3), components=("modular_add_0_1", "modular_add_1_1"))
    with pytest.raises(ValueError, match="not both"):
        BoomerangSATModel(ToySpeck(3), switch_round=1, components="modular_add_1_1")


def test_repeated_formula_build_is_stable_and_unsupported_bounds_are_rejected():
    model = BoomerangSATModel(ToySpeck(3), switch_round=1)
    assert model.cnf_formula(maximum_weight=3) == model.cnf_formula(maximum_weight=3)
    with pytest.raises(ValueError, match="nonnegative integer"):
        model.cnf_formula(maximum_weight=True)


def test_legacy_halving_flag_is_not_an_exact_probability_threshold():
    # The old heuristic accepts this width-four switch despite its exact 1/4
    # probability. Preserve its search set and report the actual local count.
    differences = (4, 0, 1, 4)
    assert _legacy_accepts(4, differences)
    assert ModularAddBoomerangSemantics(4).connectivity(*differences).count == 64
    assert ModularAddBoomerangAutomaton(4).connectivity(*differences).count == 64
