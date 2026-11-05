"""CRAFT numerical regression cases and independent non-CRAFT SPN checks.

TODO: Add a public reference for the CRAFT-specific regression cases when available.
"""

from fractions import Fraction
from itertools import product

import pytest

from claasp.analysis.circle_linear_trails import CircleLinearTrailModel
from claasp.primitives import Craft
from claasp.primitives.block_ciphers.craft import CRAFT_SBOX, CRAFT_TWEAK_PERMUTATION
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_linear import CircleAffineLayer

REFERENCE_CASES = (
    (8, 0x725A0000, 0x01190000, 8, 24, 120),
    (10, 0x45050000, 0x10050000, 12, 16, 118),
    (12, 0x2B8E0000, 0x10050000, 18, 16, 116),
    (14, 0x44260000, 0x00720000, 22, 16, 108),
    (16, 0x8A0A0000, 0x00670000, 26, 32, 110),
    (18, 0x174D0000, 0x00670000, 32, 32, 110),
)


@pytest.mark.parametrize("rounds,input_code,output_code,cost,count,key_bits", REFERENCE_CASES)
def test_reference_complete_search_and_exact_key_classes(
    rounds, input_code, output_code, cost, count, key_bits
):
    model = Craft(number_of_rounds=rounds).circle_linear_trail_model()
    trail = model.trail(output_code)
    assert (trail.input_code, trail.cost) == (input_code, cost)
    assert trail.conditions.key_count == 1 << key_bits
    assert abs(trail.contribution(0)) == Fraction(1, 1 << cost)
    result = model.search()
    assert (result.cost, result.optimal_mask_count) == (cost, count)
    assert result.complete and result.scope == "four-element perfect subgroup"
    assert result.representative.output_code == output_code
    assert result.representative.conditions == trail.conditions


def test_reference_18_round_masks_and_wrong_key_exclusion():
    trail = Craft(number_of_rounds=18).circle_linear_trail_model().trail(0x00670000)
    assert trail.input_mask == 0x7077007077707000
    assert trail.output_mask == 0x7770077000000000
    assert trail.conditions.contains(0)
    assert not trail.conditions.contains(1)
    assert trail.contribution(1) == 0


def test_affine_column_all_type_patterns_and_key_quotient_classes():
    brace = BinaryBibrace.craft()
    basis = CircleBasis((brace,) * 4)
    cell_rows = (13, 10, 4, 8)
    binary = tuple(
        sum(1 << (4 * (3 - j) + bit) for j in range(4) if cell_rows[3 - i] >> j & 1)
        for i in range(4)
        for bit in range(4)
    )
    layer = CircleAffineLayer(
        basis, basis, binary, key_width=16, key_rows=tuple(1 << i for i in range(16))
    )
    representatives = (0, 1, 8, 9)
    values = [
        sum(c << (4 * (3 - i)) for i, c in enumerate(cells))
        for cells in product(representatives, repeat=4)
    ]
    # Independent direct character sums on quotient representatives. The phase
    # is constant on each annihilator coset, so each value occurs 4**4 times.
    for pattern in range(16):
        labels = [9 if pattern >> (3 - i) & 1 else 0 for i in range(4)]
        output = sum(c << (4 * (3 - i)) for i, c in enumerate(labels))
        before = (labels[0], labels[1], labels[0] ^ labels[2], labels[0] ^ labels[1] ^ labels[3])
        inp = sum(c << (4 * (3 - i)) for i, c in enumerate(before))
        transition = layer.transition(inp, output)
        cost = 2 * ((pattern >> 3 & 1) + (pattern >> 2 & 1))
        assert transition.magnitude == Fraction(1, 1 << cost)
        for key in values:
            coefficient = transition.coefficient(key)
            assert bool(coefficient) == transition.conditions.contains(key)
            assert not coefficient or abs(coefficient) == Fraction(1, 1 << cost)
        # Use all state cosets for a varied subset of fixed key cosets.
        for key in values[::17]:
            total = 0
            for x in values:
                cells = [(x >> (4 * (3 - i))) & 15 for i in range(4)]
                y = (
                    ((cells[0] ^ cells[2] ^ cells[3]) << 12)
                    | ((cells[1] ^ cells[3]) << 8)
                    | (cells[2] << 4)
                    | cells[3]
                )
                total += (-1) ** (basis.character(inp, x) ^ basis.character(output, y ^ key))
            assert transition.coefficient(key) == Fraction(total, 256)


def test_other_spn_matches_full_unsplit_enumeration_and_handles_zero_cost_kernel():
    for rounds in (1, 2, 3, 4):
        model = CircleLinearTrailModel(BinaryBibrace.craft(), CRAFT_SBOX, (3, 2), (1, 0), rounds)
        all_trails = [model.trail(code) for code in range(1, 16)]
        best = min(t.cost for t in all_trails)
        result = model.search()
        assert result.cost == best
        assert result.optimal_mask_count == sum(t.cost == best for t in all_trails)
    assert (
        CircleLinearTrailModel(BinaryBibrace.craft(), CRAFT_SBOX, (1,), (0,), 1).search().cost == 0
    )


def test_no_craft_assumption_about_involutory_cell_permutation():
    model = CircleLinearTrailModel(BinaryBibrace.craft(), CRAFT_SBOX, (3, 2, 4), (1, 2, 0), 3)
    trails = [model.trail(code) for code in range(1, 64)]
    result = model.search()
    assert result.cost == min(t.cost for t in trails)
    assert result.optimal_mask_count == sum(t.cost == result.cost for t in trails)


def test_generic_round_products_against_independent_complete_truth_tables():
    from claasp.semantics.cryptanalysis.circle_linear import CircleLookupLayer

    model = CircleLinearTrailModel(BinaryBibrace.craft(), CRAFT_SBOX, (3, 2), (1, 0), 3)

    def one_round(x):
        left, right = x >> 4, x & 15
        mixed = (left ^ right, right)
        return (CRAFT_SBOX[mixed[1]] << 4) | CRAFT_SBOX[mixed[0]]

    whole_round = CircleLookupLayer(
        model.basis, model.basis, tuple(one_round(x) for x in range(256))
    )
    for code in range(1, 16):
        trail = model.trail(code)
        output = trail.output_mask
        direct = Fraction(1)
        for affine_step in trail._affine_steps:
            direct *= whole_round.coefficient(affine_step.input_mask, output)
            output = affine_step.input_mask
        assert direct == trail.contribution(0)


def test_round_offset_changes_key_half_but_not_cost_or_class_size():
    zero = Craft(number_of_rounds=8).circle_linear_trail_model().trail(0x01190000)
    shifted = (
        Craft(number_of_rounds=8, round_offset=1).circle_linear_trail_model().trail(0x01190000)
    )
    assert shifted.cost == zero.cost
    assert shifted.conditions.key_count == zero.conditions.key_count
    assert shifted.conditions != zero.conditions


def test_tweak_can_make_key_conditions_inconsistent_and_is_never_averaged():
    # The 8-round reference case constrains repeated K1 nibble 10.
    zero = Craft(number_of_rounds=8).circle_linear_trail_model(tweak=0).trail(0x01190000)
    assert zero.conditions.consistent
    saw_incompatible = False
    for i in range(16):
        trail = (
            Craft(number_of_rounds=8)
            .circle_linear_trail_model(tweak=1 << (4 * i))
            .trail(0x01190000)
        )
        if not trail.conditions.consistent:
            saw_incompatible = True
            assert trail.contribution(0) == 0
    assert saw_incompatible


@pytest.mark.parametrize(
    "rounds,output_code,tweak_bits",
    [
        (8, 0x01190000, 60),
        (10, 0x10050000, 60),
        (12, 0x10050000, 58),
        (14, 0x00720000, 54),
        (16, 0x00670000, 52),
        (18, 0x00670000, 52),
    ],
)
def test_reference_admissible_tweak_counts_by_existential_key_elimination(
    rounds, output_code, tweak_bits
):
    base = Craft(number_of_rounds=rounds).circle_linear_trail_model()
    layers = []
    for r, layer in enumerate(base.affine_layers):
        key_rows = []
        for bit, key_row in enumerate(layer.key_rows):
            cell, within = 15 - bit // 4, bit % 4
            source = cell if r % 4 < 2 else CRAFT_TWEAK_PERMUTATION[cell]
            key_rows.append(key_row | (1 << (128 + 4 * (15 - source) + within)))
        layers.append(
            CircleAffineLayer(
                layer.input_basis,
                layer.output_basis,
                layer.rows,
                layer.offset,
                192,
                tuple(key_rows),
            )
        )
    model = CircleLinearTrailModel(
        base.bibrace,
        base.sbox,
        base.diffusion_rows,
        base.permutation,
        rounds,
        affine_layers=tuple(layers),
    )
    joint = model.trail(output_code).conditions
    tweaks = joint.project(tuple(range(128, 192)))
    assert tweaks.key_count == 1 << tweak_bits
    assert tweaks.contains(0)


def test_missing_perfect_subgroup_and_search_limits_are_explicit():
    with pytest.raises(ValueError, match="free type flip"):
        CircleLinearTrailModel(BinaryBibrace.craft(), tuple(range(16)), (1,), (0,), 1)
    with pytest.raises(ValueError, match="maximum_factor_states"):
        Craft(number_of_rounds=8).circle_linear_trail_model().search(maximum_factor_states=100)
    with pytest.raises(ValueError, match="special final round"):
        Craft().circle_linear_trail_model()


def test_type_flip_alone_is_not_enough_for_complete_deterministic_search():
    brace = BinaryBibrace.craft()

    def conjugated(x):
        a, b, c, d = ((x >> i) & 1 for i in range(4))
        return a | ((b ^ (a & c)) << 1) | ((c ^ a) << 2) | ((d ^ (a & b)) << 3)

    table = tuple(brace.theta(conjugated(brace.theta(x))) for x in range(16))
    walsh = brace.walsh_table(table)
    assert {(a, b) for a in range(16) for b in range(16) if abs(walsh[a][b]) == 16} == {
        (0, 0),
        (1, 1),
        (4, 5),
        (5, 4),
    }
    # Here eta=5 lies in Lambda: other nonzero diffusion entries can stay in F.
    # Exact bounded networks remain applicable, but the factor search is not.
    with pytest.raises(ValueError, match="mask-displacement"):
        CircleLinearTrailModel(brace, table, (3, 2), (1, 0), 2)
