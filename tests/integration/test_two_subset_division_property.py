"""Legacy division-property verdicts with a free, independently checked solver."""

import pytest

from claasp import Primitive, UnitArrayType
from claasp.analysis import TwoSubsetDivisionProperty, two_subset_transition_table
from claasp.components import ModularAdd
from claasp.drivers.solvers import GLPKSolver, HighsSolver
from claasp.primitives import Simon, Ublock
from claasp.unit_types import Word

pytestmark = pytest.mark.external


def test_two_bit_modular_addition_matches_atomic_todo_table():
    primitive = Primitive("adder", {"plaintext": UnitArrayType(Word(2), (2,))})
    primitive._builder.add_round()
    inputs = primitive.graph.input("plaintext")
    output = primitive._builder.add_component(ModularAdd(inputs[0], inputs[1]))
    primitive._builder.set_output(output)
    table = tuple(((x >> 2) + (x & 3)) & 3 for x in range(16))
    relation = two_subset_transition_table(table, 2)
    analysis = TwoSubsetDivisionProperty(primitive)
    for mask in range(1, 16):
        cube = [index for index in range(4) if mask & (1 << (3 - index))]
        verdicts = analysis.is_balanced_over_cube_scan([0, 1], cube)
        assert verdicts == {index: (mask, 1 << (1 - index)) not in relation for index in range(2)}


def test_legacy_five_round_ublock_balance_verdicts():
    cube = list(range(48, 64)) + list(range(112, 128))
    analysis = TwoSubsetDivisionProperty(Ublock(number_of_rounds=5))
    assert analysis.is_balanced_over_cube_scan(
        [0, 3], cube, solver=GLPKSolver(timeout_seconds=120)
    ) == {0: False, 3: True}


@pytest.mark.extended
def test_legacy_simon32_thirteen_round_integral():
    analysis = TwoSubsetDivisionProperty(Simon(number_of_rounds=13))
    verdicts = analysis.is_balanced_over_cube_scan(
        range(32), range(1, 32), solver=GLPKSolver(timeout_seconds=120)
    )
    assert [bit for bit, balanced in verdicts.items() if balanced] == list(range(16, 32))


def test_binary_affine_offsets_do_not_change_two_subset_balance():
    from claasp.components import BinaryAffineMap
    from claasp.unit_types import BinaryExtensionField

    for offset in range(4):
        primitive = Primitive(
            "affine", {"plaintext": UnitArrayType(BinaryExtensionField(2, 7), (2,))}
        )
        primitive._builder.add_round()
        output = primitive._builder.add_component(
            BinaryAffineMap(primitive.graph.input("plaintext"), ((0, 1), (1, 0)), offset)
        )
        primitive._builder.set_output(output)
        verdicts = TwoSubsetDivisionProperty(primitive).is_balanced_over_cube_scan(range(4), [0])
        assert verdicts == {0: True, 1: False, 2: True, 3: True}


@pytest.mark.extended
def test_legacy_keyless_ublock_and_lea_cases():
    from claasp.primitives import LEA

    cube = [index for index in range(128) if index not in (0, 1, 2, 3)]
    analysis = TwoSubsetDivisionProperty(Ublock(number_of_rounds=7), key_schedule="independent")
    assert analysis.is_balanced_at_specific_output_bit_over_cube(
        0, cube, solver=GLPKSolver(timeout_seconds=120)
    )
    analysis = TwoSubsetDivisionProperty(Ublock(number_of_rounds=6), key_schedule="removed")
    cube = list(range(36, 64)) + list(range(100, 128))
    assert not analysis.is_balanced_at_specific_output_bit_over_cube(
        1, cube, solver=GLPKSolver(timeout_seconds=120)
    )
    primitive = LEA(
        block_bit_size=128, key_bit_size=128, number_of_rounds=6, reorder_input_and_output=False
    )
    analysis = TwoSubsetDivisionProperty(primitive, key_schedule="removed")
    assert analysis.is_balanced_over_cube_scan(
        [36, 37], range(32), solver=HighsSolver(timeout_seconds=120)
    ) == {36: True, 37: False}


@pytest.mark.extended
def test_legacy_keccak100_three_round_cube():
    from claasp.primitives import KeccakSbox

    analysis = TwoSubsetDivisionProperty(KeccakSbox(number_of_rounds=3, word_size=4))
    assert analysis.is_balanced_at_all_output_bits_over_cube(
        [0, 4, 8, 12, 16, 20, 24], solver=GLPKSolver(timeout_seconds=120)
    )
    assert not analysis.is_balanced_at_all_output_bits_over_cube(
        range(7), solver=GLPKSolver(timeout_seconds=120)
    )
