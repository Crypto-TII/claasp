"""Atomic QDT formula validity and weights checked against exhaustive coefficients."""

from fractions import Fraction
from itertools import product

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import BinaryAffineMap, BitwiseAnd, BitwiseOr, ModularAdd, ModularSubtract
from claasp.primitives import BitVectorSBox
from claasp.primitives.toy_primitives.heys import HEYS_SBOX
from claasp.representations.constraints.sat.quasidifferential import QuasidifferentialSATModel
from claasp.semantics.cryptanalysis.quasidifferential import QuasidifferentialSemantics as Q
from claasp.unit_types import BinaryExtensionField, Word


def _unit_witness(formula):
    """Unit propagation suffices when all physical boundary bits are fixed."""
    assigned = {}
    clauses = list(formula.clauses)
    while True:
        remaining = []
        changed = False
        for clause in clauses:
            if any(abs(bit) in assigned and assigned[abs(bit)] == (bit > 0) for bit in clause):
                continue
            unknown = [bit for bit in clause if abs(bit) not in assigned]
            if not unknown:
                return None
            if len(unknown) == 1:
                bit = unknown[0]
                assigned[abs(bit)] = bit > 0
                changed = True
            else:
                remaining.append(tuple(unknown))
        clauses = remaining
        if not clauses:
            return {
                name: assigned.get(index, False) for index, name in enumerate(formula.variables, 1)
            }
        if not changed:
            raise AssertionError("fixed-boundary relation unexpectedly requires search")


def _operator(kind, width):
    primitive = Primitive("atomic", {"plaintext": UnitArrayType(Word(width), (2,))})
    primitive._builder.add_round()
    inputs = primitive.graph.input("plaintext")
    output = primitive._builder.add_component(
        kind(inputs[0], inputs[1]) if kind is ModularAdd else kind((inputs[0], inputs[1]))
    )
    primitive._builder.set_output(output)
    return primitive


@pytest.mark.parametrize("kind", [ModularAdd, ModularSubtract])
def test_all_two_bit_modular_add_qdt_boundaries_and_weights(kind):
    primitive = _operator(kind, 2)
    for a, b, c, u, v, w in product(range(4), repeat=6):
        operation = Q.modular_add if kind is ModularAdd else Q.modular_subtract
        expected = operation(2, a, b, c, u, v, w)
        model = QuasidifferentialSATModel(
            primitive,
            fixed_differences={"plaintext": (a << 2) | b},
            output_difference=c,
            fixed_masks={"plaintext": (u << 2) | v},
            output_mask=w,
            nonzero_input=False,
        )
        formula = model.cnf_formula()
        witness = _unit_witness(formula)
        assert (witness is not None) == bool(expected), (a, b, c, u, v, w, expected)
        if witness is not None:
            assert formula.is_satisfied(witness)
            assert model.decode(witness)[1] == expected


@pytest.mark.parametrize("kind", [BitwiseAnd, BitwiseOr])
def test_all_one_bit_and_qdt_boundaries_and_weights(kind):
    primitive = _operator(kind, 1)
    for a, b, c, u, v, w in product(range(2), repeat=6):
        expected = Q.lookup(
            (0, 0, 0, 1) if kind is BitwiseAnd else (0, 1, 1, 1),
            (a << 1) | b,
            c,
            (u << 1) | v,
            w,
            output_width=1,
        )
        model = QuasidifferentialSATModel(
            primitive,
            fixed_differences={"plaintext": (a << 1) | b},
            output_difference=c,
            fixed_masks={"plaintext": (u << 1) | v},
            output_mask=w,
            nonzero_input=False,
        )
        witness = _unit_witness(model.cnf_formula())
        assert (witness is not None) == bool(expected)
        if witness is not None:
            assert model.decode(witness)[1] == expected


def test_fractional_lookup_weights_use_exact_product_bounds():
    primitive = BitVectorSBox(4, HEYS_SBOX)
    name = next(iter(primitive.graph.input_arrays))
    common = dict(
        fixed_differences={name: 2}, output_difference=5, fixed_masks={name: 0}, output_mask=0
    )
    for maximum, possible in [(1, False), (1.5, True), (2, True)]:
        model = QuasidifferentialSATModel(primitive, maximum_weight=maximum, **common)
        witness = _unit_witness(model.cnf_formula())
        assert (witness is not None) == possible
        if witness is not None:
            assert model.decode(witness)[1] == Fraction(3, 8)


def test_binary_affine_map_repeats_bit_matrix_and_offset_per_field_unit():
    primitive = Primitive("affine", {"plaintext": UnitArrayType(BinaryExtensionField(2, 7), (2,))})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        BinaryAffineMap(primitive.graph.input("plaintext"), ((0, 1), (1, 0)), 1)
    )
    primitive._builder.set_output(output)
    table = tuple(primitive.evaluate(value) for value in range(16))
    for a in (0, 1, 5, 15):
        b = table[0] ^ table[a]
        for u, v in product(range(16), repeat=2):
            model = QuasidifferentialSATModel(
                primitive,
                fixed_differences={"plaintext": a},
                output_difference=b,
                fixed_masks={"plaintext": u},
                output_mask=v,
                nonzero_input=False,
            )
            witness = _unit_witness(model.cnf_formula())
            expected = Q.lookup(table, a, b, u, v, output_width=4)
            assert (witness is not None) == bool(expected)
            if witness is not None:
                assert model.decode(witness)[1] == expected
