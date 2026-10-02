"""Independent concrete and symbolic checks for reusable logical components."""

from itertools import product

from claasp import Primitive, ScalarEvaluator, TransposedBatchEvaluator, ValueType, Word
from claasp.components import BitwiseAnd, BitwiseNot, BitwiseOr, Xor
from claasp.representations.constraints.polynomial import BooleanMonomial
from claasp.representations.execution import BooleanDegreeEvaluator, BooleanSymbolicEvaluator


def _logical_primitive(width: int = 4) -> Primitive:
    value_type = ValueType(Word(width), (1,))
    primitive = Primitive("logical", {"left": value_type, "right": value_type})
    primitive.add_round()
    either = primitive.add_component(BitwiseOr((primitive.input("left"), primitive.input("right"))))
    both = primitive.add_component(BitwiseAnd((primitive.input("left"), primitive.input("right"))))
    exclusive = primitive.add_component(Xor((either, both)))
    output = primitive.add_component(BitwiseNot(exclusive))
    primitive.set_output(output)
    return primitive


def test_logical_components_match_complete_small_truth_table():
    primitive = _logical_primitive(2)
    for left, right in product(range(4), repeat=2):
        expected = (~((left | right) ^ (left & right))) & 3
        assert ScalarEvaluator().evaluate(
            primitive, {"left": (left,), "right": (right,)}
        ).output == (expected,)


def test_logical_components_have_scalar_batch_parity():
    primitive = _logical_primitive()
    left = tuple((value,) for value in (0, 1, 5, 15))
    right = tuple((value,) for value in (15, 3, 10, 0))
    batch = TransposedBatchEvaluator().evaluate(primitive, {"left": left, "right": right})
    scalar = tuple(
        ScalarEvaluator().evaluate(primitive, {"left": a, "right": b}).output
        for a, b in zip(left, right)
    )
    assert batch.outputs == scalar


def test_or_and_not_exact_anfs_and_sound_degree_bounds():
    primitive = _logical_primitive(1)
    symbolic = BooleanSymbolicEvaluator().evaluate(primitive)
    # NOT(XOR(OR(a,b), AND(a,b))) simplifies to NOT(a XOR b).
    assert symbolic.output_anfs[0].monomials == (
        BooleanMonomial(),
        BooleanMonomial(("l0",)),
        BooleanMonomial(("r0",)),
    )
    degree = BooleanDegreeEvaluator().evaluate(primitive, "left")
    assert degree.output_bounds == (1,)
    assert degree.sound and not degree.complete
