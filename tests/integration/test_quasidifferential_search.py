"""Search and complete fixed-key sums checked against tiny exhaustive functions."""

from fractions import Fraction

import pytest

from claasp import InputVisibility, Primitive, PrimitiveInput, UnitArrayType
from claasp.analysis.quasidifferential import QuasidifferentialAnalysis
from claasp.components import BitwiseAnd, Xor
from claasp.graph import as_selection
from claasp.primitives import BitVectorSBox, Speck
from claasp.primitives.toy_primitives.heys import HEYS_SBOX
from claasp.unit_types import Word

pytestmark = pytest.mark.external


def _keyed_and(*, repeated=False, duplicate_output=False, key_schedule=False):
    bit = UnitArrayType(Word(1), (1,))
    primitive = Primitive(
        "keyed_and",
        {
            "plaintext": PrimitiveInput(bit, role="plaintext"),
            "key": PrimitiveInput(bit, role="key", visibility=InputVisibility.SECRET),
        },
    )
    primitive._builder.add_round()
    plaintext, key = (as_selection(primitive.graph.input(name)) for name in ("plaintext", "key"))
    if key_schedule:
        key = as_selection(primitive._builder.add_component(BitwiseAnd((key, key))))
    output = primitive._builder.add_component(
        BitwiseAnd((plaintext, plaintext if repeated else key))
    )
    if duplicate_output:
        other = primitive._builder.add_component(BitwiseAnd((plaintext, key)))
        output = primitive._builder.add_component(Xor((output, other)))
    primitive._builder.set_output(output)
    return primitive


@pytest.mark.parametrize("key", [0, 1])
@pytest.mark.parametrize("key_schedule", [False, True])
def test_signed_sum_recovers_fixed_key_not_key_averaged_probability(key, key_schedule):
    primitive = _keyed_and(key_schedule=key_schedule)
    result = QuasidifferentialAnalysis(primitive).estimate_fixed_key_probability(1, 1, key)
    expected = Fraction(
        sum(primitive.evaluate(x, key) ^ primitive.evaluate(x ^ 1, key) == 1 for x in range(2)), 2
    )
    assert result.complete
    assert result.probability == expected == key


def test_fork_masks_are_distinct_for_repeated_reads_within_one_component():
    primitive = _keyed_and(repeated=True)
    result = QuasidifferentialAnalysis(primitive).estimate_fixed_key_probability(1, 1, 0)
    assert result.complete and result.probability == 1
    assert result.trail_count == 2


def test_signed_cancellation_for_duplicate_nonlinear_branches():
    primitive = _keyed_and(duplicate_output=True)
    result = QuasidifferentialAnalysis(primitive).estimate_fixed_key_probability(1, 1, 1)
    assert result.complete and result.probability == 0
    assert result.trail_count > 0


def test_resource_and_weight_limited_sums_do_not_claim_exact_probability():
    analysis = QuasidifferentialAnalysis(_keyed_and())
    partial = analysis.estimate_fixed_key_probability(1, 1, 1, maximum_trails=1)
    assert not partial.complete
    with pytest.raises(RuntimeError, match="maximum_trails"):
        _ = partial.probability
    limited = analysis.estimate_fixed_key_probability(1, 1, 1, maximum_weight=1)
    assert not limited.complete
    with pytest.raises(RuntimeError, match="weight-limited"):
        _ = limited.probability


def test_fractional_lookup_optimum_is_exact():
    primitive = BitVectorSBox(4, HEYS_SBOX)
    name = next(iter(primitive.graph.input_arrays))
    result = QuasidifferentialAnalysis(primitive).find_lowest_weight_trail(
        fixed_differences={name: 2}, output_difference=5
    )
    assert result.coefficient == Fraction(3, 8)
    assert result.is_optimal


def test_two_round_speck_qdt_optimum_has_a_checked_signed_witness():
    result = QuasidifferentialAnalysis(Speck(number_of_rounds=2)).find_lowest_weight_trail()
    assert result.is_optimal and result.weight == 1
    assert abs(result.coefficient) == Fraction(1, 2)


def test_key_average_is_distinct_from_each_fixed_key_probability():
    analysis = _keyed_and().analysis.quasidifferential()
    averaged = analysis.estimate_fixed_key_probability(1, 1)
    assert averaged.complete and averaged.key_averaged
    assert averaged.probability == Fraction(1, 2)
    assert {analysis.estimate_fixed_key_probability(1, 1, key).probability for key in (0, 1)} == {
        0,
        1,
    }


def test_partial_bit_patterns_can_address_structural_boundaries():
    primitive = _keyed_and()
    joined = primitive._builder.join(
        primitive.graph.input("plaintext"), primitive.graph.input("key")
    )
    model = primitive.analysis.quasidifferential().model(
        fixed_differences={joined.source_id: "1?"}, output_difference=1
    )
    assert model.cnf_formula().variable_count > 0
    result = primitive.analysis.find_lowest_weight_xor_quasidifferential_trail(
        fixed_differences={joined.source_id: "10"}, output_difference=1
    )
    assert abs(result.coefficient) == Fraction(1, 2)
