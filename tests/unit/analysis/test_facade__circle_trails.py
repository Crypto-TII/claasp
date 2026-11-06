"""Standard circle search queries delegate to the existing model/measurement paths."""

from fractions import Fraction
from io import StringIO

import pytest

from claasp.primitives import BitVectorSBox, Craft
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace


def test_lowest_weight_circle_linear_query_retains_scope_key_class_and_reporting():
    primitive = Craft(number_of_rounds=8)
    operation = BinaryBibrace(4, ((8, 0, 8, 5),), (5,))
    actual = primitive.analysis.find_lowest_weight_circle_linear_trail(
        bibrace=operation, fixed_inputs={"tweak": 0}
    )
    expected = primitive.analysis.circle_linear_trail_model(
        bibrace=operation, fixed_inputs={"tweak": 0}
    ).search()
    assert actual == expected
    assert (actual.cost, actual.optimal_mask_count, actual.complete) == (8, 24, True)
    assert actual.scope == "four-element perfect subgroup"
    output = StringIO()
    actual.to_terminal(file=output)
    assert "Relative |correlation|" in output.getvalue()
    with pytest.raises(ValueError, match="maximum_factor_states"):
        primitive.analysis.find_lowest_weight_circle_linear_trail(
            bibrace=operation, fixed_inputs={"tweak": 0}, maximum_factor_states=1
        )


def test_lowest_weight_circle_differential_query_reproduces_published_example():
    primitive = BitVectorSBox(4, (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5))
    operation = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
    options = {"input_name": "input", "bibrace": operation}
    actual = primitive.analysis.find_lowest_weight_circle_differential_trail(
        input_difference=7, **options
    )
    expected = primitive.analysis.circle_differential(**options).best_trail(7)
    assert actual == expected
    assert actual.differences == (7, 6) and actual.probability == Fraction(1)
    assert actual.searched and actual.evidence.complete
    assert (
        primitive.analysis.find_lowest_weight_circle_differential_trail(
            input_difference=7, output_difference=0, **options
        )
        is None
    )
    with pytest.raises(ValueError, match="maximum_inputs"):
        primitive.analysis.find_lowest_weight_circle_differential_trail(
            input_difference=7, maximum_inputs=1, **options
        )


def test_lowest_weight_circle_differential_query_passes_boundaries_and_fixed_inputs():
    from claasp.primitives.single_component_primitives import ModularAdd

    primitive = ModularAdd(word_bit_size=4)
    first, second = primitive.graph.input_arrays
    basis_options = {"input_name": first}
    query_options = {"fixed_inputs": {second: 3}, "boundaries": (), "boundary_bases": ()}
    actual = primitive.analysis.find_lowest_weight_circle_differential_trail(
        input_difference=1, **basis_options, **query_options
    )
    expected = primitive.analysis.circle_differential(**basis_options).best_trail(
        1, **query_options
    )
    assert actual == expected
    assert actual.evidence.fixed_inputs == ((second, 3),)
