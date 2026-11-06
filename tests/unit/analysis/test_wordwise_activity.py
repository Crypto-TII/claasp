from dataclasses import replace
from io import StringIO

import pytest

from claasp.analysis import ActiveSBoxResult
from claasp.analysis.wordwise_activity import WordwiseActivityAnalysis
from claasp.primitives import Ublock, UblockSingleLinearLayer
from claasp.representations.constraints.milp._word_activity import _BitWordActivityCompiler


def test_incomplete_objectives_never_become_primitive_lower_bounds():
    result = ActiveSBoxResult("feasible", 7, False)
    assert result.lower_bound is None
    with pytest.raises(ValueError, match="completed optimal"):
        replace(result, complete=True)
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "candidate model objective" in stream.getvalue()
    assert "wordwise branch-number relaxation" in stream.getvalue()


def test_consolidated_layers_require_exact_matching_word_branch_results():
    from claasp.representations.constraints.milp import WordwiseBranchNumberActiveSBoxesMILPModel

    model = WordwiseBranchNumberActiveSBoxesMILPModel(
        UblockSingleLinearLayer(number_of_rounds=1, use_mix_column=False),
        active_input="plaintext",
        zero_difference_inputs=("key",),
    )
    with pytest.raises(ValueError, match="exact branch result"):
        model.milp_model()


def test_malformed_word_sizes_fail_before_attempting_an_external_solver():
    analysis = WordwiseActivityAnalysis(
        UblockSingleLinearLayer(number_of_rounds=1, use_mix_column=False)
    )
    for size in (True, 0, 3):
        with pytest.raises(ValueError, match="word_size"):
            analysis.model(word_size=size)


def test_decomposed_activity_relaxation_admits_concrete_seeded_differentials():
    primitive = Ublock(number_of_rounds=2)
    owner = WordwiseActivityAnalysis(primitive).model()
    compiler = _BitWordActivityCompiler(owner)
    model = compiler.build()
    for plaintext, difference, key in (
        (0, 1, 0),
        (0x123456, 0x100, 0xABCD),
        ((1 << 128) - 1, 1 << 80, 0x9876),
    ):
        first = primitive.evaluate_with_trace(plaintext, key)
        second = primitive.evaluate_with_trace(plaintext ^ difference, key)
        assignment = {}
        for source, names in compiler.names.items():
            array = primitive.graph.unit_array(source).array_type
            a = primitive._encode_boundary(first.values[source], array)
            b = primitive._encode_boundary(second.values[source], array)
            assert isinstance(a, int) and isinstance(b, int)
            delta = a ^ b
            for position, name in enumerate(names):
                assignment[name] = int(
                    bool(
                        (delta >> (compiler.width * (len(names) - 1 - position)))
                        & ((1 << compiler.width) - 1)
                    )
                )
        for constraint in model.constraints:
            if not constraint.name.startswith("activate_"):
                continue
            terms = dict(constraint.expression.terms)
            indicator = next(name for name, value in terms.items() if value < 0)
            source = next(name for name, value in terms.items() if value > 0)
            assignment[indicator] = max(assignment.get(indicator, 0), assignment[source])
        assert model.is_feasible(assignment)
