import os
from functools import lru_cache

import pytest

from claasp.analysis.component_properties import (
    ComponentProperty,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
)
from claasp.analysis.wordwise_activity import WordwiseActivityAnalysis
from claasp.components import LinearMap
from claasp.drivers.analysis import MiniZincBranchNumberDriver
from claasp.primitives import ToyAES, Ublock, UblockSingleLinearLayer

pytestmark = pytest.mark.external


@lru_cache(maxsize=1)
def _branch_driver():
    return MiniZincBranchNumberDriver(
        solver=os.environ.get("CLAASP_PARITY_CP_SOLVER", "gecode"), timeout_seconds=60
    )


def test_binary_word_branch_number_restores_the_legacy_ublock_eight_fixture():
    primitive = UblockSingleLinearLayer(number_of_rounds=1, use_mix_column=False)
    component = next(c for c in primitive.graph.components if isinstance(c, LinearMap))
    result = _branch_driver().analyze(
        component,
        PropertyRequest(
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            PropertyDomain.WORD_LINEAR,
            (("word_size", 4),),
        ),
    )
    assert result.claim is PropertyClaim.EXACT and result.complete
    assert result.value == 8


@pytest.mark.parametrize("rounds,expected", [(1, 1), (2, 6)])
def test_decomposed_ublock_preserves_legacy_relaxation_bounds(rounds, expected):
    result = Ublock(number_of_rounds=rounds).analysis.find_lowest_number_of_active_sboxes()
    assert result.complete and result.lower_bound == expected


@pytest.mark.parametrize("rounds,expected", [(1, 1), (2, 8), (3, 9)])
def test_consolidated_ublock_preserves_legacy_relaxation_bounds_and_branch_cache(rounds, expected):
    analysis = WordwiseActivityAnalysis(
        UblockSingleLinearLayer(number_of_rounds=rounds, use_mix_column=False)
    )
    result = analysis.find_lowest_number_of_active_sboxes(branch_driver=_branch_driver())
    assert result.complete and result.lower_bound == expected
    assert len(analysis._branches) == 1
    # The published three-round exact count is 13; nine remains a model lower bound.
    if rounds == 3:
        assert result.lower_bound < 13


def test_existing_field_wordwise_aes_still_has_the_same_public_workflow():
    result = ToyAES(number_of_rounds=2).analysis.find_lowest_number_of_active_sboxes()
    assert result.complete and result.lower_bound == 5
