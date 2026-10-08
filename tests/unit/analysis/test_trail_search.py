"""Capability and dispatch contracts that do not execute an external solver."""

import pytest

from claasp.analysis.facade import TrailSearchBackend
from claasp.analysis.trail_search import require_word_sat_capability
from claasp.primitives import (
    AES,
    CHAM,
    SPARX,
    ChaCha,
    Present,
    Salsa,
    Simeck,
    Simon,
    Speck,
    Threefish,
)
from claasp.representations.constraints.sat import WordDifferentialSATModel, WordLinearSATModel
from claasp.semantics.cryptanalysis import TrailKind


@pytest.mark.parametrize(
    "primitive",
    (
        Simon(number_of_rounds=1),
        Simeck(number_of_rounds=1),
        CHAM(number_of_rounds=1),
        Speck(number_of_rounds=1),
        SPARX(number_of_rounds=1),
        Threefish(number_of_rounds=1),
        ChaCha(number_of_rounds=1),
        Salsa(number_of_rounds=1),
    ),
)
@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_confirmed_word_catalogue_graphs_construct_for_both_kinds(primitive, kind):
    require_word_sat_capability(primitive, kind)
    model = (
        WordDifferentialSATModel(primitive)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordLinearSATModel(primitive, maximum_weight=None)
    )
    assert model.cnf_formula().variable_count


def test_unsupported_error_names_actual_primitive_kind_backend_and_domain():
    with pytest.raises(NotImplementedError) as error:
        AES(number_of_rounds=1).analysis.find_optimal_trail(backend="sat")
    message = str(error.value)
    assert "aes" in message
    assert "xor_differential" in message
    assert "backend 'sat'" in message
    assert "BinaryExtensionField" in message
    assert "present" not in message.lower()
    assert "speck" not in message.lower()


def test_dependency_free_never_falls_back_to_an_unrelated_validator():
    with pytest.raises(NotImplementedError, match="simon.*xor_differential.*dependency_free"):
        Simon(number_of_rounds=3).analysis.find_optimal_trail(backend="dependency_free")


def test_public_enums_and_default_kind_are_exposed():
    assert TrailSearchBackend.SAT.value == "sat"
    assert (
        Present(number_of_rounds=2).analysis.find_optimal_trail().trail.kind
        is TrailKind.XOR_DIFFERENTIAL
    )
