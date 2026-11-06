"""Explicit XOR semantics are public names, with no old-name aliases."""

import importlib

import pytest


@pytest.mark.parametrize("backend", ["sat", "smt", "milp", "cp"])
@pytest.mark.parametrize("semantics", ["Differential", "Linear"])
def test_word_models_use_explicit_xor_names_without_aliases(backend, semantics):
    module = importlib.import_module(f"claasp.representations.constraints.{backend}")
    expected = f"WordXor{semantics}{backend.upper()}Model"
    old = f"Word{semantics}{backend.upper()}Model"
    model = getattr(module, expected)
    assert model.__name__ == expected
    assert expected in module.__all__
    assert not hasattr(module, old)
    assert old not in module.__all__


@pytest.mark.parametrize("backend", ["sat", "milp", "cp"])
def test_composed_models_name_both_xor_semantics_without_old_aliases(backend):
    module = importlib.import_module(f"claasp.representations.constraints.{backend}")
    expected = f"WordDeterministicXorDifferentialLinear{backend.upper()}Model"
    old = f"WordDeterministicDifferentialLinear{backend.upper()}Model"
    assert getattr(module, expected).__name__ == expected
    assert expected in module.__all__
    assert not hasattr(module, old)


def test_circle_public_names_identify_the_analysis_and_report_backend_scope():
    import claasp.analysis as analysis
    from claasp.primitives import Craft

    model = Craft(number_of_rounds=8).circle_linear_trail_model()
    assert type(model).__name__ == "CircleLinearTrailModel"
    assert model.backend == "perfect_subgroup_spn"
    result = model.search()
    assert type(result).__name__ == "CircleLinearTrailSearchResult"
    assert type(result.representative).__name__ == "CircleLinearTrail"
    assert result.backend == model.backend
    assert result.scope == "four-element perfect subgroup"
    assert not hasattr(analysis, "FreeSubgroupSPN")
    assert not hasattr(analysis, "SubgroupSearchResult")
    assert not hasattr(Craft(number_of_rounds=8), "circle_linear_model")
