import pytest

from claasp.analysis.continuous_differential import ContinuousDifferentialAnalysis
from claasp.primitives import ModularAdd, Present


def test_model_is_deterministic_and_has_explicit_heuristic_provenance():
    model = ContinuousDifferentialAnalysis(ModularAdd(2)).model("0?", output_mask=1)
    first = model.minizinc_model()
    assert first == model.minizinc_model()
    assert "0.25*" in first.source()
    assert first.constraint_models[0].model.analysis_kind == "continuous_differential_linear"
    assert "heuristic" in first.constraint_models[0].model.rationale
    assert model.input_variables == {"input_0": "input_0", "input_1": "input_1"}


def test_unsupported_nonlinear_components_cannot_be_silently_skipped():
    model = ContinuousDifferentialAnalysis(Present(number_of_rounds=1)).model(1)
    with pytest.raises(NotImplementedError, match="does not support"):
        model.minizinc_model()
