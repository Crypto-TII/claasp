"""Independent inference, exact discrete chance bands, and two-sided decisions."""

from dataclasses import replace
from io import StringIO

import pytest

from claasp.analysis.neural import NeuralDataset, NeuralExperimentResult
from claasp.analysis.neural_distinguisher import _evaluate_test
from claasp.primitives import Speck


def _test(k, n=1000, comparisons=7, confidence=0.95):
    pytest.importorskip("scipy")
    data = NeuralDataset(((0,),) * n, (0,) * n, "black_box", 19, ("x",))
    return _evaluate_test(
        1, data, (0,) * k + (1,) * (n - k), confidence=confidence, comparisons=comparisons
    )


def test_symmetric_evidence_detects_above_and_below_chance():
    above, below, chance = _test(600), _test(400), _test(500)
    assert above.detected and below.detected and not chance.detected
    assert above.signal == "direct" and below.signal == "inverted"
    assert above.pvalue == below.pvalue
    assert above.adjusted_pvalue == min(1, 7 * above.pvalue)
    assert above.chance_lower == pytest.approx(1 - above.chance_upper)


def test_more_samples_narrow_the_band_and_more_comparisons_widen_it():
    assert _test(500, n=1000).chance_lower > _test(50, n=100).chance_lower
    assert _test(500, comparisons=7).chance_lower < _test(500, comparisons=1).chance_lower
    assert not _test(55, n=100).detected
    assert _test(5500, n=10000).detected


@pytest.mark.parametrize("n", [1, 10, 64, 1000])
@pytest.mark.parametrize("comparisons", [1, 7])
@pytest.mark.parametrize("confidence", [0.5, 0.95, 0.99])
def test_band_boundaries_agree_with_exact_two_sided_decisions(n, comparisons, confidence):
    center = _test(n // 2, n=n, comparisons=comparisons, confidence=confidence)
    lower = round(center.chance_lower * n)
    upper = round(center.chance_upper * n)
    for k in {0, n, max(0, lower - 1), lower, upper, min(n, upper + 1)}:
        result = _test(k, n=n, comparisons=comparisons, confidence=confidence)
        assert result.detected == (k < lower or k > upper)


def test_independent_test_is_not_seen_by_training_and_fixed_key_is_preserved(monkeypatch):
    pytest.importorskip("scipy")
    keys = []
    primitive = Speck(number_of_rounds=1)
    evaluate = type(primitive).evaluate

    def capture(self, inputs):
        keys.append(inputs["key"])
        return evaluate(self, inputs)

    monkeypatch.setattr(type(primitive), "evaluate", capture)

    class Driver:
        def train(self, dataset, experiment):
            self.training = dataset
            return NeuralExperimentResult((0.9,), "spy", True)

        def predict(self, dataset):
            self.testing = dataset
            assert dataset.seed != self.training.seed
            return (0,) * dataset.sample_count

    driver = Driver()
    result = primitive.analysis.neural_blackbox(samples=32, test_samples=100, driver=driver)
    assert len(set(keys)) == 1
    assert driver.training.sample_count == 32 and driver.testing.sample_count == 100
    assert result.tests[0].dataset_digest != result.dataset_digests[0]
    assert result.tests[0].seed != result.dataset_seed
    output = StringIO()
    result.to_terminal(file=output)
    assert "independent final-model test" in output.getvalue()
    # Artificial negative evidence exercises the same public report path.
    inverted = replace(result, tests=(_test(100),))
    assert "Below-chance evidence" in inverted.conclusion
    assert "No statistically significant" in replace(result, tests=(_test(500),)).conclusion


def test_missing_prediction_contract_requires_explicit_validation_only_mode():
    class Driver:
        def train(self, dataset, experiment):
            return NeuralExperimentResult((0.5,), "train-only", True)

    primitive = Speck(number_of_rounds=1)
    with pytest.raises(TypeError, match="driver.predict"):
        primitive.analysis.neural_blackbox(samples=8, driver=Driver())
    result = primitive.analysis.neural_blackbox(samples=8, driver=Driver(), test_samples=0)
    assert result.tests == ()
    assert "No independent test" in result.conclusion


@pytest.mark.parametrize(
    "options", [{"test_samples": -1}, {"confidence": 1}, {"comparisons": 0}, {"test_seed": 9}]
)
def test_invalid_statistical_settings_are_rejected_before_training(options):
    with pytest.raises(ValueError):
        Speck(number_of_rounds=1).analysis.neural_blackbox(**options)
