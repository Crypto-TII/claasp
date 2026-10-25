"""Exercise the neural guide scripts with real training and retained reporting."""

import runpy
from io import StringIO
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "docs" / "examples"


def _example(name):
    pytest.importorskip("sklearn")
    return runpy.run_path(str(ROOT / f"{name}.py"))["run_example"]()


@pytest.mark.parametrize("kind", ["blackbox", "differential", "autond"])
def test_basic_neural_scripts_train_and_report_without_retraining(kind, tmp_path, monkeypatch):
    pytest.importorskip("matplotlib").use("Agg")
    import matplotlib.pyplot as plt

    from claasp.drivers.neural import SklearnMLPDriver

    result = _example(f"basic_neural_{kind}")
    assert result.sample_count == (30000 if kind == "blackbox" else 3000)
    assert all(len(stage.result.validation_accuracy) == 15 for stage in result.rounds)
    assert all(
        0 <= accuracy <= 1
        for stage in result.rounds
        for accuracy in stage.result.validation_accuracy
    )
    assert [stage.round_number for stage in result.rounds] == list(range(1, 8))
    assert result.rounds[0].result.validation_accuracy[-1] > 0.8
    assert abs(result.rounds[-1].result.validation_accuracy[-1] - 0.5) < 0.1
    assert [test.round_number for test in result.tests] == list(range(1, 8))
    assert all(test.samples == 1000 and test.comparisons == 7 for test in result.tests)
    assert all(test.seed != result.dataset_seed for test in result.tests)
    assert result.tests[0].detected and result.tests[0].signal == "direct"
    if kind == "autond":
        assert result.difference_search.best.packed_difference != 0
        assert result.threshold is None

    def forbidden(*args, **kwargs):
        raise AssertionError("reporting must reuse the trained result")

    monkeypatch.setattr(SklearnMLPDriver, "train", forbidden)
    monkeypatch.setattr(SklearnMLPDriver, "predict", forbidden)
    output = StringIO()
    result.to_terminal(details=True, file=output)
    assert "independent" in output.getvalue().lower()
    assert "Adjusted p" in output.getvalue()
    assert result.conclusion.startswith("Conclusion:")
    assert all(
        test.detected == (test.adjusted_pvalue <= 1 - test.confidence) for test in result.tests
    )
    assert (
        "Round 1 — epochs" in output.getvalue()
        if kind == "autond"
        else "epochs" in output.getvalue()
    )
    for view in ("epochs", "rounds"):
        target = tmp_path / f"{view}.png"
        result.plot(view=view, show=False, save_to=target)
        assert target.read_bytes().startswith(b"\x89PNG")
        if view == "rounds":
            axis = plt.gcf().axes[0]
            assert axis.get_ylabel() == "Independent test accuracy"
            assert len(axis.collections) == 1
            assert "simultaneous chance band" in axis.get_legend_handles_labels()[1][0]
    plt.close("all")


def test_advanced_blackbox_has_reserved_testing_and_digest():
    result, test_accuracy, digest = _example("advanced_neural_blackbox")
    assert len(result.validation_accuracy) == 15
    assert 0 <= test_accuracy <= 1
    assert len(digest) == 64


def test_advanced_differential_trains_component_projection():
    result, projected = _example("advanced_neural_differential")
    assert result.fixed_inputs == (("key", 0),)
    assert result.rounds[0].result.validation_accuracy[-1] > 0.8
    assert len(projected.validation_accuracy) == 5


def test_advanced_autond_has_search_and_stage_metadata():
    result = _example("advanced_neural_autond")
    assert result.difference_search.samples == 64
    assert result.difference_search.generations == 2
    output = StringIO()
    result.difference_search.to_terminal(file=output)
    assert "bias" in output.getvalue().lower()


@pytest.mark.external
@pytest.mark.parametrize("architecture", ["gohr_resnet", "dbitnet"])
def test_guide_tensorflow_architectures_train(architecture):
    pytest.importorskip("tensorflow")
    from claasp.primitives import Speck

    result = Speck(number_of_rounds=2).analysis.neural_differential(
        "plaintext",
        0x400000,
        architecture=architecture,
        samples=64,
        epochs=1,
        batch_size=16,
    )
    assert len(result.tests) == 1 and result.tests[0].samples == 1000
    assert len(result.rounds[0].result.validation_accuracy) == 1
    assert 0 <= result.rounds[0].result.validation_accuracy[0] <= 1
