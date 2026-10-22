"""Short neural-analysis workflows over framework-independent data contracts."""

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.neural import NeuralExperiment, black_box_dataset, xor_differential_dataset
from claasp.analysis.neural_experiments import dataset_digest, deterministic_partition
from claasp.analysis.neural_workflows import (
    NeuralDifferenceSearchResult,
    NeuralRoundTrainingResult,
    _active_inputs,
    find_good_input_difference,
    train_staged_neural_distinguisher,
)

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class NeuralAnalysisResult:
    """Retained validation histories and experiment settings for a neural analysis.

    Accuracy is empirical validation evidence, not independent test accuracy.
    ``rounds`` contains one history per trained reduced-round primitive.

    EXAMPLES::

        >>> callable(NeuralAnalysisResult.to_terminal), callable(NeuralAnalysisResult.plot)
        (True, True)
    """

    primitive_family: str
    kind: str
    sample_count: int
    dataset_seed: int
    experiment: NeuralExperiment
    rounds: tuple[NeuralRoundTrainingResult, ...]
    input_differences: tuple[tuple[str, int], ...] = ()
    varied_input: str | None = None
    dataset_digests: tuple[str, ...] = ()
    threshold: float | None = None
    difference_search: NeuralDifferenceSearchResult | None = None
    fixed_inputs: tuple[tuple[str, int], ...] = ()

    def to_terminal(self, *, details: bool = False, file: TextIO | None = None) -> None:
        """Print settings and per-round validation accuracy; details add epochs."""
        from claasp.presentation._terminal import to_terminal
        from claasp.presentation.adapters import _neural_analysis_section

        to_terminal(_neural_analysis_section(self, details=details), file=file)

    def plot(
        self, *, view: str | None = None, show: bool = True, save_to: str | Path | None = None
    ) -> "FigureArtifact":
        """Plot stored validation accuracy by epoch or round without retraining.

        The default is epochs for individual distinguishers and rounds for
        AutoND. The 0.5 line is balanced-label chance, not a significance test.
        """
        from claasp.drivers.renderers.presentation import _plot_neural_analysis

        return _plot_neural_analysis(self, view=view, show=show, save_to=save_to)


def _driver(primitive, architecture, driver):
    if architecture not in {"mlp", "gohr_resnet", "dbitnet"}:
        raise ValueError("architecture must be mlp, gohr_resnet, or dbitnet")
    if driver is not None:
        return driver
    from claasp.drivers.neural import SklearnMLPDriver, TensorFlowDistinguisherDriver

    if architecture == "mlp":
        return SklearnMLPDriver()
    width = primitive.graph.output.array_type.unit_type.encoded_bit_size
    return TensorFlowDistinguisherDriver(word_size=width)


def _train_neural(
    primitive,
    kind,
    input_name=None,
    input_difference=0,
    *,
    samples=3000,
    epochs=15,
    batch_size=64,
    validation_fraction=0.1,
    seed=9,
    architecture="mlp",
    driver=None,
    input_differences=None,
    fixed_inputs=None,
):
    experiment = NeuralExperiment(architecture, epochs, batch_size, validation_fraction, seed)
    selected = input_name or _active_inputs(primitive, None)[0]
    if selected not in primitive.graph.input_arrays:
        raise ValueError(f"unknown primitive input {selected!r}")
    differences = {}
    if kind == "black_box":
        dataset = black_box_dataset(
            primitive, selected, samples=samples, seed=seed, fixed_inputs=fixed_inputs
        )
    else:
        differences = {name: 0 for name in primitive.graph.input_arrays}
        differences[selected] = input_difference
        if input_differences is not None:
            if set(input_differences) - set(differences):
                raise ValueError("input_differences contains an unknown primitive input")
            differences.update(input_differences)
        if not any(differences.values()):
            raise ValueError("a differential distinguisher requires a nonzero input difference")
        dataset = xor_differential_dataset(
            primitive, differences, samples=samples, seed=seed, fixed_inputs=fixed_inputs
        )
    trained = _driver(primitive, architecture, driver).train(dataset, experiment)
    return NeuralAnalysisResult(
        primitive.family_name,
        kind,
        samples,
        seed,
        experiment,
        (NeuralRoundTrainingResult(len(primitive.graph.rounds), trained),),
        tuple(differences.items()),
        selected,
        (dataset_digest(dataset),),
        fixed_inputs=tuple(sorted((fixed_inputs or {}).items())),
    )


def _autond(
    primitive,
    *,
    samples=3000,
    epochs=15,
    batch_size=64,
    validation_fraction=0.1,
    seed=9,
    architecture="mlp",
    driver=None,
    optimizer_population=8,
    optimizer_generations=2,
    optimizer_samples=64,
    active_inputs=None,
    initial_candidates=None,
):
    from claasp.analysis.datasets import packed_bit_width

    names = _active_inputs(primitive, active_inputs)
    if initial_candidates is None:
        width = sum(packed_bit_width(primitive, name) for name in names)
        initial_candidates = tuple(1 << bit for bit in range(width))
    search = find_good_input_difference(
        primitive,
        active_inputs=names,
        population=optimizer_population,
        generations=optimizer_generations,
        samples=optimizer_samples,
        seed=seed,
        initial_candidates=initial_candidates,
    )
    experiment = NeuralExperiment(architecture, epochs, batch_size, validation_fraction, seed)
    # Obtain the actual validation count: the generator consumes randomness
    # independently of the chosen round graph, so label counts are stable.
    differences = dict(search.best.input_differences)
    calibration = xor_differential_dataset(primitive, differences, samples=samples, seed=seed)
    validation_count = len(
        deterministic_partition(
            calibration,
            validation_fraction=validation_fraction,
            testing_fraction=0,
            seed=seed,
        ).validation
    )
    if validation_count == 0:
        raise ValueError("samples must produce a nonempty validation partition")
    training = train_staged_neural_distinguisher(
        primitive,
        _driver(primitive, architecture, driver),
        differences,
        starting_round=max(1, search.best.highest_round - 3),
        samples=samples,
        experiment=experiment,
        significance_samples=validation_count,
    )
    return NeuralAnalysisResult(
        primitive.family_name,
        "autond",
        samples,
        seed,
        experiment,
        training.rounds,
        training.input_differences,
        threshold=training.threshold,
        difference_search=search,
    )


__all__ = ["NeuralAnalysisResult"]
