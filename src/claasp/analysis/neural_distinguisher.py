"""Short neural-analysis workflows over framework-independent data contracts."""

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from random import Random
from typing import TYPE_CHECKING, TextIO

from claasp.analysis.neural import NeuralExperiment, black_box_dataset, xor_differential_dataset
from claasp.analysis.neural_experiments import dataset_digest, deterministic_partition
from claasp.analysis.neural_workflows import (
    NeuralDifferenceSearchResult,
    NeuralRoundTrainingResult,
    _active_inputs,
    find_good_input_difference,
)

if TYPE_CHECKING:
    from claasp.drivers.renderers.presentation import FigureArtifact


@dataclass(frozen=True, slots=True)
class NeuralRoundTestResult:
    """Independent final-model test with a two-sided, Bonferroni-corrected decision.

    The chance band is a discrete null acceptance region, not a confidence
    interval for the observed accuracy. Correction covers the planned rounds.

    EXAMPLES::

        >>> result = NeuralRoundTestResult(1, 50, 100, 19, "digest", 1.0, 1.0, 0.4, 0.6, 0.95, 1)
        >>> result.accuracy, result.signal
        (0.5, 'not detected')
    """

    round_number: int
    successes: int
    samples: int
    seed: int
    dataset_digest: str
    pvalue: float
    adjusted_pvalue: float
    chance_lower: float
    chance_upper: float
    confidence: float
    comparisons: int

    def __post_init__(self) -> None:
        if self.round_number < 1 or self.samples < 1 or not 0 <= self.successes <= self.samples:
            raise ValueError("test round and sample counts must be valid")
        if self.comparisons < 1 or not 0 < self.confidence < 1:
            raise ValueError("test confidence and comparison count must be valid")
        if not 0 <= self.pvalue <= self.adjusted_pvalue <= 1:
            raise ValueError("test p-values must be ordered probabilities")
        if not 0 <= self.chance_lower <= 0.5 <= self.chance_upper <= 1:
            raise ValueError("chance band must contain 0.5")

    @property
    def accuracy(self) -> float:
        """Return the raw independent-test accuracy, without folding below-chance scores."""
        return self.successes / self.samples

    @property
    def detected(self) -> bool:
        """Return whether the two-sided adjusted p-value meets the family-wise level."""
        return self.adjusted_pvalue <= 1 - self.confidence

    @property
    def signal(self) -> str:
        """Return direct, inverted, or not detected for the retained test evidence."""
        if not self.detected:
            return "not detected"
        return "direct" if self.accuracy > 0.5 else "inverted"


@dataclass(frozen=True, slots=True)
class NeuralAnalysisResult:
    """Retained validation histories and experiment settings for a neural analysis.

    Validation histories and independent final-model tests are kept separate.
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
    tests: tuple[NeuralRoundTestResult, ...] = ()

    @property
    def conclusion(self) -> str:
        """Return a qualified conclusion from the independent tests, or note their absence."""
        from claasp.presentation.adapters import _neural_conclusion

        return _neural_conclusion(self)

    def to_terminal(self, *, details: bool = False, file: TextIO | None = None) -> None:
        """Print independent-test evidence; details also include validation epochs."""
        from claasp.presentation._terminal import to_terminal
        from claasp.presentation.adapters import _neural_analysis_section

        to_terminal(_neural_analysis_section(self, details=details), file=file)

    def plot(
        self, *, view: str | None = None, show: bool = True, save_to: str | Path | None = None
    ) -> "FigureArtifact":
        """Plot stored validation accuracy by epoch or round without retraining.

        The default shows independent-test accuracy and a simultaneous chance
        band. The epochs view shows validation histories used during training.
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
    rounds=None,
    test_samples=1000,
    test_seed=None,
    confidence=0.95,
    comparisons=None,
):
    _test_options(test_samples, confidence, comparisons)
    if rounds is not None:
        total = len(primitive.graph.rounds)
        if isinstance(rounds, str):
            if rounds != "all":
                raise ValueError("rounds must be 'all' or increasing round numbers")
            numbers = tuple(range(1, total + 1))
        else:
            try:
                numbers = tuple(rounds)
            except TypeError as error:
                raise ValueError("rounds must be 'all' or increasing round numbers") from error
        if (
            not numbers
            or any(
                not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= total
                for n in numbers
            )
            or tuple(sorted(set(numbers))) != numbers
        ):
            raise ValueError(f"rounds must be unique increasing integers between 1 and {total}")
        results = []
        for number in numbers:
            reduced = (
                primitive if number == total else primitive.edit.reduce_rounds(number).primitive
            )
            if driver is not None and callable(getattr(driver, "reset", None)):
                driver.reset()
            results.append(
                _train_neural(
                    reduced,
                    kind,
                    input_name,
                    input_difference,
                    samples=samples,
                    epochs=epochs,
                    batch_size=batch_size,
                    validation_fraction=validation_fraction,
                    seed=seed,
                    architecture=architecture,
                    driver=driver,
                    input_differences=input_differences,
                    fixed_inputs=fixed_inputs,
                    test_samples=test_samples,
                    test_seed=test_seed,
                    confidence=confidence,
                    comparisons=max(len(numbers), comparisons or 1),
                )
            )
        return replace(
            results[-1],
            rounds=tuple(stage for result in results for stage in result.rounds),
            dataset_digests=tuple(
                digest for result in results for digest in result.dataset_digests
            ),
            tests=tuple(test for result in results for test in result.tests),
        )
    experiment = NeuralExperiment(architecture, epochs, batch_size, validation_fraction, seed)
    selected = input_name or _active_inputs(primitive, None)[0]
    if selected not in primitive.graph.input_arrays:
        raise ValueError(f"unknown primitive input {selected!r}")
    differences = {}
    actual_fixed = dict(fixed_inputs or {})
    if kind == "black_box":
        if selected in actual_fixed:
            raise ValueError("the varied input cannot also be fixed")
        from claasp.analysis.neural import _widths

        # Reproduce the training generator's fixed inputs, then reuse precisely
        # that primitive instance for independently generated test rows.
        random = Random(seed)
        generated = {name: random.getrandbits(width) for name, width in _widths(primitive).items()}
        generated.update(actual_fixed)
        actual_fixed = {name: value for name, value in generated.items() if name != selected}
        dataset = black_box_dataset(
            primitive, selected, samples=samples, seed=seed, fixed_inputs=actual_fixed
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
    trainer = _driver(primitive, architecture, driver)
    if test_samples and not callable(getattr(trainer, "predict", None)):
        raise TypeError(
            "independent testing requires driver.predict(dataset); use test_samples=0 for validation only"
        )
    independent_seed = _test_seed(seed, test_seed)
    trained = trainer.train(dataset, experiment)
    tests: tuple[NeuralRoundTestResult, ...] = ()
    if test_samples:
        if kind == "black_box":
            testing = black_box_dataset(
                primitive,
                selected,
                samples=test_samples,
                seed=independent_seed,
                fixed_inputs=actual_fixed,
            )
        else:
            testing = xor_differential_dataset(
                primitive,
                differences,
                samples=test_samples,
                seed=independent_seed,
                fixed_inputs=actual_fixed,
            )
        tests = (
            _evaluate_test(
                len(primitive.graph.rounds),
                testing,
                trainer.predict(testing),
                confidence=confidence,
                comparisons=comparisons or 1,
            ),
        )
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
        fixed_inputs=tuple(sorted(actual_fixed.items())),
        tests=tests,
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
    rounds=None,
    test_samples=1000,
    test_seed=None,
    confidence=0.95,
    comparisons=None,
):
    _test_options(test_samples, confidence, comparisons)
    from claasp.analysis.datasets import packed_bit_width

    if rounds not in (None, "all"):
        raise ValueError("AutoND rounds must be None or 'all'")
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
    total = len(primitive.graph.rounds)
    start = 1 if rounds == "all" else max(1, search.best.highest_round - 3)
    trainer = _driver(primitive, architecture, driver)
    threshold = 0.5 + 5 / validation_count**0.5
    results = []
    for number in range(start, total + 1):
        reduced = primitive if number == total else primitive.edit.reduce_rounds(number).primitive
        result = _train_neural(
            reduced,
            "xor_differential",
            input_differences=differences,
            samples=samples,
            epochs=epochs,
            batch_size=batch_size,
            validation_fraction=validation_fraction,
            seed=seed,
            architecture=architecture,
            driver=trainer,
            test_samples=test_samples,
            test_seed=test_seed,
            confidence=confidence,
            comparisons=max(total, comparisons or 1),
        )
        results.append(result)
        history = result.rounds[0].result.validation_accuracy
        # Schedule using validation ONLY. Independent test scores never choose
        # an epoch, difference, orientation, or whether to continue training.
        if rounds is None and (
            not history or max(abs(value - 0.5) for value in history) < threshold - 0.5
        ):
            break
    return replace(
        results[-1],
        kind="autond",
        varied_input=None,
        difference_search=search,
        rounds=tuple(stage for result in results for stage in result.rounds),
        tests=tuple(test for result in results for test in result.tests),
        dataset_digests=tuple(digest for result in results for digest in result.dataset_digests),
        threshold=threshold if rounds is None else None,
    )


def _test_options(samples, confidence, comparisons):
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 0:
        raise ValueError("test_samples must be a nonnegative integer")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be between zero and one")
    if comparisons is not None and (
        not isinstance(comparisons, int) or isinstance(comparisons, bool) or comparisons < 1
    ):
        raise ValueError("comparisons must be a positive integer")


def _test_seed(seed, requested):
    value = (
        int.from_bytes(sha256(f"claasp/neural/test/{seed}".encode()).digest()[:8], "big")
        if requested is None
        else requested
    )
    if not isinstance(value, int) or isinstance(value, bool) or value == seed:
        raise ValueError("test_seed must be an integer different from the training seed")
    return value


def _evaluate_test(number, dataset, predictions, *, confidence, comparisons):
    try:
        from scipy.stats import binom, binomtest
    except ImportError as error:
        raise ImportError(
            "Independent neural tests require SciPy; install claasp[ml] or claasp[ml-tensorflow]"
        ) from error

    values = tuple(predictions)
    if len(values) != dataset.sample_count or any(value not in (0, 1) for value in values):
        raise ValueError("driver.predict must return one binary prediction per test row")
    n = dataset.sample_count
    k = sum(prediction == label for prediction, label in zip(values, dataset.labels, strict=True))
    alpha = (1 - confidence) / comparisons
    lower = int(binom.ppf(alpha / 2, n, 0.5))
    if 2 * binom.cdf(lower, n, 0.5) <= alpha:
        lower += 1
    pvalue = float(binomtest(k, n, 0.5, alternative="two-sided").pvalue)
    return NeuralRoundTestResult(
        number,
        k,
        n,
        dataset.seed,
        dataset_digest(dataset),
        pvalue,
        min(1.0, comparisons * pvalue),
        lower / n,
        (n - lower) / n,
        confidence,
        comparisons,
    )


__all__ = ["NeuralAnalysisResult", "NeuralRoundTestResult"]
