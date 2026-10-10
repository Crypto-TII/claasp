"""Executable neural-cryptanalysis workflows retained from legacy CLAASP."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from math import sqrt
from random import Random

from claasp.analysis.datasets import packed_bit_width
from claasp.analysis.neural import (
    NeuralExperiment,
    NeuralExperimentResult,
    NeuralTrainingDriver,
    xor_differential_dataset,
)
from claasp.graph import Primitive


@dataclass(frozen=True, slots=True)
class NeuralDifferenceCandidate:
    """One candidate input difference and its deterministic bias score.

    EXAMPLES::

        >>> NeuralDifferenceCandidate(1, (("state", 1),), 0.25, 2).highest_round
        2
    """

    packed_difference: int
    input_differences: tuple[tuple[str, int], ...]
    score: float
    highest_round: int


@dataclass(frozen=True, slots=True)
class NeuralDifferenceSearchResult:
    """Ranked output of the AutoND-style evolutionary difference search.

    EXAMPLES::

        >>> candidate = NeuralDifferenceCandidate(1, (("state", 1),), 0.25, 1)
        >>> NeuralDifferenceSearchResult((candidate,), ("state",), 8, 1, 0).best == candidate
        True
    """

    candidates: tuple[NeuralDifferenceCandidate, ...]
    active_inputs: tuple[str, ...]
    samples: int
    generations: int
    seed: int

    @property
    def best(self) -> NeuralDifferenceCandidate:
        """Return the highest-ranked candidate.

        EXAMPLES::

            >>> candidate = NeuralDifferenceCandidate(1, (("state", 1),), 0.5, 1)
            >>> NeuralDifferenceSearchResult((candidate,), ("state",), 4, 0, 0).best.score
            0.5
        """

        if not self.candidates:
            raise RuntimeError("difference search produced no nonzero candidates")
        return self.candidates[-1]


@dataclass(frozen=True, slots=True)
class NeuralRoundTrainingResult:
    """Training evidence for one reduced-round primitive.

    EXAMPLES::

        >>> callable(NeuralRoundTrainingResult)
        True
    """

    round_number: int
    result: NeuralExperimentResult


@dataclass(frozen=True, slots=True)
class NeuralStagedTrainingResult:
    """Ordered staged training results and the statistical stopping threshold.

    EXAMPLES::

        >>> NeuralStagedTrainingResult((("state", 1),), (), 0.6).threshold
        0.6
    """

    input_differences: tuple[tuple[str, int], ...]
    rounds: tuple[NeuralRoundTrainingResult, ...]
    threshold: float


@dataclass(frozen=True, slots=True)
class AutoNDResult:
    """Difference optimization followed by staged neural training.

    EXAMPLES::

        >>> callable(AutoNDResult)
        True
    """

    difference_search: NeuralDifferenceSearchResult
    training: NeuralStagedTrainingResult


def find_good_input_difference(
    primitive: Primitive,
    *,
    active_inputs: Iterable[str] | None = None,
    population: int = 32,
    generations: int = 15,
    samples: int = 1000,
    seed: int = 0,
    threshold: float = 0.05,
    initial_candidates: Iterable[int] | None = None,
) -> NeuralDifferenceSearchResult:
    """Rank XOR differences with the deterministic bias metric used by AutoND.

    EXAMPLES::

        >>> callable(find_good_input_difference)
        True
    """

    _positive("population", population)
    if not isinstance(generations, int) or isinstance(generations, bool) or generations < 0:
        raise ValueError("generations must be a non-negative integer")
    _positive("samples", samples)
    if not 0.0 <= threshold <= 0.5:
        raise ValueError("threshold must be between zero and 0.5")
    names = _active_inputs(primitive, active_inputs)
    widths = {name: packed_bit_width(primitive, name) for name in primitive.graph.input_ports}
    difference_bits = sum(widths[name] for name in names)
    random = Random(seed)
    initial = tuple(initial_candidates or ())
    if initial:
        if any(not isinstance(value, int) or value <= 0 for value in initial):
            raise ValueError("initial candidates must be positive integers")
        if any(value >= 1 << difference_bits for value in initial):
            raise ValueError("an initial candidate does not fit the active input widths")
        generation = set(initial)
    else:
        generation = {
            random.randrange(1, 1 << difference_bits)
            for _ in range(max(population * 2, population))
        }
    explored: set[int] = set()
    scores: dict[int, tuple[float, int]] = {}
    for _ in range(generations + 1):
        pending = tuple(sorted(generation - explored))
        for candidate in pending:
            scores[candidate] = _difference_score(
                primitive,
                _unpack_difference(candidate, names, widths),
                samples=samples,
                seed=seed,
                threshold=threshold,
            )
        explored.update(pending)
        survivors = tuple(
            sorted(explored, key=lambda value: (scores[value][0], value))[-population:]
        )
        children = {left ^ right for left in survivors for right in survivors if left != right}
        for value in survivors:
            if random.random() < 0.1:
                children.add(value ^ (1 << random.randrange(difference_bits)))
        generation = {value for value in children if value and value not in explored}

    ranked = tuple(
        NeuralDifferenceCandidate(
            value,
            tuple(_unpack_difference(value, names, widths).items()),
            scores[value][0],
            scores[value][1],
        )
        for value in sorted(scores, key=lambda item: (scores[item][0], item))[-population:]
    )
    return NeuralDifferenceSearchResult(ranked, names, samples, generations, seed)


def train_staged_neural_distinguisher(
    primitive: Primitive,
    driver: NeuralTrainingDriver,
    input_differences: Mapping[str, int],
    *,
    starting_round: int,
    samples: int,
    experiment: NeuralExperiment,
    maximum_round: int | None = None,
    significance_samples: int | None = None,
) -> NeuralStagedTrainingResult:
    """Train successive reduced-round distinguishers until accuracy loses significance.

    EXAMPLES::

        >>> callable(train_staged_neural_distinguisher)
        True
    """

    total_rounds = len(primitive.graph.rounds)
    stop = total_rounds if maximum_round is None else maximum_round
    if not 1 <= starting_round <= stop <= total_rounds:
        raise ValueError(
            f"round range must satisfy 1 <= starting_round <= maximum_round <= {total_rounds}"
        )
    _positive("samples", samples)
    evidence_samples = samples if significance_samples is None else significance_samples
    _positive("significance_samples", evidence_samples)
    threshold = 0.5 + 10 * sqrt(evidence_samples / 4) / evidence_samples
    normalized = _validate_differences(primitive, input_differences)
    results = []
    for round_number in range(starting_round, stop + 1):
        reduced = (
            primitive
            if round_number == total_rounds
            else primitive.edit.reduce_rounds(round_number).primitive
        )
        dataset = xor_differential_dataset(
            reduced, normalized, samples=samples, seed=experiment.seed
        )
        trained = driver.train(dataset, experiment)
        results.append(NeuralRoundTrainingResult(round_number, trained))
        if not trained.validation_accuracy or max(trained.validation_accuracy) < threshold:
            break
    return NeuralStagedTrainingResult(tuple(normalized.items()), tuple(results), threshold)


def run_autond(
    primitive: Primitive,
    driver: NeuralTrainingDriver,
    experiment: NeuralExperiment,
    *,
    active_inputs: Iterable[str] | None = None,
    optimizer_population: int = 32,
    optimizer_generations: int = 15,
    optimizer_samples: int = 1000,
    training_samples: int = 10_000,
    seed: int = 0,
) -> AutoNDResult:
    """Run difference search and staged training as one typed AutoND workflow.

    EXAMPLES::

        >>> callable(run_autond)
        True
    """

    search = find_good_input_difference(
        primitive,
        active_inputs=active_inputs,
        population=optimizer_population,
        generations=optimizer_generations,
        samples=optimizer_samples,
        seed=seed,
    )
    start = max(1, search.best.highest_round - 3)
    training = train_staged_neural_distinguisher(
        primitive,
        driver,
        dict(search.best.input_differences),
        starting_round=start,
        samples=training_samples,
        experiment=experiment,
    )
    return AutoNDResult(search, training)


def _difference_score(primitive, differences, *, samples, seed, threshold):
    random = Random(seed)
    widths = {name: packed_bit_width(primitive, name) for name in primitive.graph.input_ports}
    base_inputs = tuple(
        {name: random.getrandbits(width) for name, width in widths.items()} for _ in range(samples)
    )
    score = 0.0
    highest_round = 1
    for round_number in range(1, len(primitive.graph.rounds) + 1):
        reduced = (
            primitive
            if round_number == len(primitive.graph.rounds)
            else primitive.edit.reduce_rounds(round_number).primitive
        )
        output_width = packed_bit_width(reduced)
        counts = [0] * output_width
        for inputs in base_inputs:
            related = {name: value ^ differences[name] for name, value in inputs.items()}
            left = reduced.evaluate(inputs)
            right = reduced.evaluate(related)
            if not isinstance(left, int) or not isinstance(right, int):
                raise TypeError("neural difference search requires packed integer outputs")
            difference = left ^ right
            for bit in range(output_width):
                counts[bit] += (difference >> (output_width - bit - 1)) & 1
        biases = tuple(abs(0.5 - count / samples) for count in counts)
        round_score = sum(biases) / len(biases)
        score += round_number * round_score
        highest_round = round_number
        if max(biases) < threshold:
            break
    return score, highest_round


def _active_inputs(primitive, requested):
    if requested is None:
        plaintexts = tuple(name for name in primitive.graph.input_ports if "plaintext" in name)
        if len(plaintexts) == 1:
            return plaintexts
        if len(primitive.graph.input_ports) == 1:
            return tuple(primitive.graph.input_ports)
        raise ValueError("active_inputs is ambiguous; specify one or more primitive input names")
    names = tuple(requested)
    if not names:
        raise ValueError("active_inputs must not be empty")
    unknown = set(names) - set(primitive.graph.input_ports)
    if unknown:
        raise ValueError(f"unknown active inputs: {sorted(unknown)}")
    if len(names) != len(set(names)):
        raise ValueError("active_inputs must not contain duplicates")
    return names


def _unpack_difference(value, active_inputs, widths):
    result = {name: 0 for name in widths}
    for name in active_inputs:
        mask = (1 << widths[name]) - 1
        result[name] = value & mask
        value >>= widths[name]
    return result


def _validate_differences(primitive, differences):
    widths = {name: packed_bit_width(primitive, name) for name in primitive.graph.input_ports}
    if set(differences) != set(widths):
        raise ValueError("input_differences must define every primitive input exactly once")
    normalized = dict(differences)
    for name, value in normalized.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"difference for {name!r} must be an integer")
        if not 0 <= value < 1 << widths[name]:
            raise ValueError(f"difference for {name!r} does not fit its input width")
    return normalized


def _positive(name, value):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
