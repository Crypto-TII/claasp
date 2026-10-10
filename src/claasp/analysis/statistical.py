"""Public orchestration for reproducible statistical-suite experiments."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from claasp.analysis.statistical_datasets import (
    StatisticalDataset,
    avalanche_statistical_dataset,
    cbc_dataset,
    correlation_dataset,
    high_density_dataset,
    low_density_dataset,
    random_statistical_dataset,
)
from claasp.analysis.statistical_results import StatisticalTestRun
from claasp.graph import Primitive


class StatisticalSuiteDriver(Protocol):
    """Driver boundary shared by NIST STS, Dieharder, and test doubles.

    EXAMPLES::

        >>> callable(StatisticalSuiteDriver)
        True
    """

    def run(self, dataset: StatisticalDataset, **options) -> StatisticalTestRun:
        """Execute a statistical suite for one canonical dataset stream.

        EXAMPLES::

            >>> callable(StatisticalSuiteDriver.run)
            True
        """


@dataclass(frozen=True, slots=True)
class StatisticalRoundResult:
    """One round-specific dataset and external-suite result.

    EXAMPLES::

        >>> callable(StatisticalRoundResult)
        True
    """

    round_number: int
    dataset: StatisticalDataset
    run: StatisticalTestRun


@dataclass(frozen=True, slots=True)
class StatisticalCampaignResult:
    """Ordered results for a statistical suite applied over primitive rounds.

    EXAMPLES::

        >>> StatisticalCampaignResult("random", "state", ()).rounds
        ()
    """

    kind: str
    input_name: str
    rounds: tuple[StatisticalRoundResult, ...]


def run_statistical_campaign(
    primitive: Primitive,
    driver: StatisticalSuiteDriver,
    kind: str,
    input_name: str,
    *,
    number_of_samples: int,
    blocks_per_sample: int | None = None,
    ratio: float = 1.0,
    seed: int = 0,
    fixed_inputs: Mapping[str, int] | None = None,
    round_start: int = 1,
    round_end: int | None = None,
    driver_options: Mapping[str, object] | None = None,
) -> StatisticalCampaignResult:
    """Generate and test one dataset family at every requested round boundary.

    Round numbers are one-based and inclusive. This replaces the legacy
    mutable NIST/Dieharder wrappers while retaining their multi-round behavior.

    EXAMPLES::

        >>> callable(run_statistical_campaign)
        True
    """

    total_rounds = len(primitive.rounds)
    selected_end = total_rounds if round_end is None else round_end
    if not isinstance(round_start, int) or isinstance(round_start, bool):
        raise TypeError("round_start must be an integer")
    if not isinstance(selected_end, int) or isinstance(selected_end, bool):
        raise TypeError("round_end must be an integer")
    if not 1 <= round_start <= selected_end <= total_rounds:
        raise ValueError(
            f"round range must satisfy 1 <= round_start <= round_end <= {total_rounds}"
        )
    if not hasattr(driver, "run"):
        raise TypeError("driver must provide run(dataset, **options)")

    results = []
    for round_number in range(round_start, selected_end + 1):
        reduced = (
            primitive
            if round_number == total_rounds
            else primitive.reduced_rounds(round_number).primitive
        )
        dataset = _dataset(
            reduced,
            kind,
            input_name,
            number_of_samples,
            blocks_per_sample,
            ratio,
            seed,
            fixed_inputs,
        )
        run = driver.run(dataset, **dict(driver_options or {}))
        results.append(StatisticalRoundResult(round_number, dataset, run))
    return StatisticalCampaignResult(kind, input_name, tuple(results))


def _dataset(
    primitive,
    kind,
    input_name,
    number_of_samples,
    blocks_per_sample,
    ratio,
    seed,
    fixed_inputs,
):
    if kind == "avalanche":
        return avalanche_statistical_dataset(
            primitive,
            input_name,
            number_of_samples,
            seed=seed,
            fixed_inputs=fixed_inputs,
        )
    if kind in {"correlation", "cbc", "random"}:
        if blocks_per_sample is None:
            raise ValueError(f"blocks_per_sample is required for {kind} datasets")
        factory = {
            "correlation": correlation_dataset,
            "cbc": cbc_dataset,
            "random": random_statistical_dataset,
        }[kind]
        return factory(
            primitive,
            input_name,
            number_of_samples,
            blocks_per_sample,
            seed=seed,
            fixed_inputs=fixed_inputs,
        )
    if kind in {"low_density", "high_density"}:
        if kind == "low_density":
            return low_density_dataset(
                primitive,
                input_name,
                number_of_samples,
                ratio=ratio,
                seed=seed,
                fixed_inputs=fixed_inputs,
            )
        return high_density_dataset(
            primitive,
            input_name,
            number_of_samples,
            ratio=ratio,
            seed=seed,
            fixed_inputs=fixed_inputs,
        )
    supported = "avalanche, correlation, cbc, random, low_density, high_density"
    raise ValueError(f"unsupported statistical dataset kind {kind!r}; choose one of {supported}")
