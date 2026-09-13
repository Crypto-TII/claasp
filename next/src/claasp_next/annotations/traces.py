"""Distinct trace types built on graph annotations."""

from dataclasses import dataclass

from claasp_next.annotations.base import GraphAnnotation
from claasp_next.interpretations import CONCRETE, LEAKAGE


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    """Concrete values attached to inputs, components, and optional output."""

    annotation: GraphAnnotation

    def __post_init__(self) -> None:
        if self.annotation.interpretation != CONCRETE:
            raise ValueError("an execution trace requires the concrete interpretation")

    def value_of(self, source_id: str) -> object:
        """Return a concrete value from the underlying graph annotation."""

        return self.annotation.value_of(source_id)


@dataclass(frozen=True, slots=True)
class LeakageSample:
    """A simulated leakage observation associated with one component."""

    component_id: str
    value: float
    sample_index: int

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("component_id must not be empty")
        if not isinstance(self.sample_index, int) or self.sample_index < 0:
            raise ValueError("sample_index must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class SideChannelTrace:
    """Leakage annotations plus their ordered sampled observations."""

    annotation: GraphAnnotation
    samples: tuple[LeakageSample, ...]

    def __post_init__(self) -> None:
        if self.annotation.interpretation != LEAKAGE:
            raise ValueError("a side-channel trace requires the leakage interpretation")
        if tuple(sample.sample_index for sample in self.samples) != tuple(range(len(self.samples))):
            raise ValueError("side-channel sample indices must be contiguous and ordered")
