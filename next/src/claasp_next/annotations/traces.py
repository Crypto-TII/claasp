"""Distinct trace types built on graph annotations."""

from dataclasses import dataclass

from claasp_next.annotations.base import GraphAnnotation
from claasp_next.semantics import CONCRETE, LEAKAGE


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    """Expose concrete values attached to graph sources and output.

    EXAMPLES::

        >>> from claasp_next import Bit, Primitive, ValueType
        >>> from claasp_next.annotations import AnnotationEntry, AnnotationRole
        >>> from claasp_next.semantics import CONCRETE
        >>> primitive = Primitive("identity", {"state": ValueType(Bit(), (1,))})
        >>> trace = ExecutionTrace(GraphAnnotation(primitive, CONCRETE, (
        ...     AnnotationEntry("state", AnnotationRole.INPUT, 1),
        ... )))
        >>> trace.value_of("state")
        1
    """

    annotation: GraphAnnotation

    def __post_init__(self) -> None:
        if self.annotation.semantics != CONCRETE:
            raise ValueError("an execution trace requires the concrete semantics")

    def value_of(self, source_id: str) -> object:
        """Return a concrete value from the underlying graph annotation."""

        return self.annotation.value_of(source_id)


@dataclass(frozen=True, slots=True)
class LeakageSample:
    """Record one ordered simulated leakage observation.

    EXAMPLES::

        >>> LeakageSample("xor_0_0", 2.5, 0)
        LeakageSample(component_id='xor_0_0', value=2.5, sample_index=0)
    """

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
    """Pair leakage annotations with contiguous ordered observations.

    EXAMPLES::

        >>> from claasp_next import Bit, Primitive, ValueType
        >>> from claasp_next.semantics import LEAKAGE
        >>> primitive = Primitive("leakage", {"state": ValueType(Bit(), (1,))})
        >>> annotation = GraphAnnotation(primitive, LEAKAGE, ())
        >>> trace = SideChannelTrace(annotation, (LeakageSample("input", 1.0, 0),))
        >>> trace.samples[0].value
        1.0
    """

    annotation: GraphAnnotation
    samples: tuple[LeakageSample, ...]

    def __post_init__(self) -> None:
        if self.annotation.semantics != LEAKAGE:
            raise ValueError("a side-channel trace requires the leakage semantics")
        if tuple(sample.sample_index for sample in self.samples) != tuple(range(len(self.samples))):
            raise ValueError("side-channel sample indices must be contiguous and ordered")
