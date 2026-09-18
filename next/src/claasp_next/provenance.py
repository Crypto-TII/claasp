"""Typed provenance shared by execution, analysis, and representation results."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from collections.abc import Mapping

from claasp_next.graph.realization import RealizationDescriptor


class DriverKind(str, Enum):
    """The role played by a result-producing driver."""

    EXECUTION_ENGINE = "execution_engine"
    SOLVER = "solver"
    RENDERER = "renderer"
    EXTERNAL_TOOL = "external_tool"


@dataclass(frozen=True, slots=True)
class DriverIdentity:
    """Stable driver name, role, and optional implementation version."""

    name: str
    kind: DriverKind
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("driver name must be a non-empty string")
        if not isinstance(self.kind, DriverKind):
            object.__setattr__(self, "kind", DriverKind(self.kind))
        if self.version is not None and (not isinstance(self.version, str) or not self.version):
            raise ValueError("driver version must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class TransformationRecord:
    """One immutable graph derivation, separate from realization and drivers.

    EXAMPLES::

        >>> TransformationRecord("slice", (("rounds", "1:2"),)).operation
        'slice'
    """

    operation: str
    parameters: tuple[tuple[str, str], ...] = ()
    source_identity: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation, str) or not self.operation:
            raise ValueError("transformation operation must be a non-empty string")
        if not isinstance(self.parameters, tuple) or any(
            not isinstance(item, tuple) or len(item) != 2
            or not all(isinstance(value, str) for value in item)
            for item in self.parameters
        ):
            raise TypeError("transformation parameters must be string pairs")
        if self.source_identity is not None and (
            not isinstance(self.source_identity, str) or not self.source_identity
        ):
            raise ValueError("transformation source identity must be non-empty or None")

    @property
    def parameter_map(self) -> Mapping[str, str]:
        """Return a read-only parameter view."""

        return MappingProxyType(dict(self.parameters))


@dataclass(frozen=True, slots=True)
class ResultProvenance:
    """Primitive realization, transformations, and driver recorded separately."""

    primitive: str
    realization: RealizationDescriptor
    driver: DriverIdentity
    transformations: tuple[TransformationRecord, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.primitive, str) or not self.primitive:
            raise ValueError("provenance primitive identity must be non-empty")
        if not isinstance(self.realization, RealizationDescriptor):
            raise TypeError("provenance realization must be a RealizationDescriptor")
        if not isinstance(self.driver, DriverIdentity):
            raise TypeError("provenance driver must be a DriverIdentity")
        if not isinstance(self.transformations, tuple) or any(
            not isinstance(item, TransformationRecord) for item in self.transformations
        ):
            raise TypeError("provenance transformations must contain TransformationRecord values")

    @classmethod
    def for_primitive(cls, primitive, driver: DriverIdentity) -> "ResultProvenance":
        """Bind an already selected graph to the driver producing a result."""

        return cls(
            primitive.family_name,
            primitive.realization,
            driver,
            tuple(getattr(primitive, "transformation_provenance", ())),
        )

    @property
    def realization_identity(self) -> str:
        return f"{self.primitive}:{self.realization.name}"
