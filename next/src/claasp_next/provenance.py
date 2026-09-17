"""Typed provenance shared by execution, analysis, and representation results."""

from dataclasses import dataclass
from enum import Enum

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
class ResultProvenance:
    """Primitive realization and processing driver recorded separately."""

    primitive: str
    realization: RealizationDescriptor
    driver: DriverIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.primitive, str) or not self.primitive:
            raise ValueError("provenance primitive identity must be non-empty")
        if not isinstance(self.realization, RealizationDescriptor):
            raise TypeError("provenance realization must be a RealizationDescriptor")
        if not isinstance(self.driver, DriverIdentity):
            raise TypeError("provenance driver must be a DriverIdentity")

    @classmethod
    def for_primitive(cls, primitive, driver: DriverIdentity) -> "ResultProvenance":
        """Bind an already selected graph to the driver producing a result."""

        return cls(primitive.family_name, primitive.realization, driver)

    @property
    def realization_identity(self) -> str:
        return f"{self.primitive}:{self.realization.name}"
