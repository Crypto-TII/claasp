"""Metadata for interchangeable graph realizations of one primitive."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RealizationDescriptor:
    """Capabilities and structure exposed by a primitive realization."""

    name: str
    capabilities: frozenset[str]
    structure: frozenset[str]
    description: str

    def __post_init__(self) -> None:
        if not self.name or not self.description:
            raise ValueError("a realization requires a name and description")

    def supports(self, requirements) -> bool:
        """Return whether all requested capabilities are declared."""

        return set(requirements) <= self.capabilities
