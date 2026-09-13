"""Common protocol for mechanisms processing representation artifacts."""

from typing import Protocol, runtime_checkable

from claasp_next.representations import Artifact

@runtime_checkable
class Driver(Protocol):
    """A solver, interpreter, compiler, or renderer consuming an artifact."""

    def execute(self, artifact: Artifact) -> object:
        """Process ``artifact`` and return a semantic result."""


@runtime_checkable
class SolverDriver(Protocol):
    """A driver which solves a constraint representation."""

    def solve(self, representation: object) -> object:
        """Solve a representation and return its decoded solver result."""
