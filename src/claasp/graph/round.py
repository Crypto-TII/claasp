"""Round containers for typed primitive graphs."""

from dataclasses import dataclass, field

from claasp.graph.component import Component


@dataclass(slots=True)
class Round:
    """Group authored components in one sequential primitive round.

    EXAMPLES::

        >>> primitive_round = Round(2)
        >>> (primitive_round.number, primitive_round.components)
        (2, ())
    """

    number: int
    _components: list[Component] = field(default_factory=list, init=False, repr=False)
    _scopes: list[object] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.number, int) or isinstance(self.number, bool):
            raise TypeError("round number must be an integer")
        if self.number < 0:
            raise ValueError("round number must be non-negative")

    @property
    def components(self) -> tuple[Component, ...]:
        """Return components in deterministic insertion order."""

        return tuple(self._components)

    def _append(self, component: Component) -> None:
        self._components.append(component)

    @property
    def scopes(self) -> tuple[object, ...]:
        """Composite scopes instantiated in this round, including nested scopes."""

        return tuple(self._scopes)

    def _append_scope(self, scope: object) -> None:
        self._scopes.append(scope)
