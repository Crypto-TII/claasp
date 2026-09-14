"""Round containers for typed primitive graphs."""

from dataclasses import dataclass, field

from claasp_next.graph.component import Component


@dataclass(slots=True)
class Round:
    """An ordered group of components."""

    number: int
    _components: list[Component] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.number, int) or isinstance(self.number, bool):
            raise TypeError("round number must be an integer")
        if self.number < 0:
            raise ValueError("round number must be non-negative")

    @property
    def components(self) -> tuple[Component, ...]:
        return tuple(self._components)

    def _append(self, component: Component) -> None:
        self._components.append(component)
