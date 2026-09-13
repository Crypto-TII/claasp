"""Solver-independent container for a MiniZinc CP representation."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MiniZincModel:
    """Ordered MiniZinc declarations, constraints, solve, and output items."""

    declarations: tuple[str, ...]
    constraints: tuple[str, ...]
    solve: str = "solve satisfy;"
    includes: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    name_mapping: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        sections = (self.includes, self.declarations, self.constraints, self.outputs)
        if any(not isinstance(section, tuple) for section in sections):
            raise TypeError("MiniZinc model sections must be tuples")
        if any(not isinstance(line, str) or not line.strip() for section in sections for line in section):
            raise ValueError("MiniZinc model lines must be nonempty strings")
        if len({encoded for encoded, _ in self.name_mapping}) != len(self.name_mapping):
            raise ValueError("encoded MiniZinc names must be unique")
        if len({logical for _, logical in self.name_mapping}) != len(self.name_mapping):
            raise ValueError("logical variable names must be unique")
        if not isinstance(self.solve, str) or not self.solve.strip().startswith("solve "):
            raise ValueError("solve must be a MiniZinc solve item")

    def source(self) -> str:
        """Serialize the model deterministically in MiniZinc item order."""

        lines = (*self.includes, *self.declarations, *self.constraints, self.solve, *self.outputs)
        return "\n".join(lines) + "\n"
