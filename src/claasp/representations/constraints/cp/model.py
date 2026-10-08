"""Solver-independent container for a MiniZinc CP representation."""

from dataclasses import dataclass

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)


@dataclass(frozen=True, slots=True)
class MiniZincModel:
    """Ordered MiniZinc declarations, constraints, solve, and output items.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MiniZincModel.__dataclass_params__.frozen, tuple(field.name for field in fields(MiniZincModel)))
        (True, ('declarations', 'constraints', 'solve', 'includes', 'outputs', 'provenance', 'name_mapping', 'constraint_models'))
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "MiniZincModel",
        "representation_container",
        "ordered MiniZinc item container",
        "This immutable serialization container introduces no constraint construction.",
    )

    declarations: tuple[str, ...]
    constraints: tuple[str, ...]
    solve: str = "solve satisfy;"
    includes: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    name_mapping: tuple[tuple[str, str], ...] = ()
    constraint_models: tuple[ConstraintModelApplication, ...] = ()

    def __post_init__(self) -> None:
        sections = (self.includes, self.declarations, self.constraints, self.outputs)
        if any(not isinstance(section, tuple) for section in sections):
            raise TypeError("MiniZinc model sections must be tuples")
        if any(
            not isinstance(line, str) or not line.strip()
            for section in sections
            for line in section
        ):
            raise ValueError("MiniZinc model lines must be nonempty strings")
        if len({encoded for encoded, _ in self.name_mapping}) != len(self.name_mapping):
            raise ValueError("encoded MiniZinc names must be unique")
        if len({logical for _, logical in self.name_mapping}) != len(self.name_mapping):
            raise ValueError("logical variable names must be unique")
        if not isinstance(self.solve, str) or not self.solve.strip().startswith("solve "):
            raise ValueError("solve must be a MiniZinc solve item")
        if any(not isinstance(item, ConstraintModelApplication) for item in self.constraint_models):
            raise TypeError("constraint_models must contain ConstraintModelApplication values")

    def source(self) -> str:
        """Serialize the model deterministically in MiniZinc item order."""

        lines = (*self.includes, *self.declarations, *self.constraints, self.solve, *self.outputs)
        return "\n".join(lines) + "\n"
