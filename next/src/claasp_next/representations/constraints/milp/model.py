"""Solver-independent mixed-integer linear representations."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from math import isfinite


class VariableKind(str, Enum):
    """Supported linear-model variable domains."""

    BINARY = "binary"
    INTEGER = "integer"
    CONTINUOUS = "continuous"


class ConstraintSense(str, Enum):
    """Comparison used by a linear constraint."""

    LESS_EQUAL = "<="
    EQUAL = "="
    GREATER_EQUAL = ">="


class ObjectiveSense(str, Enum):
    """Direction of optimization."""

    MINIMIZE = "minimize"
    MAXIMIZE = "maximize"


@dataclass(frozen=True, slots=True)
class LinearVariable:
    """A named variable and its domain bounds."""

    name: str
    kind: VariableKind = VariableKind.CONTINUOUS
    lower_bound: float | None = 0
    upper_bound: float | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "a").isalnum() or self.name[0].isdigit():
            raise ValueError(f"invalid variable name {self.name!r}")
        if self.kind is VariableKind.BINARY:
            if self.lower_bound not in (None, 0) or self.upper_bound not in (None, 1):
                raise ValueError("binary variables have bounds 0 and 1")
            object.__setattr__(self, "lower_bound", 0)
            object.__setattr__(self, "upper_bound", 1)
        for bound in (self.lower_bound, self.upper_bound):
            if bound is not None and not isfinite(bound):
                raise ValueError("variable bounds must be finite or None")
        if (
            self.lower_bound is not None
            and self.upper_bound is not None
            and self.lower_bound > self.upper_bound
        ):
            raise ValueError("lower bound cannot exceed upper bound")


@dataclass(frozen=True, slots=True)
class LinearExpression:
    """A canonical affine expression."""

    terms: tuple[tuple[str, float], ...] = ()
    constant: float = 0

    def __post_init__(self) -> None:
        names = [name for name, _ in self.terms]
        if len(set(names)) != len(names):
            raise ValueError("an expression cannot repeat a variable")
        if names != sorted(names):
            raise ValueError("expression terms must be sorted by variable name")
        if any(not isfinite(coefficient) or coefficient == 0 for _, coefficient in self.terms):
            raise ValueError("coefficients must be finite and nonzero")
        if not isfinite(self.constant):
            raise ValueError("constant must be finite")

    @classmethod
    def from_terms(
        cls, terms: Mapping[str, int | float], constant: int | float = 0
    ) -> "LinearExpression":
        """Build a canonical expression from a coefficient mapping."""

        return cls(
            tuple(sorted((name, float(value)) for name, value in terms.items() if value != 0)),
            float(constant),
        )

    def evaluate(self, assignment: Mapping[str, int | float]) -> float:
        """Evaluate this expression under a complete named assignment."""

        return self.constant + sum(coefficient * assignment[name] for name, coefficient in self.terms)


@dataclass(frozen=True, slots=True)
class LinearConstraint:
    """A named affine comparison against a scalar right-hand side."""

    expression: LinearExpression
    sense: ConstraintSense
    rhs: float
    name: str | None = None

    def __post_init__(self) -> None:
        if not isfinite(self.rhs):
            raise ValueError("constraint right-hand side must be finite")


@dataclass(frozen=True, slots=True)
class MILPModel:
    """A portable linear objective, domains, and constraints."""

    variables: tuple[LinearVariable, ...]
    constraints: tuple[LinearConstraint, ...]
    objective: LinearExpression = LinearExpression()
    objective_sense: ObjectiveSense = ObjectiveSense.MINIMIZE

    def __post_init__(self) -> None:
        if not self.variables:
            raise ValueError("a model must declare at least one variable")
        names = tuple(variable.name for variable in self.variables)
        if len(set(names)) != len(names):
            raise ValueError("variable names must be unique")
        known = set(names)
        referenced = {name for constraint in self.constraints for name, _ in constraint.expression.terms}
        referenced.update(name for name, _ in self.objective.terms)
        if unknown := referenced - known:
            raise ValueError(f"expressions refer to unknown variables: {sorted(unknown)!r}")

    def objective_value(self, assignment: Mapping[str, int | float]) -> float:
        """Independently evaluate the objective value."""

        return self.objective.evaluate(assignment)

    def is_feasible(self, assignment: Mapping[str, int | float], tolerance: float = 1e-7) -> bool:
        """Check domains and constraints without trusting a solver status."""

        if set(assignment) != {variable.name for variable in self.variables}:
            return False
        for variable in self.variables:
            value = assignment[variable.name]
            if variable.lower_bound is not None and value < variable.lower_bound - tolerance:
                return False
            if variable.upper_bound is not None and value > variable.upper_bound + tolerance:
                return False
            if variable.kind is not VariableKind.CONTINUOUS and abs(value - round(value)) > tolerance:
                return False
        for constraint in self.constraints:
            value = constraint.expression.evaluate(assignment)
            if constraint.sense is ConstraintSense.EQUAL and abs(value - constraint.rhs) > tolerance:
                return False
            if constraint.sense is ConstraintSense.LESS_EQUAL and value > constraint.rhs + tolerance:
                return False
            if constraint.sense is ConstraintSense.GREATER_EQUAL and value < constraint.rhs - tolerance:
                return False
        return True
