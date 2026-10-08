"""Exact local XOR formulations for MILP."""

from itertools import product

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _unaudited_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)


class XorParityMILPModel:
    """Compact exact integer-quotient formulation of an n-input XOR.

    EXAMPLES::

        >>> relation = XorParityMILPModel(3)
        >>> model = relation.milp_model(inputs=(1, 0, 1), output=0)
        >>> model.is_feasible({"input_0": 1, "input_1": 0, "input_2": 1,
        ...                    "output": 0, "parity_quotient": 1})
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "XorParityMILPModel",
        "functional",
        "integer-quotient parity equality",
        "The equality sum(inputs, output) = 2q defines XOR exactly.",
    )

    def __init__(self, operands: int) -> None:
        if not isinstance(operands, int) or isinstance(operands, bool) or operands < 2:
            raise ValueError("operands must be an integer of at least two")
        self.operands = operands
        self.columns = tuple(f"input_{position}" for position in range(operands)) + ("output",)
        self._model: MILPModel | None = None

    def _fixed(self, inputs, output):
        values: dict[str, int] = {}
        if inputs is not None:
            if len(inputs) != self.operands or any(value not in (0, 1) for value in inputs):
                raise ValueError("fixed inputs must be binary and match the operand count")
            values.update(zip(self.columns[:-1], inputs))
        if output is not None:
            if output not in (0, 1):
                raise ValueError("fixed output must be binary")
            values["output"] = output
        return tuple(
            LinearConstraint(
                LinearExpression.from_terms({name: 1}),
                ConstraintSense.EQUAL,
                value,
                f"fixed_{name}",
            )
            for name, value in values.items()
        )

    def milp_model(self, *, inputs=None, output=None):
        """Return the compact exact formulation with optional fixed values."""

        quotient = "parity_quotient"
        variables = tuple(LinearVariable(name, VariableKind.BINARY) for name in self.columns) + (
            LinearVariable(quotient, VariableKind.INTEGER, 0, (self.operands + 1) // 2),
        )
        parity = LinearConstraint(
            LinearExpression.from_terms({**dict.fromkeys(self.columns, 1), quotient: -2}),
            ConstraintSense.EQUAL,
            0,
            "xor_parity",
        )
        self._model = MILPModel(
            variables,
            (parity, *self._fixed(inputs, output)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_transition(self, assignment):
        """Decode and independently re-evaluate a feasible XOR assignment."""

        if self._model is None or not self._model.is_feasible(assignment):
            raise ValueError("invalid XOR witness")
        inputs = tuple(round(assignment[name]) for name in self.columns[:-1])
        output = round(assignment["output"])
        if output != sum(inputs) % 2:
            raise ValueError("XOR output disagrees with parity")
        return inputs, output


class XorImpossiblePointMILPModel(XorParityMILPModel):
    """Recovered legacy no-auxiliary impossible-point XOR formulation.

    EXAMPLES::

        >>> relation = XorImpossiblePointMILPModel(3)
        >>> model = relation.milp_model(inputs=(1, 0, 1), output=0)
        >>> (len(model.variables), len(model.constraints))
        (4, 12)
    """

    model_provenance = _unaudited_model(
        ConstraintBackend.MILP,
        "XorImpossiblePointMILPModel",
        "functional",
        "legacy impossible-point parity inequalities",
        "Every odd-parity point is excluded directly; no mutable arity cache is required.",
    )

    def milp_model(self, *, inputs=None, output=None):
        """Return one excluding inequality per impossible parity point."""

        variables = tuple(LinearVariable(name, VariableKind.BINARY) for name in self.columns)
        constraints = []
        for number, point in enumerate(product((0, 1), repeat=len(self.columns))):
            if sum(point) % 2 == 0:
                continue
            terms = {
                name: 1 if value == 0 else -1 for name, value in zip(self.columns, point)
            }
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms(terms),
                    ConstraintSense.GREATER_EQUAL,
                    1 - sum(point),
                    f"exclude_odd_parity_{number}",
                )
            )
        self._model = MILPModel(
            variables,
            (*constraints, *self._fixed(inputs, output)),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )
        return self._model


def xor_arities_for_binary_matrix(matrix) -> tuple[int, ...]:
    """Return distinct nontrivial column XOR arities without a mutable cache.

    EXAMPLES::

        >>> xor_arities_for_binary_matrix(((1, 0, 1), (1, 1, 0), (0, 1, 1)))
        (2,)
    """

    rows = tuple(tuple(row) for row in matrix)
    if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
        raise ValueError("matrix must be nonempty and rectangular")
    if any(value not in (0, 1) for row in rows for value in row):
        raise ValueError("matrix must be binary")
    return tuple(sorted({sum(row[column] for row in rows) for column in range(len(rows[0]))} - {0, 1}))


__all__ = ["XorImpossiblePointMILPModel", "XorParityMILPModel", "xor_arities_for_binary_matrix"]
