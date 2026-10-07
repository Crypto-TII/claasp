"""Exact MILP encoding of component monomial transitions."""

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _verified_model,
)
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)
from claasp.representations.constraints.polynomial.boolean import monomial_transition_table


class MonomialTransitionMILPModel:
    """Select one exact input/output monomial transition of a lookup table.

    EXAMPLES::

        >>> transition = MonomialTransitionMILPModel((0, 1, 2, 3))
        >>> model = transition.milp_model(input_mask=1, output_mask=1)
        >>> witness = transition.assignment(1, 1)
        >>> model.is_feasible(witness)
        True
    """

    model_provenance = _verified_model(
        ConstraintBackend.MILP,
        "MonomialTransitionMILPModel",
        "division_property",
        "exhaustive monomial-transition row selection",
        "https://eprint.iacr.org/2020/1048",
        "An Algebraic Formulation of the Division Property: Revisiting Degree Evaluations, Cube Attacks, and Key-Independent Sums",
        "section 3, Definition 1",
    )

    def __init__(self, table) -> None:
        self.table = monomial_transition_table(tuple(table))
        self.width = len(table).bit_length() - 1
        self.transitions = tuple(
            (input_mask, output_mask)
            for output_mask, input_masks in self.table.items()
            for input_mask in sorted(input_masks)
        )

    def milp_model(
        self, input_mask: int | None = None, output_mask: int | None = None
    ) -> MILPModel:
        """Return an exact one-hot MILP representation with optional boundaries."""

        for name, mask in (("input_mask", input_mask), ("output_mask", output_mask)):
            if mask is not None and (
                not isinstance(mask, int)
                or isinstance(mask, bool)
                or not 0 <= mask < 1 << self.width
            ):
                raise ValueError(f"{name} must fit the lookup-table width")
        selector_names = tuple(f"transition_{index}" for index in range(len(self.transitions)))
        variables = (
            tuple(
                LinearVariable(f"input_{index}", VariableKind.BINARY) for index in range(self.width)
            )
            + tuple(
                LinearVariable(f"output_{index}", VariableKind.BINARY)
                for index in range(self.width)
            )
            + tuple(LinearVariable(name, VariableKind.BINARY) for name in selector_names)
        )
        constraints = [
            LinearConstraint(
                LinearExpression.from_terms({name: 1 for name in selector_names}),
                ConstraintSense.EQUAL,
                1,
                "select_one_transition",
            )
        ]
        for bit in range(self.width):
            input_terms = {f"input_{bit}": 1}
            output_terms = {f"output_{bit}": 1}
            for index, (transition_input, transition_output) in enumerate(self.transitions):
                input_bit = (transition_input >> (self.width - 1 - bit)) & 1
                output_bit = (transition_output >> (self.width - 1 - bit)) & 1
                if input_bit:
                    input_terms[selector_names[index]] = -1
                if output_bit:
                    output_terms[selector_names[index]] = -1
            constraints.extend(
                (
                    LinearConstraint(
                        LinearExpression.from_terms(input_terms),
                        ConstraintSense.EQUAL,
                        0,
                        f"project_input_{bit}",
                    ),
                    LinearConstraint(
                        LinearExpression.from_terms(output_terms),
                        ConstraintSense.EQUAL,
                        0,
                        f"project_output_{bit}",
                    ),
                )
            )
            if input_mask is not None:
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({f"input_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (input_mask >> (self.width - 1 - bit)) & 1,
                        f"fix_input_{bit}",
                    )
                )
            if output_mask is not None:
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({f"output_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (output_mask >> (self.width - 1 - bit)) & 1,
                        f"fix_output_{bit}",
                    )
                )
        return MILPModel(
            variables,
            tuple(constraints),
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )

    def assignment(self, input_mask: int, output_mask: int) -> dict[str, int]:
        """Build and independently validate a witness for one transition."""

        try:
            selected = self.transitions.index((input_mask, output_mask))
        except ValueError as error:
            raise ValueError("the monomial transition is impossible") from error
        assignment = {
            **{
                f"input_{bit}": (input_mask >> (self.width - 1 - bit)) & 1
                for bit in range(self.width)
            },
            **{
                f"output_{bit}": (output_mask >> (self.width - 1 - bit)) & 1
                for bit in range(self.width)
            },
            **{
                f"transition_{index}": int(index == selected)
                for index in range(len(self.transitions))
            },
        }
        if not self.milp_model().is_feasible(assignment):
            raise RuntimeError("internal monomial-transition witness is inconsistent")
        return assignment
