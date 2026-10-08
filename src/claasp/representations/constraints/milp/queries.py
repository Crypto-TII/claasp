"""High-level portable monomial degree and cube-feasibility queries."""

from dataclasses import dataclass

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.milp.lowering import BooleanMonomialGraphMILPModel
from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    MILPModel,
    ObjectiveSense,
)


@dataclass(frozen=True, slots=True)
class MonomialDegreeBound:
    """One solver witness establishing a reachable monomial degree bound.

    EXAMPLES::

        >>> MonomialDegreeBound(3, 7, (0, 2, 4)).degree
        3
    """

    degree: int
    output_bit: int
    active_input_positions: tuple[int, ...]


class MonomialDegreeMILPModel:
    """Maximize the reachable input-monomial degree for one output bit.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> model = MonomialDegreeMILPModel(
        ...     Simon(number_of_rounds=1), output_bit=0,
        ...     variable_input="plaintext",
        ... )
        >>> len(model.milp_model().objective.terms)
        32
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "MonomialDegreeMILPModel",
        "division_property_degree_bound",
        "degree maximization over the verified Boolean monomial graph formulation",
        "A decoded optimum is a model bound; tightness depends on the underlying monomial rules.",
    )

    def __init__(self, primitive, *, output_bit, variable_input, variable_positions=None):
        self.output_bit = output_bit
        self.variable_input = variable_input
        self._graph = BooleanMonomialGraphMILPModel(
            primitive, output_bit, variable_input, variable_positions
        )
        self.variable_positions = self._graph.variable_positions
        self._model: MILPModel | None = None

    def milp_model(self) -> MILPModel:
        """Return the portable degree-maximization formulation."""

        graph = self._graph.milp_model()
        self._model = MILPModel(
            graph.variables,
            graph.constraints,
            graph.objective,
            graph.objective_sense,
            graph.constraint_models + (ConstraintModelApplication(self.model_provenance),),
        )
        return self._model

    def decode_bound(self, assignment) -> MonomialDegreeBound:
        """Validate a complete assignment and project its selected input monomial."""

        if self._model is None:
            raise ValueError("build the MILP model before decoding")
        projected = {
            variable.name: int(round(assignment[variable.name]))
            for variable in self._model.variables
        }
        if not self._model.is_feasible(projected):
            raise ValueError("invalid monomial degree assignment")
        active = tuple(
            bit for bit in self.variable_positions if projected[f"wire_{self.variable_input}_{bit}"]
        )
        return MonomialDegreeBound(len(active), self.output_bit, active)


class CubeMonomialFeasibilityMILPModel:
    """Decide whether one complete cube monomial can reach an output bit.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> model = CubeMonomialFeasibilityMILPModel(
        ...     Simon(number_of_rounds=1), output_bit=0,
        ...     variable_input="plaintext", cube_positions=(0, 1),
        ... )
        >>> model.milp_model().objective.terms
        ()
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "CubeMonomialFeasibilityMILPModel",
        "cube_monomial_feasibility",
        "fixed cube over the verified Boolean monomial graph formulation",
        "Infeasibility excludes the selected cube monomial from the chosen output bit.",
    )

    def __init__(self, primitive, *, output_bit, variable_input, cube_positions):
        self.output_bit = output_bit
        self.variable_input = variable_input
        self.cube_positions = tuple(cube_positions)
        self._graph = BooleanMonomialGraphMILPModel(
            primitive, output_bit, variable_input, self.cube_positions
        )
        if not self.cube_positions:
            raise ValueError("cube_positions must not be empty")

    def milp_model(self) -> MILPModel:
        """Return a fixed-cube feasibility formulation with no objective."""

        graph = self._graph.milp_model()
        fixed = tuple(
            LinearConstraint(
                LinearExpression.from_terms({f"wire_{self.variable_input}_{bit}": 1}),
                ConstraintSense.EQUAL,
                1,
                f"fix_cube_{bit}",
            )
            for bit in self.cube_positions
        )
        return MILPModel(
            graph.variables,
            graph.constraints + fixed,
            LinearExpression(),
            ObjectiveSense.MINIMIZE,
            graph.constraint_models + (ConstraintModelApplication(self.model_provenance),),
        )
