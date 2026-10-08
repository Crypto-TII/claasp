"""High-level portable monomial, degree, and exact cube-superpoly queries."""

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


@dataclass(frozen=True, slots=True)
class CubeSuperpolyResult:
    """Exact Boolean ANF of one cube coefficient over selected variables.

    ``anf_terms`` contains tuples of positions in ``symbolic_positions``.  The
    empty tuple denotes the constant coefficient.

    EXAMPLES::

        >>> CubeSuperpolyResult((0, 1), (0, 1), ((1,),)).anf_terms
        ((1,),)
    """

    symbolic_positions: tuple[int, ...]
    truth_table: tuple[int, ...]
    anf_terms: tuple[tuple[int, ...], ...]

    def coefficient(self, positions=()) -> int:
        """Return the coefficient of one symbolic monomial."""

        requested = tuple(sorted(positions))
        if len(set(requested)) != len(requested) or not set(requested) <= set(
            self.symbolic_positions
        ):
            raise ValueError("coefficient positions must be distinct symbolic positions")
        return int(requested in self.anf_terms)


class CubeSuperpolyQuery:
    """Compute an exact cube coefficient and its symbolic superpoly.

    This bounded, dependency-free oracle evaluates every point of the selected
    cube and symbolic subspace, then applies the Boolean Möbius transform.  It
    therefore accounts for parity cancellation rather than merely asking if a
    division-property path exists.  The explicit dimension limit prevents an
    accidental exponential query.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> query = CubeSuperpolyQuery(
        ...     Simon(number_of_rounds=1), output_bit=0,
        ...     cube_input="plaintext", cube_positions=(1,),
        ...     symbolic_input="key", symbolic_positions=(0, 1),
        ... )
        >>> len(query.compute().truth_table)
        4
    """

    def __init__(
        self,
        primitive,
        *,
        output_bit,
        cube_input,
        cube_positions,
        symbolic_input=None,
        symbolic_positions=(),
        fixed_inputs=None,
        maximum_dimension=20,
    ):
        self.primitive = primitive
        self.output_bit = output_bit
        self.cube_input = cube_input
        self.cube_positions = tuple(cube_positions)
        self.symbolic_input = symbolic_input
        self.symbolic_positions = tuple(symbolic_positions)
        self.fixed_inputs = dict(fixed_inputs or {})
        if not self.cube_positions:
            raise ValueError("cube_positions must not be empty")
        if symbolic_input is None and self.symbolic_positions:
            raise ValueError("symbolic_input is required for symbolic_positions")
        for name in (cube_input, symbolic_input):
            if name is not None and name not in primitive.input_ports:
                raise ValueError(f"unknown primitive input {name!r}")
        for name, value in self.fixed_inputs.items():
            if name not in primitive.input_ports:
                raise ValueError(f"unknown fixed input {name!r}")
            primitive._decode_boundary(value, primitive.input_ports[name].value_type)
        self._validate_positions(cube_input, self.cube_positions, "cube_positions")
        if symbolic_input is not None:
            self._validate_positions(symbolic_input, self.symbolic_positions, "symbolic_positions")
        if cube_input == symbolic_input and set(self.cube_positions) & set(self.symbolic_positions):
            raise ValueError("cube and symbolic positions must be disjoint")
        if (
            not isinstance(maximum_dimension, int)
            or isinstance(maximum_dimension, bool)
            or maximum_dimension <= 0
        ):
            raise ValueError("maximum_dimension must be a positive integer")
        if len(self.cube_positions) + len(self.symbolic_positions) > maximum_dimension:
            raise ValueError("query dimension exceeds maximum_dimension")
        output_size = primitive.output.value_type.encoded_bit_size
        if (
            output_size is None
            or not isinstance(output_bit, int)
            or not 0 <= output_bit < output_size
        ):
            raise ValueError("output_bit must select a bit-encoded primitive output")

    def _validate_positions(self, name, positions, label):
        size = self.primitive.input_ports[name].value_type.encoded_bit_size
        if (
            size is None
            or len(set(positions)) != len(positions)
            or any(
                not isinstance(bit, int) or isinstance(bit, bool) or not 0 <= bit < size
                for bit in positions
            )
        ):
            raise ValueError(f"{label} must contain distinct encoded bit positions")

    @staticmethod
    def _set_positions(value, size, positions, mask):
        for local, position in enumerate(positions):
            bit = (mask >> local) & 1
            shift = size - position - 1
            value = (value & ~(1 << shift)) | (bit << shift)
        return value

    def _output_value(self, cube_mask, symbolic_mask):
        values = {name: self.fixed_inputs.get(name, 0) for name in self.primitive.input_ports}
        cube_size = self.primitive.input_ports[self.cube_input].value_type.encoded_bit_size
        values[self.cube_input] = self._set_positions(
            values[self.cube_input], cube_size, self.cube_positions, cube_mask
        )
        if self.symbolic_input is not None:
            symbolic_size = self.primitive.input_ports[
                self.symbolic_input
            ].value_type.encoded_bit_size
            values[self.symbolic_input] = self._set_positions(
                values[self.symbolic_input],
                symbolic_size,
                self.symbolic_positions,
                symbolic_mask,
            )
        encoded = self.primitive.evaluate(values)
        size = self.primitive.output.value_type.encoded_bit_size
        return (encoded >> (size - self.output_bit - 1)) & 1

    def compute(self) -> CubeSuperpolyResult:
        """Return the exact truth table and Boolean ANF of the cube coefficient."""

        table = []
        for symbolic_mask in range(1 << len(self.symbolic_positions)):
            coefficient = 0
            for cube_mask in range(1 << len(self.cube_positions)):
                coefficient ^= self._output_value(cube_mask, symbolic_mask)
            table.append(coefficient)
        coefficients = list(table)
        for bit in range(len(self.symbolic_positions)):
            for mask in range(len(coefficients)):
                if mask & (1 << bit):
                    coefficients[mask] ^= coefficients[mask ^ (1 << bit)]
        terms = tuple(
            tuple(
                position
                for bit, position in enumerate(self.symbolic_positions)
                if mask & (1 << bit)
            )
            for mask, coefficient in enumerate(coefficients)
            if coefficient
        )
        return CubeSuperpolyResult(self.symbolic_positions, tuple(table), terms)


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
