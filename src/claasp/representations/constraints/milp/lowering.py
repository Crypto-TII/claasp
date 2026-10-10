"""Select and compose MILP component encodings for complete graphs."""

from typing import cast

from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
    _verified_model,
)
from claasp.representations.constraints.sat import BooleanCNFModel, CNFFormula

from .model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)


def cnf_to_milp(formula):
    """Translate each clause to the exact inequality ``sum(literals) >= 1``.

    A positive literal is ``x``; a negative literal is ``1-x``. Repeated
    variables are combined, including tautological positive/negative pairs.
    No convex-hull package, Sage, or proprietary solver is needed.


    EXAMPLES::

        >>> formula = CNFFormula(("x", "y"), ((1, -2),), ("implication",))
        >>> model = cnf_to_milp(formula)
        >>> model.is_feasible({"x": 1, "y": 1})
        True
        >>> model.is_feasible({"x": 0, "y": 1})
        False
    """
    if not isinstance(formula, CNFFormula):
        raise TypeError("formula must be a CNFFormula")
    constraints = []
    for number, clause in enumerate(formula.clauses):
        terms, negative = {}, 0
        for literal in clause:
            name = formula.variables[abs(literal) - 1]
            terms[name] = terms.get(name, 0) + (1 if literal > 0 else -1)
            negative += literal < 0
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(terms),
                ConstraintSense.GREATER_EQUAL,
                1 - negative,
                f"clause_{number}",
            )
        )
    return MILPModel(
        tuple(LinearVariable(name, VariableKind.BINARY) for name in formula.variables),
        tuple(constraints),
        constraint_models=formula.constraint_models,
    )


class BooleanGraphMILPModel:
    """Exact Bit/Word graph execution, not a differential propagation model.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> from claasp.representations.execution import ScalarEvaluator
        >>> primitive = Speck(number_of_rounds=1)
        >>> execution = BooleanGraphMILPModel(primitive)
        >>> values = ScalarEvaluator().evaluate(
        ...     primitive,
        ...     {"plaintext": (0x6574, 0x694C), "key": (0x1918, 0x1110, 0x0908, 0x0100)},
        ... )
        >>> execution.milp_model().is_feasible(execution.witness(values))
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.MILP,
        "BooleanGraphMILPModel",
        "functional",
        "literal CNF-clause inequality graph lowering",
        "Each clause becomes its exact sum-of-literals inequality and component provenance is retained.",
    )

    def __init__(self, primitive):
        self.boolean_model = BooleanCNFModel(primitive)

    def milp_model(self):
        """Compute the milp model for this public typed contract."""

        return cnf_to_milp(self.boolean_model.cnf_formula())

    def witness(self, evaluation):
        """Derive every binary auxiliary from independent scalar execution."""
        return self.boolean_model.witness(evaluation)


class BooleanMonomialGraphMILPModel:
    """Monomial-reachability degree model for Boolean Bit/Word graphs.

    The initial graph-wide slice supports the structural and Boolean word
    components needed by Simon. Every component input has a separate edge
    exponent; fan-out is modeled as Boolean COPY rather than accidental
    equality between all consumers.


    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> compilation = BooleanMonomialGraphMILPModel(
        ...     Simon(number_of_rounds=2), 0, "plaintext"
        ... )
        >>> model = compilation.milp_model()
        >>> model.objective_sense.value
        'maximize'
        >>> len(model.objective.terms)
        32
    """

    model_provenance = _verified_model(
        ConstraintBackend.MILP,
        "BooleanMonomialGraphMILPModel",
        "monomial_prediction",
        "COPY, AND, XOR, and bit-permutation monomial-trail rules",
        "https://eprint.iacr.org/2020/1048",
        "An Algebraic Formulation of the Division Property: Revisiting Degree Evaluations, Cube Attacks, and Key-Independent Sums",
        "section 4.2, MILP model for the monomial trail of f^(i)",
    )

    def __init__(
        self, primitive, output_bit: int, variable_input: str, variable_positions=None
    ) -> None:
        from claasp.domains import Bit, Word

        if variable_input not in primitive.graph.input_ports:
            raise ValueError(f"unknown variable input: {variable_input}")
        if primitive.graph.output is None:
            raise ValueError("primitive must have an output")
        output_width = primitive.graph.output.array_type.encoded_bit_size
        if (
            not isinstance(output_bit, int)
            or isinstance(output_bit, bool)
            or output_width is None
            or not 0 <= output_bit < output_width
        ):
            raise ValueError("output_bit must fit the primitive output")
        domains = [port.array_type.domain for port in primitive.graph.input_ports.values()]
        domains += [component.output_type.domain for component in primitive.graph.components]
        if not all(isinstance(domain, (Bit, Word)) for domain in domains):
            raise TypeError("Boolean monomial graph models require Bit or Word domains")
        self.primitive = primitive
        self.output_bit = output_bit
        self.variable_input = variable_input
        selected_width = self._width(primitive.graph.input_ports[variable_input].array_type)
        self.variable_positions = tuple(
            range(selected_width) if variable_positions is None else variable_positions
        )
        if len(set(self.variable_positions)) != len(self.variable_positions) or any(
            not isinstance(position, int)
            or isinstance(position, bool)
            or not 0 <= position < selected_width
            for position in self.variable_positions
        ):
            raise ValueError("variable_positions must be unique positions in variable_input")

    @staticmethod
    def _wire(owner_id, bit):
        return f"wire_{owner_id}_{bit}"

    @staticmethod
    def _edge(component_index, operand, bit):
        return f"edge_{component_index}_{operand}_{bit}"

    @staticmethod
    def _width(array_type):
        width = array_type.encoded_bit_size
        if width is None:
            raise TypeError("value must have a canonical bit encoding")
        return width

    def milp_model(self) -> MILPModel:
        """Return a portable maximization model for the selected output bit."""

        from claasp.components import BitwiseAnd, Constant, Rotate, Xor

        variables = []
        constraints = []
        uses = {}

        def add_wire(owner_id, width):
            for bit in range(width):
                name = self._wire(owner_id, bit)
                variables.append(LinearVariable(name, VariableKind.BINARY))
                uses[name] = []

        for name, port in self.primitive.graph.input_ports.items():
            add_wire(name, self._width(port.array_type))
        for component in self.primitive.graph.components:
            add_wire(component.component_id, self._width(component.output_type))

        for component_index, component in enumerate(self.primitive.graph.components):
            operand_edges = []
            for operand, selection in enumerate(component.inputs):
                edges = []
                for bit, (owner_id, source_bit) in enumerate(
                    self.primitive.graph.selection_bit_sources(selection)
                ):
                    edge = self._edge(component_index, operand, bit)
                    variables.append(LinearVariable(edge, VariableKind.BINARY))
                    uses[self._wire(owner_id, source_bit)].append(edge)
                    edges.append(edge)
                operand_edges.append(tuple(edges))

            output = tuple(
                self._wire(component.component_id, bit)
                for bit in range(self._width(component.output_type))
            )
            if isinstance(component, Xor):
                for bit, target in enumerate(output):
                    terms = {target: -1, **{edges[bit]: 1 for edges in operand_edges}}
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms(terms),
                            ConstraintSense.EQUAL,
                            0,
                            f"xor_{component_index}_{bit}",
                        )
                    )
            elif isinstance(component, BitwiseAnd):
                for bit, target in enumerate(output):
                    for operand, edges in enumerate(operand_edges):
                        constraints.append(
                            LinearConstraint(
                                LinearExpression.from_terms({edges[bit]: 1, target: -1}),
                                ConstraintSense.EQUAL,
                                0,
                                f"and_{component_index}_{operand}_{bit}",
                            )
                        )
            elif isinstance(component, Rotate):
                width = len(output)
                amount = component.amount % width
                for bit, target in enumerate(output):
                    source_bit = (
                        (bit + amount) if component.direction == "left" else (bit - amount)
                    ) % width
                    constraints.append(
                        LinearConstraint(
                            LinearExpression.from_terms(
                                {operand_edges[0][source_bit]: 1, target: -1}
                            ),
                            ConstraintSense.EQUAL,
                            0,
                            f"rotate_{component_index}_{bit}",
                        )
                    )
            elif isinstance(component, Constant):
                domain_width = component.output_type.domain.encoded_bit_size
                for unit, value in enumerate(component.values):
                    for local_bit in range(domain_width):
                        bit = unit * domain_width + local_bit
                        if not value & (1 << (domain_width - 1 - local_bit)):
                            constraints.append(
                                LinearConstraint(
                                    LinearExpression.from_terms({output[bit]: 1}),
                                    ConstraintSense.EQUAL,
                                    0,
                                    f"constant_{component_index}_{bit}",
                                )
                            )
            else:
                raise NotImplementedError(
                    f"Boolean monomial graph MILP does not support {type(component).__name__}"
                )

        for bit, (owner_id, source_bit) in enumerate(
            self.primitive.graph.selection_bit_sources(self.primitive.graph.output)
        ):
            edge = f"primitive_output_{bit}"
            variables.append(LinearVariable(edge, VariableKind.BINARY))
            uses[self._wire(owner_id, source_bit)].append(edge)
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms({edge: 1}),
                    ConstraintSense.EQUAL,
                    int(bit == self.output_bit),
                    f"fix_output_{bit}",
                )
            )

        for wire, consumers in uses.items():
            if not consumers:
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({wire: 1}),
                        ConstraintSense.EQUAL,
                        0,
                        f"dead_{wire}",
                    )
                )
                continue
            for index, consumer in enumerate(consumers):
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({wire: 1, consumer: -1}),
                        ConstraintSense.GREATER_EQUAL,
                        0,
                        f"copy_lower_{wire}_{index}",
                    )
                )
            constraints.append(
                LinearConstraint(
                    LinearExpression.from_terms(
                        {wire: 1, **{consumer: -1 for consumer in consumers}}
                    ),
                    ConstraintSense.LESS_EQUAL,
                    0,
                    f"copy_upper_{wire}",
                )
            )

        selected_width = self._width(
            self.primitive.graph.input_ports[self.variable_input].array_type
        )
        selected_positions = set(self.variable_positions)
        for bit in range(selected_width):
            if bit not in selected_positions:
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({self._wire(self.variable_input, bit): 1}),
                        ConstraintSense.EQUAL,
                        0,
                        f"exclude_variable_{bit}",
                    )
                )
        objective = LinearExpression.from_terms(
            {self._wire(self.variable_input, bit): 1 for bit in self.variable_positions}
        )
        return MILPModel(
            tuple(variables),
            tuple(constraints),
            objective,
            ObjectiveSense.MAXIMIZE,
            constraint_models=(
                ConstraintModelApplication(
                    self.model_provenance,
                    tuple(
                        cast(str, component.component_id)
                        for component in self.primitive.graph.components
                    ),
                ),
            ),
        )
