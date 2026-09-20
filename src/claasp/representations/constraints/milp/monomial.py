"""Exact portable MILP representation of component monomial transitions."""

from claasp.representations.constraints.milp.model import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    ObjectiveSense,
    VariableKind,
)
from claasp.representations.constraints.polynomial.boolean import monomial_transition_table


class BooleanMonomialGraphMILPModel:
    """Monomial-reachability degree model for Boolean Bit/Word graphs.

    The initial graph-wide slice supports the structural and Boolean word
    components needed by Simon. Every component input has a separate edge
    exponent; fan-out is modeled as Boolean COPY rather than accidental
    equality between all consumers.


    EXAMPLES::

        >>> try:
        ...     BooleanMonomialGraphMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(
        self, primitive, output_bit: int, variable_input: str, variable_positions=None
    ) -> None:
        from claasp.domains import Bit, Word

        if variable_input not in primitive.input_ports:
            raise ValueError(f"unknown variable input: {variable_input}")
        if primitive.output is None:
            raise ValueError("primitive must have an output")
        output_width = primitive.output.value_type.encoded_bit_size
        if (
            not isinstance(output_bit, int)
            or isinstance(output_bit, bool)
            or output_width is None
            or not 0 <= output_bit < output_width
        ):
            raise ValueError("output_bit must fit the primitive output")
        domains = [port.value_type.domain for port in primitive.input_ports.values()]
        domains += [component.output_type.domain for component in primitive.components]
        if not all(isinstance(domain, (Bit, Word)) for domain in domains):
            raise TypeError("Boolean monomial graph models require Bit or Word domains")
        self.primitive = primitive
        self.output_bit = output_bit
        self.variable_input = variable_input
        selected_width = self._width(primitive.input_ports[variable_input].value_type)
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
    def _width(value_type):
        width = value_type.encoded_bit_size
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

        for name, port in self.primitive.input_ports.items():
            add_wire(name, self._width(port.value_type))
        for component in self.primitive.components:
            add_wire(component.component_id, self._width(component.output_type))

        for component_index, component in enumerate(self.primitive.components):
            operand_edges = []
            for operand, selection in enumerate(component.inputs):
                edges = []
                for bit, (owner_id, source_bit) in enumerate(
                    self.primitive.selection_bit_sources(selection)
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
            self.primitive.selection_bit_sources(self.primitive.output)
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

        selected_width = self._width(self.primitive.input_ports[self.variable_input].value_type)
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
        return MILPModel(tuple(variables), tuple(constraints), objective, ObjectiveSense.MAXIMIZE)


class MonomialTransitionMILPModel:
    """Select one exact input/output monomial transition of a lookup table.

    EXAMPLES::

        >>> try:
        ...     MonomialTransitionMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

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
        return MILPModel(variables, tuple(constraints))

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


class PresentMonomialTrailMILPModel:
    """Compose exact local monomial transitions over reduced PRESENT rounds.

    EXAMPLES::

        >>> try:
        ...     PresentMonomialTrailMILPModel()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive, input_mask: int, output_mask: int) -> None:
        from claasp.components import BitVectorSBox, Permutation

        if primitive.family_name != "present":
            raise ValueError("primitive must be a typed PRESENT graph")
        for name, mask in (("input_mask", input_mask), ("output_mask", output_mask)):
            if not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask < 1 << 64:
                raise ValueError(f"{name} must be a 64-bit exponent vector")
        self.primitive = primitive
        self.input_mask = input_mask
        self.output_mask = output_mask
        self.round_count = len(primitive.rounds)
        first_sbox = next(
            component
            for component in primitive.components
            if isinstance(component, BitVectorSBox) and component.component_id == "sbox_1_0"
        )
        table = monomial_transition_table(first_sbox.table)
        self.local_transitions = tuple(
            (input_value, output_value)
            for output_value, input_values in table.items()
            for input_value in sorted(input_values)
        )
        self.permutations = tuple(
            next(
                component
                for component in primitive.components
                if isinstance(component, Permutation)
                and component.component_id == f"p_layer_{round_number}"
            )
            for round_number in range(1, self.round_count + 1)
        )

    def milp_model(self) -> MILPModel:
        """Return the complete fixed-boundary portable MILP query."""

        variables = []
        constraints = []
        for boundary in range(self.round_count + 1):
            variables.extend(
                LinearVariable(f"state_{boundary}_{bit}", VariableKind.BINARY) for bit in range(64)
            )
        for round_index in range(self.round_count):
            variables.extend(
                LinearVariable(f"sub_{round_index}_{bit}", VariableKind.BINARY) for bit in range(64)
            )
            for nibble in range(16):
                selectors = tuple(
                    f"select_{round_index}_{nibble}_{index}"
                    for index in range(len(self.local_transitions))
                )
                variables.extend(LinearVariable(name, VariableKind.BINARY) for name in selectors)
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms({name: 1 for name in selectors}),
                        ConstraintSense.EQUAL,
                        1,
                        f"one_{round_index}_{nibble}",
                    )
                )
                for local_bit in range(4):
                    position = 4 * nibble + local_bit
                    input_terms = {f"state_{round_index}_{position}": 1}
                    output_terms = {f"sub_{round_index}_{position}": 1}
                    for index, (input_value, output_value) in enumerate(self.local_transitions):
                        shift = 3 - local_bit
                        if (input_value >> shift) & 1:
                            input_terms[selectors[index]] = -1
                        if (output_value >> shift) & 1:
                            output_terms[selectors[index]] = -1
                    constraints.extend(
                        (
                            LinearConstraint(
                                LinearExpression.from_terms(input_terms), ConstraintSense.EQUAL, 0
                            ),
                            LinearConstraint(
                                LinearExpression.from_terms(output_terms), ConstraintSense.EQUAL, 0
                            ),
                        )
                    )
            for output_position, input_position in enumerate(
                self.permutations[round_index].mapping
            ):
                constraints.append(
                    LinearConstraint(
                        LinearExpression.from_terms(
                            {
                                f"state_{round_index + 1}_{output_position}": 1,
                                f"sub_{round_index}_{input_position}": -1,
                            }
                        ),
                        ConstraintSense.EQUAL,
                        0,
                        f"permute_{round_index}_{output_position}",
                    )
                )
        for bit in range(64):
            shift = 63 - bit
            constraints.extend(
                (
                    LinearConstraint(
                        LinearExpression.from_terms({f"state_0_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (self.input_mask >> shift) & 1,
                        f"fix_input_{bit}",
                    ),
                    LinearConstraint(
                        LinearExpression.from_terms({f"state_{self.round_count}_{bit}": 1}),
                        ConstraintSense.EQUAL,
                        (self.output_mask >> shift) & 1,
                        f"fix_output_{bit}",
                    ),
                )
            )
        return MILPModel(tuple(variables), tuple(constraints))

    def decode_trail(self, assignment):
        """Decode a solver witness and validate it with independent semantics."""

        from claasp.analysis.monomial import (
            MonomialTrail,
            MonomialTrailStep,
            MultiRoundMonomialTrail,
            PresentMonomialSemantics,
        )

        def mask(prefix):
            value = 0
            for bit in range(64):
                value = (value << 1) | int(round(assignment[f"{prefix}_{bit}"]))
            return value

        rounds = []
        for round_index in range(self.round_count):
            source = mask(f"state_{round_index}")
            substituted = mask(f"sub_{round_index}")
            target = mask(f"state_{round_index + 1}")
            steps = tuple(
                MonomialTrailStep(
                    f"sbox_{round_index + 1}_{nibble}",
                    (source >> (4 * (15 - nibble))) & 0xF,
                    (substituted >> (4 * (15 - nibble))) & 0xF,
                )
                for nibble in range(16)
            ) + (MonomialTrailStep(f"p_layer_{round_index + 1}", substituted, target),)
            rounds.append(
                MonomialTrail(
                    source, target, 64, steps, "plaintext", f"typed PRESENT round {round_index + 1}"
                )
            )
        trail = MultiRoundMonomialTrail(
            self.input_mask,
            self.output_mask,
            tuple(rounds),
            "portable MILP monomial witness through typed PRESENT graph",
        )
        if not PresentMonomialSemantics(self.primitive).check(trail):
            raise ValueError("solver returned an invalid PRESENT monomial trail")
        return trail
