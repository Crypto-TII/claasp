"""Two-subset division-property relations and portable MILP balance tests.

This is the key-invariant two-subset property, distinct from exact
monomial prediction. A feasible trail is inconclusive; infeasibility proves
balance. Chaining additions of three or more operands is conservative,
as in the legacy model. No Gurobi license or Sage runtime is needed.
"""

from collections import Counter
from dataclasses import replace
from functools import lru_cache

from claasp.components import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    LinearMap,
    ModularAdd,
    Permutation,
    Rotate,
    SBox,
    Shift,
    Xor,
)
from claasp.representations.constraints.milp import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    LinearVariable,
    MILPModel,
    VariableKind,
)
from claasp.unit_types import BinaryExtensionField, Bit, UnitType, Word
from claasp.utils.finite_fields import binary_field_multiply


def two_subset_transition_table(table, output_width=None):
    """Return Todo's size-reduced relation as ``(input_mask, output_mask)`` pairs.

    EXAMPLES::

        >>> sorted(two_subset_transition_table((0, 1, 2, 3)))
        [(0, 0), (1, 1), (2, 2), (3, 3)]
    """
    values = tuple(table)
    if len(values) < 2 or len(values) & (len(values) - 1):
        raise ValueError("table size must be a power of two")
    output_width = max(1, max(values).bit_length()) if output_width is None else output_width
    if any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << output_width
        for value in values
    ):
        raise ValueError("table values must fit output_width")
    if len(values) > 256 or not 0 < output_width <= 8:
        raise NotImplementedError(
            "dense two-subset tables are limited to 8 input and 8 output bits"
        )
    return _two_subset_table(values, output_width)


@lru_cache(maxsize=128)
def _two_subset_table(table, output_width):
    reachable: list[list[int]] = [[] for _ in table]
    for v in range(1 << output_width):
        coefficients = [int(value & v == v) for value in table]
        for bit in range(len(table).bit_length() - 1):
            for mask in range(len(table)):
                if mask & (1 << bit):
                    coefficients[mask] ^= coefficients[mask ^ (1 << bit)]
        # Boolean downward closure of ANF support: w >= u.
        closure = list(coefficients)
        for bit in range(len(table).bit_length() - 1):
            for u in range(len(table)):
                if not u & (1 << bit):
                    closure[u] |= closure[u | (1 << bit)]
        for u, occurs in enumerate(closure):
            if occurs:
                reachable[u].append(v)
    return frozenset(
        (u, v)
        for u, outputs in enumerate(reachable)
        for v in outputs
        if not any(other != v and other & v == other for other in outputs)
    )


class _Builder:
    def __init__(self):
        self.variables: list[LinearVariable] = []
        self.constraints: list[LinearConstraint] = []

    def variable(self):
        name = f"d{len(self.variables)}"
        self.variables.append(LinearVariable(name, VariableKind.BINARY))
        return name

    def row(self, terms, rhs=0, sense=ConstraintSense.EQUAL):
        coefficients: Counter[str] = Counter()
        for name, coefficient in terms:
            coefficients[name] += coefficient
        self.constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(dict(coefficients)),
                sense,
                rhs,
                f"rule{len(self.constraints)}",
            )
        )

    def equal(self, left, right):
        self.row([(left, 1), (right, -1)])

    def point_set(self, inputs, outputs, transitions):
        points = tuple(transitions)
        selectors = [self.variable() for _ in points]
        self.row([(selector, 1) for selector in selectors], 1)
        for variables, column in [(inputs, 0), (outputs, 1)]:
            for bit, variable in enumerate(variables):
                self.row(
                    [(variable, 1)]
                    + [
                        (selector, -((point[column] >> (len(variables) - 1 - bit)) & 1))
                        for selector, point in zip(selectors, points)
                    ]
                )

    def adder(self, left, right, output):
        carry = self.variable()
        self.row([(carry, 1)], 0)
        for index in reversed(range(len(output))):
            next_carry = self.variable()
            if index == 0:
                self.row([(next_carry, 1)], 0)
            x, y, s = left[index], right[index], output[index]
            self.row(
                [(s, 1), (next_carry, 2), (x, -1), (y, -1), (carry, -1)],
                0,
                ConstraintSense.GREATER_EQUAL,
            )
            self.row(
                [(s, 2), (next_carry, 2), (x, -1), (y, -1), (carry, -1)],
                1,
                ConstraintSense.LESS_EQUAL,
            )
            carry = next_carry


def _unit_width(unit: UnitType) -> int:
    width = unit.encoded_bit_size
    if width is None:
        raise TypeError("unit type must have a canonical binary encoding")
    return width


def _check_xor_key_injections(primitive):
    secret = set(primitive.graph.secret_inputs)
    dependencies = {name: {name} for name in primitive.graph.input_arrays}
    for component in primitive.graph.components:
        operand_dependencies = [
            set().union(
                *(
                    dependencies[name]
                    for name, _ in primitive.graph.selection_bit_sources(selection)
                )
            )
            for selection in component.inputs
        ]
        combined = set().union(*operand_dependencies)
        has_key_operand = any(group and group <= secret for group in operand_dependencies)
        if has_key_operand and combined - secret:
            if (
                not isinstance(component, (Xor, Add))
                or isinstance(component, Add)
                and not isinstance(component.output_type.unit_type, (Bit, BinaryExtensionField))
            ):
                raise ValueError(
                    "removing key additions is sound only for XOR key injection; use key_schedule='independent' or 'original'"
                )
        dependencies[component.component_id] = combined


class TwoSubsetDivisionProperty:
    """Build key-invariant division-trail models and prove balanced output bits.

    ``cube_positions`` uses zero-based MSB-first bit positions in the chosen
    input. All key exponents are zero: constants and key addition are transparent.
    This does not assert the stronger exact-monomial cancellation property.
    ``key_schedule="independent"`` retains independent round-key inputs;
    ``"removed"`` drops key injections only after checking that they are XORs.

    EXAMPLES::

        >>> from claasp.primitives import Present
        >>> analysis = TwoSubsetDivisionProperty(Present(number_of_rounds=1))
        >>> model = analysis.milp_model([0, 1, 2, 3], output_bit=0)
        >>> bool(model.variables) and bool(model.constraints)
        True
    """

    def __init__(self, primitive, *, key_schedule="original"):
        if key_schedule not in ("original", "independent", "removed"):
            raise ValueError("key_schedule must be original, independent, or removed")
        self.source_primitive = primitive
        self.key_schedule = key_schedule
        if key_schedule != "original":
            from claasp.transformations import remove_key_schedule

            if key_schedule == "removed":
                _check_xor_key_injections(primitive)
            primitive = remove_key_schedule(
                primitive, keep_round_key_injection=key_schedule != "removed"
            ).primitive
        if primitive.graph.output is None:
            raise ValueError("primitive must have an output")
        arrays = [value.array_type for value in primitive.graph.input_arrays.values()]
        arrays += [component.output_type for component in primitive.graph.components]
        if not all(
            isinstance(array.unit_type, (Bit, Word, BinaryExtensionField)) for array in arrays
        ):
            raise TypeError("two-subset analysis requires canonical binary encodings")
        self.primitive = primitive

    def milp_model(self, cube_positions, *, output_bit=0, variable_input="plaintext"):
        """Return a portable feasibility model for one output bit over an input cube.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> model = Present(number_of_rounds=1).analysis.two_subset_division_property().milp_model([0, 1, 2, 3])
            >>> bool(model.variables)
            True
        """
        return self._compile(cube_positions, output_bit=output_bit, variable_input=variable_input)[
            0
        ]

    def _compile(self, cube_positions, *, output_bit, variable_input):
        graph = self.primitive.graph
        if variable_input not in graph.input_arrays:
            raise ValueError("unknown variable_input")
        width = graph.input_arrays[variable_input].array_type.encoded_bit_size
        cube = tuple(cube_positions)
        if not cube:
            raise ValueError("an integral cube must contain at least one active bit")
        if len(set(cube)) != len(cube) or any(
            not isinstance(bit, int) or isinstance(bit, bool) or not 0 <= bit < width
            for bit in cube
        ):
            raise ValueError("cube positions must be distinct input bit positions")
        size = graph.output.array_type.encoded_bit_size
        if (
            not isinstance(output_bit, int)
            or isinstance(output_bit, bool)
            or not 0 <= output_bit < size
        ):
            raise ValueError("output_bit must fit primitive output")
        build = _Builder()
        wires: dict[str, list[str]] = {}
        uses: dict[str, list[str]] = {}
        for name, array in graph.input_arrays.items():
            wires[name] = [build.variable() for _ in range(array.array_type.encoded_bit_size)]
        for component in graph.components:
            wires[component.component_id] = [
                build.variable() for _ in range(component.output_type.encoded_bit_size)
            ]
        for row in wires.values():
            for wire in row:
                uses[wire] = []
        for component in graph.components:
            operands = []
            for selection in component.inputs:
                edges = []
                for source, bit in graph.selection_bit_sources(selection):
                    edge = build.variable()
                    uses[wires[source][bit]].append(edge)
                    edges.append(edge)
                operands.append(edges)
            output = wires[component.component_id]
            self._component_rules(build, component, operands, output)
        output_constraints = []
        for index, (source, bit) in enumerate(graph.selection_bit_sources(graph.output)):
            sink = build.variable()
            uses[wires[source][bit]].append(sink)
            output_constraints.append(len(build.constraints))
            build.row([(sink, 1)], int(index == output_bit))
        for wire, copies in uses.items():
            build.row([(wire, -1)] + [(edge, 1) for edge in copies])
        for name, row in wires.items():
            if name not in graph.input_arrays:
                continue
            for bit, wire in enumerate(row):
                build.row([(wire, 1)], int(name == variable_input and bit in cube))
        return MILPModel(tuple(build.variables), tuple(build.constraints)), tuple(
            output_constraints
        )

    def is_balanced_over_cube_scan(
        self, output_bit_indices, cube_positions, *, variable_input="plaintext", solver=None
    ):
        """Return a balance verdict for each bit; unknown solver status raises.

        Feasibility means the two-subset rule cannot prove balance, rather than
        proving the actual function unbalanced. Only infeasibility certifies balance.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> analysis = Present(number_of_rounds=1).analysis.two_subset_division_property()
            >>> analysis.is_balanced_over_cube_scan([], [0])
            {}
            >>> analysis.is_balanced_over_cube_scan([0, 4], [0, 1, 2, 3])  # doctest: +SKIP
            {0: True, 4: True}

        The last call requires the ``glpsol`` executable; the integration tests
        run this method against retained legacy and exhaustive local fixtures.
        """
        from claasp.drivers.solvers import GLPKSolver, MILPStatus

        selected = GLPKSolver() if solver is None else solver
        targets = tuple(output_bit_indices)
        if not targets:
            return {}
        results = {}
        base, output_constraints = self._compile(
            tuple(cube_positions), output_bit=targets[0], variable_input=variable_input
        )
        size = self.primitive.graph.output.array_type.encoded_bit_size
        for bit in targets:
            if not isinstance(bit, int) or isinstance(bit, bool) or not 0 <= bit < size:
                raise ValueError("output bit index must fit primitive output")
            constraints = list(base.constraints)
            for index, constraint_index in enumerate(output_constraints):
                constraints[constraint_index] = replace(
                    constraints[constraint_index], rhs=int(index == bit)
                )
            solved = selected.solve(replace(base, constraints=tuple(constraints)))
            if solved.status is MILPStatus.UNKNOWN:
                raise RuntimeError("solver returned unknown; balance is not proved")
            results[bit] = solved.status is MILPStatus.INFEASIBLE
        return results

    def is_balanced_at_specific_output_bit_over_cube(
        self, output_bit, cube_positions, *, variable_input="plaintext", solver=None
    ):
        """Prove balance of one output bit over the specified nonempty cube.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> analysis = Present(number_of_rounds=1).analysis.two_subset_division_property()
            >>> analysis.is_balanced_at_specific_output_bit_over_cube(0, [0, 1, 2, 3])  # doctest: +SKIP
            True

        This example requires ``glpsol``.
        """
        return self.is_balanced_over_cube_scan(
            (output_bit,), cube_positions, variable_input=variable_input, solver=solver
        )[output_bit]

    def is_balanced_at_all_output_bits_over_cube(
        self, cube_positions, *, variable_input="plaintext", solver=None
    ):
        """Return whether the two-subset model proves every output bit balanced.

        EXAMPLES::

            >>> from claasp.primitives import Present
            >>> analysis = Present(number_of_rounds=1).analysis.two_subset_division_property()
            >>> analysis.is_balanced_at_all_output_bits_over_cube([0, 1, 2, 3])  # doctest: +SKIP
            True

        This example requires ``glpsol``.
        """
        size = self.primitive.graph.output.array_type.encoded_bit_size
        return all(
            self.is_balanced_over_cube_scan(
                range(size), cube_positions, variable_input=variable_input, solver=solver
            ).values()
        )

    @staticmethod
    def _component_rules(build, component, operands, output):
        if isinstance(component, Constant):
            for bit in output:
                build.row([(bit, 1)], 0)
        elif isinstance(component, (Xor, Add)):
            if isinstance(component, Add) and not isinstance(
                component.output_type.unit_type, (Bit, BinaryExtensionField)
            ):
                raise NotImplementedError("Add must use characteristic-two units")
            for index, bit in enumerate(output):
                build.row([(bit, -1)] + [(operand[index], 1) for operand in operands])
        elif isinstance(component, (BitwiseAnd, BitwiseOr)):
            for index, bit in enumerate(output):
                for operand in operands:
                    build.row([(bit, 1), (operand[index], -1)], 0, ConstraintSense.GREATER_EQUAL)
                build.row(
                    [(bit, 1)] + [(operand[index], -1) for operand in operands],
                    0,
                    ConstraintSense.LESS_EQUAL,
                )
        elif isinstance(component, (Identity, BitwiseNot)):
            for left, right in zip(operands[0], output):
                build.equal(left, right)
        elif isinstance(component, Permutation):
            width = _unit_width(component.output_type.unit_type)
            for unit, source in enumerate(component.mapping):
                for bit in range(width):
                    build.equal(output[unit * width + bit], operands[0][source * width + bit])
        elif isinstance(component, (Rotate, Shift)):
            width = _unit_width(component.output_type.unit_type)
            for index, bit in enumerate(output):
                unit, position = divmod(index, width)
                source = position + (
                    component.amount if component.direction == "left" else -component.amount
                )
                if isinstance(component, Rotate):
                    source %= width
                if 0 <= source < width:
                    build.equal(bit, operands[0][unit * width + source])
                else:
                    build.row([(bit, 1)], 0)
        elif isinstance(component, ModularAdd):
            width = _unit_width(component.output_type.unit_type)
            if component.modulus not in (None, 1 << width):
                raise NotImplementedError("two-subset addition requires power-of-two modulus")
            accumulator = operands[0]
            for number, operand in enumerate(operands[1:], 1):
                target = (
                    output if number == len(operands) - 1 else [build.variable() for _ in output]
                )
                for start in range(0, len(output), width):
                    build.adder(
                        accumulator[start : start + width],
                        operand[start : start + width],
                        target[start : start + width],
                    )
                accumulator = target
        elif isinstance(component, (BitVectorSBox, SBox)):
            if isinstance(component, BitVectorSBox):
                build.point_set(
                    operands[0], output, two_subset_transition_table(component.table, len(output))
                )
            else:
                width = _unit_width(component.output_type.unit_type)
                for start in range(0, len(output), width):
                    build.point_set(
                        operands[0][start : start + width],
                        output[start : start + width],
                        two_subset_transition_table(component.table, width),
                    )
        elif isinstance(component, BinaryAffineMap):
            width = _unit_width(component.output_type.unit_type)
            rows: list[list[str]] = [[] for _ in output]
            copies: list[list[str]] = [[] for _ in operands[0]]
            for unit in range(component.output_type.unit_count):
                for row, coefficients in enumerate(component.matrix):
                    for column, coefficient in enumerate(coefficients):
                        if coefficient:
                            edge = build.variable()
                            copies[unit * width + column].append(edge)
                            rows[unit * width + row].append(edge)
            for source, fanout in zip(operands[0], copies):
                build.row([(source, -1)] + [(edge, 1) for edge in fanout])
            for target, sources in zip(output, rows):
                build.row([(target, -1)] + [(source, 1) for source in sources])
        elif isinstance(component, LinearMap):
            field_type = component.output_type.unit_type
            if not isinstance(field_type, (Bit, BinaryExtensionField)):
                raise NotImplementedError(
                    "linear division rules require a characteristic-two field"
                )
            width = _unit_width(field_type)
            rows = [[] for _ in output]
            copies = [[] for _ in operands[0]]
            for row, coefficients in enumerate(component.matrix):
                for column, coefficient in enumerate(coefficients):
                    for source_bit in range(width):
                        basis = 1 << (width - 1 - source_bit)
                        product = (
                            (coefficient & basis)
                            if isinstance(field_type, Bit)
                            else binary_field_multiply(field_type, coefficient, basis)
                        )
                        for target_bit in range(width):
                            if product & (1 << (width - 1 - target_bit)):
                                edge = build.variable()
                                copies[column * width + source_bit].append(edge)
                                rows[row * width + target_bit].append(edge)
            for source, fanout in zip(operands[0], copies):
                build.row([(source, -1)] + [(edge, 1) for edge in fanout])
            for target, sources in zip(output, rows):
                build.row([(target, -1)] + [(source, 1) for source in sources])
        else:
            raise NotImplementedError(
                f"no two-subset division rule for {type(component).__name__}: {component.component_id}"
            )


__all__ = ["TwoSubsetDivisionProperty", "two_subset_transition_table"]
