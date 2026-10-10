"""Whole-graph monomial-trail composition for supported primitive slices."""

from dataclasses import dataclass

from claasp.components import BitVectorSBox, Permutation
from claasp.representations.constraints.milp import (
    ConstraintSense,
    LinearConstraint,
    LinearExpression,
    MILPModel,
)
from claasp.representations.constraints.polynomial import monomial_transition_table
from claasp.semantics.cryptanalysis.monomial import ComponentMonomialSemantics


@dataclass(frozen=True, slots=True)
class MonomialTrailStep:
    """One named component input/output exponent transition.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MonomialTrailStep.__dataclass_params__.frozen, tuple(field.name for field in fields(MonomialTrailStep)))
        (True, ('component_id', 'input_mask', 'output_mask'))
    """

    component_id: str
    input_mask: int
    output_mask: int


@dataclass(frozen=True, slots=True)
class MonomialTrail:
    """A reachable monomial exponent pair and its component witness.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MonomialTrail.__dataclass_params__.frozen, tuple(field.name for field in fields(MonomialTrail)))
        (True, ('input_mask', 'output_mask', 'width', 'steps', 'variable_group', 'provenance'))
    """

    input_mask: int
    output_mask: int
    width: int
    steps: tuple[MonomialTrailStep, ...]
    variable_group: str
    provenance: str


class PresentRoundMonomialSemantics:
    """Compose exact S-box monomial transitions through one typed PRESENT round.

    The tracked variable group is plaintext. XOR with key variables therefore
    selects the state term, while concatenation is structural and the p-layer
    permutes exponent bits. This is monomial-trail reachability; parity-based
    cancellation is a separate analysis.


    EXAMPLES::

        >>> try:
        ...     PresentRoundMonomialSemantics()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive) -> None:
        sboxes = tuple(
            component
            for component in primitive.graph.components
            if isinstance(component, BitVectorSBox) and component.component_id.startswith("sbox_1_")
        )
        permutations = tuple(
            component
            for component in primitive.graph.components
            if isinstance(component, Permutation) and component.component_id == "p_layer_1"
        )
        if primitive.family_name != "present" or len(primitive.graph.rounds) != 1:
            raise ValueError("primitive must be a one-round typed PRESENT graph")
        if len(sboxes) != 16 or len(permutations) != 1:
            raise ValueError("PRESENT graph does not expose the expected S-box/p-layer structure")
        self.primitive = primitive
        self.sboxes = tuple(
            sorted(sboxes, key=lambda component: int(component.component_id.rsplit("_", 1)[1]))
        )
        self.permutation = permutations[0]
        self.tables = tuple(monomial_transition_table(component.table) for component in self.sboxes)

    def trail(self, input_mask: int, output_mask: int) -> MonomialTrail | None:
        """Return a component witness, or ``None`` when the pair is unreachable."""

        limit = 1 << 64
        if any(
            not isinstance(mask, int) or isinstance(mask, bool) or not 0 <= mask < limit
            for mask in (input_mask, output_mask)
        ):
            raise ValueError("PRESENT monomial masks must be 64-bit integers")
        before_permutation = self._inverse_permute(output_mask)
        steps = []
        for index, _table in enumerate(self.tables):
            shift = 4 * (15 - index)
            local_input = (input_mask >> shift) & 0xF
            local_output = (before_permutation >> shift) & 0xF
            if not ComponentMonomialSemantics.is_possible(
                self.sboxes[index], (local_input,), local_output
            ):
                return None
            steps.append(
                MonomialTrailStep(self.sboxes[index].component_id, local_input, local_output)
            )
        steps.append(MonomialTrailStep("p_layer_1", before_permutation, output_mask))
        if not ComponentMonomialSemantics.is_possible(
            self.permutation, (before_permutation,), output_mask
        ):
            raise RuntimeError(
                "typed permutation mapping produced an inconsistent monomial boundary"
            )
        return MonomialTrail(
            input_mask,
            output_mask,
            64,
            tuple(steps),
            "plaintext",
            "typed PRESENT round; exact component 3SDP-woU transitions",
        )

    def check(self, trail: MonomialTrail) -> bool:
        """Independently reconstruct and validate every component boundary."""

        if not isinstance(trail, MonomialTrail) or trail.width != 64 or len(trail.steps) != 17:
            return False
        rebuilt = self.trail(trail.input_mask, trail.output_mask)
        return rebuilt == trail

    def _inverse_permute(self, output_mask: int) -> int:
        output_bits = tuple((output_mask >> (63 - index)) & 1 for index in range(64))
        input_bits = [0] * 64
        for output_position, input_position in enumerate(self.permutation.mapping):
            input_bits[input_position] = output_bits[output_position]
        result = 0
        for bit in input_bits:
            result = (result << 1) | bit
        return result


@dataclass(frozen=True, slots=True)
class MultiRoundMonomialTrail:
    """Ordered round witnesses for a complete fixed-boundary query.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MultiRoundMonomialTrail.__dataclass_params__.frozen, tuple(field.name for field in fields(MultiRoundMonomialTrail)))
        (True, ('input_mask', 'output_mask', 'rounds', 'provenance'))
    """

    input_mask: int
    output_mask: int
    rounds: tuple[MonomialTrail, ...]
    provenance: str


class PresentMonomialSemantics:
    """Deterministically construct and check multi-round PRESENT predecessors.

    EXAMPLES::

        >>> try:
        ...     PresentMonomialSemantics()
        ... except TypeError:
        ...     print("required configuration rejected")
        required configuration rejected
    """

    def __init__(self, primitive) -> None:
        if primitive.family_name != "present":
            raise ValueError("primitive must be a typed PRESENT graph")
        self.primitive = primitive
        self.round_count = len(primitive.graph.rounds)
        self.sbox_table = monomial_transition_table(
            next(
                component
                for component in primitive.graph.components
                if component.component_id == "sbox_1_0"
            ).table
        )
        self.permutations = tuple(
            next(
                component
                for component in primitive.graph.components
                if component.component_id == f"p_layer_{round_number}"
            )
            for round_number in range(1, self.round_count + 1)
        )

    def predecessor_trail(self, output_mask: int) -> MultiRoundMonomialTrail:
        """Choose a canonical exact predecessor for a requested output monomial."""

        if (
            not isinstance(output_mask, int)
            or isinstance(output_mask, bool)
            or not 0 <= output_mask < 1 << 64
        ):
            raise ValueError("output_mask must be a 64-bit exponent vector")
        following = output_mask
        reversed_rounds = []
        for round_number in range(self.round_count, 0, -1):
            permutation = self.permutations[round_number - 1]
            before_permutation = ComponentMonomialSemantics._permutation_input(
                permutation, following
            )
            predecessor = 0
            steps = []
            for nibble in range(16):
                shift = 4 * (15 - nibble)
                local_output = (before_permutation >> shift) & 0xF
                local_input = min(self.sbox_table[local_output])
                predecessor |= local_input << shift
                steps.append(
                    MonomialTrailStep(f"sbox_{round_number}_{nibble}", local_input, local_output)
                )
            steps.append(
                MonomialTrailStep(f"p_layer_{round_number}", before_permutation, following)
            )
            reversed_rounds.append(
                MonomialTrail(
                    predecessor,
                    following,
                    64,
                    tuple(steps),
                    "plaintext",
                    f"typed PRESENT round {round_number}",
                )
            )
            following = predecessor
        rounds = tuple(reversed(reversed_rounds))
        return MultiRoundMonomialTrail(
            following,
            output_mask,
            rounds,
            "canonical exact 3SDP-woU predecessor through typed PRESENT graph",
        )

    def check(self, trail: MultiRoundMonomialTrail) -> bool:
        """Check every local transition and inter-round boundary independently."""

        if not isinstance(trail, MultiRoundMonomialTrail) or len(trail.rounds) != self.round_count:
            return False
        boundary = trail.input_mask
        for index, round_trail in enumerate(trail.rounds, 1):
            if round_trail.input_mask != boundary or len(round_trail.steps) != 17:
                return False
            before = 0
            for nibble, step in enumerate(round_trail.steps[:-1]):
                if step.component_id != f"sbox_{index}_{nibble}":
                    return False
                component = next(
                    item
                    for item in self.primitive.graph.components
                    if item.component_id == step.component_id
                )
                if not ComponentMonomialSemantics.is_possible(
                    component, (step.input_mask,), step.output_mask
                ):
                    return False
                before = (before << 4) | step.output_mask
            permutation = self.permutations[index - 1]
            if not ComponentMonomialSemantics.is_possible(
                permutation, (before,), round_trail.output_mask
            ):
                return False
            boundary = round_trail.output_mask
        return boundary == trail.output_mask


@dataclass(frozen=True, slots=True)
class MonomialParityResult:
    """Parity of completely enumerated optimal monomial paths.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (MonomialParityResult.__dataclass_params__.frozen, tuple(field.name for field in fields(MonomialParityResult)))
        (True, ('degree', 'odd_input_monomials', 'enumerated_paths', 'complete', 'termination'))
    """

    degree: int | None
    odd_input_monomials: tuple[int, ...]
    enumerated_paths: int
    complete: bool
    termination: str

    def require_complete(self) -> "MonomialParityResult":
        """Compute the require complete for this public typed contract."""

        if not self.complete:
            raise RuntimeError("monomial-path enumeration is incomplete")
        return self


@dataclass(frozen=True, slots=True)
class SolutionPoolMonomialParityResult:
    """Parity-cancelled input monomials projected from an optimal path pool.

    Variable names retain their full input identity, so bits from different
    inputs cannot cancel accidentally.

    EXAMPLES::

        >>> result = SolutionPoolMonomialParityResult(
        ...     (("key[0]", "plaintext[1]"),), 3, True, "exhaustive_pool"
        ... )
        >>> result.maximum_degree("key")
        1
    """

    odd_input_monomials: tuple[tuple[str, ...], ...]
    enumerated_paths: int
    complete: bool
    termination: str

    def require_complete(self) -> "SolutionPoolMonomialParityResult":
        """Reject a pool whose capacity or solver termination hid paths."""

        if not self.complete:
            raise RuntimeError("monomial solution-pool projection is incomplete")
        return self

    def maximum_degree(self, input_name: str) -> int:
        """Return the largest surviving degree in one named primitive input."""

        self.require_complete()
        prefix = f"{input_name}["
        return max(
            (
                sum(variable.startswith(prefix) for variable in monomial)
                for monomial in self.odd_input_monomials
            ),
            default=0,
        )


def project_optimal_pool_monomial_parity(compilation, pool):
    """Project a validated optimal solution pool and cancel equal paths mod two.

    This is the dependency-free counterpart of the legacy Sage Boolean-ring
    conversion. It operates in time linear in the returned assignments and
    symbolic input width. A truncated Gurobi pool remains visibly incomplete;
    callers must not interpret its provisional parity as an ANF.

    EXAMPLES::

        >>> from claasp.drivers.solvers import GurobiSolutionPoolResult, MILPStatus
        >>> from claasp.primitives import Simon
        >>> from claasp.representations.constraints.milp import BooleanMonomialGraphMILPModel
        >>> graph = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=1), 0, "plaintext")
        >>> assignment = {variable.name: 0.0 for variable in graph.milp_model().variables}
        >>> assignment[graph._wire("plaintext", 0)] = 1.0
        >>> pool = GurobiSolutionPoolResult(MILPStatus.OPTIMAL, (assignment,), 1.0, 0.0, True)
        >>> project_optimal_pool_monomial_parity(graph, pool).odd_input_monomials
        (('plaintext[0]',),)
    """

    from claasp.drivers.solvers import GurobiSolutionPoolResult, MILPStatus

    if not isinstance(pool, GurobiSolutionPoolResult):
        raise TypeError("pool must be a GurobiSolutionPoolResult")
    if pool.status is not MILPStatus.OPTIMAL:
        return SolutionPoolMonomialParityResult((), len(pool.assignments), False, pool.status.value)
    input_variables: list[tuple[str, str]] = []
    for input_name, port in compilation.primitive.graph.input_ports.items():
        width = compilation._width(port.array_type)
        input_variables.extend(
            (compilation._wire(input_name, bit), f"{input_name}[{bit}]") for bit in range(width)
        )
    parity: dict[tuple[str, ...], bool] = {}
    for assignment in pool.assignments:
        missing = tuple(name for name, _ in input_variables if name not in assignment)
        if missing:
            raise ValueError(f"solution-pool assignment omits input variable {missing[0]!r}")
        monomial = tuple(
            public_name
            for solver_name, public_name in input_variables
            if round(assignment[solver_name]) == 1
        )
        parity[monomial] = not parity.get(monomial, False)
    return SolutionPoolMonomialParityResult(
        tuple(sorted(monomial for monomial, odd in parity.items() if odd)),
        len(pool.assignments),
        pool.is_exhaustive,
        "exhaustive_pool" if pool.is_exhaustive else "pool_capacity",
    )


def enumerate_optimal_monomial_parity(compilation, solver, max_paths=10000):
    """Enumerate optimal paths until UNSAT and aggregate input masks mod two.

    ``compilation`` is a ``BooleanMonomialGraphMILPModel``. Re-solving with
    portable no-good constraints is slower than a native solution pool but
    makes completeness independent of proprietary solver behavior.


    EXAMPLES::

        >>> try:
        ...     enumerate_optimal_monomial_parity()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    from claasp.drivers.solvers import MILPStatus

    if not isinstance(max_paths, int) or isinstance(max_paths, bool) or max_paths <= 0:
        raise ValueError("max_paths must be a positive integer")
    base = compilation.milp_model()
    optimum = solver.solve(base)
    if optimum.status is not MILPStatus.OPTIMAL:
        return MonomialParityResult(None, (), 0, False, optimum.status.value)
    degree = int(round(optimum.objective_value))
    fixed_objective = LinearConstraint(
        base.objective, ConstraintSense.EQUAL, degree, "fix_optimal_degree"
    )
    constraints = list(base.constraints) + [fixed_objective]
    parity = {}
    paths = 0
    binary_names = tuple(variable.name for variable in base.variables)
    while paths < max_paths:
        query = MILPModel(base.variables, tuple(constraints), base.objective, base.objective_sense)
        result = solver.solve(query)
        if result.status is MILPStatus.INFEASIBLE:
            return MonomialParityResult(
                degree,
                tuple(sorted(mask for mask, odd in parity.items() if odd)),
                paths,
                True,
                "exhausted_unsat",
            )
        if result.status is not MILPStatus.OPTIMAL or result.assignment is None:
            return MonomialParityResult(
                degree,
                tuple(sorted(mask for mask, odd in parity.items() if odd)),
                paths,
                False,
                result.status.value,
            )
        assignment = result.assignment
        mask = 0
        width = compilation._width(
            compilation.primitive.graph.input_ports[compilation.variable_input].array_type
        )
        for bit in range(width):
            mask = (mask << 1) | int(
                round(assignment[compilation._wire(compilation.variable_input, bit)])
            )
        parity[mask] = not parity.get(mask, False)
        paths += 1
        ones = {name for name in binary_names if round(assignment[name]) == 1}
        terms = {name: (-1 if name in ones else 1) for name in binary_names}
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(terms),
                ConstraintSense.GREATER_EQUAL,
                1 - len(ones),
                f"exclude_path_{paths}",
            )
        )
    return MonomialParityResult(
        degree,
        tuple(sorted(mask for mask, odd in parity.items() if odd)),
        paths,
        False,
        "path_limit",
    )
