"""Exact ANFs, superpolys and completeness-qualified division-property degrees."""

from dataclasses import dataclass

from claasp.representations.constraints.polynomial import BooleanPolynomial


@dataclass(frozen=True, slots=True)
class ANFResult:
    """Exact selected output polynomials, including parity cancellation.

    A zero polynomial has degree -1. Variables use p/k/s prefixes for
    plaintext/key/state; other inputs use their full name followed by '_'.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> Simon(number_of_rounds=1).analysis.anf(output_bit=0).degrees
        (2,)
    """

    polynomials: tuple[BooleanPolynomial, ...]
    variables: tuple[str, ...]
    complete: bool = True

    @property
    def degrees(self) -> tuple[int, ...]:
        """Return the exact degree of each retained polynomial."""
        return tuple(poly.degree for poly in self.polynomials)

    def degree_in(self, variables) -> tuple[int, ...]:
        """Count only selected variables, keeping other variables symbolic."""
        selected = self._variables(variables)
        return tuple(
            max((len(set(term.variables) & selected) for term in poly.monomials), default=-1)
            for poly in self.polynomials
        )

    def _variables(self, variables):
        values = tuple(variables)
        if len(set(values)) != len(values) or not set(values) <= set(self.variables):
            raise ValueError("variables must be distinct registered input-variable names")
        return set(values)

    def coefficient(self, variables=()) -> tuple[int, ...]:
        """Return coefficients of one exact monomial, not a reachability flag."""
        selected = self._variables(variables)
        return tuple(
            int(any(set(term.variables) == selected for term in poly.monomials))
            for poly in self.polynomials
        )

    def superpoly(self, cube, *, fixed_variables=None) -> "ANFResult":
        """Extract the cube coefficient while retaining other symbolic variables."""
        selected = self._variables(cube)
        fixed = dict(fixed_variables or {})
        if set(fixed) - (set(self.variables) - selected):
            raise ValueError("fixed variables must be registered variables outside the cube")
        polynomials = tuple(
            poly.cube_coefficient(selected).substitute(fixed) for poly in self.polynomials
        )
        return ANFResult(
            polynomials,
            tuple(name for name in self.variables if name not in selected and name not in fixed),
        )

    def to_terminal(self, *, details=False, file=None):
        """Print degrees and term counts, optionally including the full ANFs."""
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        table = Table(
            (
                TableColumn("bit", "Selected bit"),
                TableColumn("degree", "Degree"),
                TableColumn("terms", "Terms"),
            ),
            tuple(
                TableRow.of(index, poly.degree, len(poly.monomials))
                for index, poly in enumerate(self.polynomials)
            ),
        )
        print(render_terminal_table(table), file=file)
        if details:
            for index, polynomial in enumerate(self.polynomials):
                text = (
                    " + ".join("*".join(term.variables) or "1" for term in polynomial.monomials)
                    or "0"
                )
                print(f"{index}: {text}", file=file)


def analyze_anf(
    primitive,
    *,
    output_bit=None,
    component=None,
    fixed_inputs=None,
    maximum_terms=100_000,
    maximum_operations=1_000_000,
) -> ANFResult:
    """Expand selected outputs or a named intermediate component exactly.

    EXAMPLES::

        >>> from claasp.primitives import Simon
        >>> analyze_anf(Simon(number_of_rounds=1), output_bit=0).degrees
        (2,)
    """
    from claasp.representations.execution import BooleanSymbolicEvaluator

    result = BooleanSymbolicEvaluator().evaluate(
        primitive,
        fixed_inputs=fixed_inputs,
        maximum_terms=maximum_terms,
        maximum_operations=maximum_operations,
    )
    if component is None:
        polynomials = result.output_anfs
    else:
        if component in primitive.graph.input_arrays or component not in result.values:
            raise ValueError("component must name a graph component")
        polynomials = tuple(
            bit
            for unit in result.values[component]
            for bit in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
        )
    if output_bit is not None:
        if type(output_bit) is not int or not 0 <= output_bit < len(polynomials):
            raise ValueError("output_bit must select a retained output bit")
        polynomials = (polynomials[output_bit],)
    variables = tuple(
        sorted(
            {
                name
                for input_name in primitive.graph.input_arrays
                for unit in result.values[input_name]
                for poly in ((unit,) if isinstance(unit, BooleanPolynomial) else unit)
                for term in poly.monomials
                for name in term.variables
            }
        )
    )
    return ANFResult(polynomials, variables)


@dataclass(frozen=True, slots=True)
class AlgebraicDegreeResult:
    """A reachable upper bound and an optional parity-proved exact degree.

    EXAMPLES::

        >>> AlgebraicDegreeResult(3, None, False, 10, "path limit").complete
        False
    """

    upper_bound: int | None
    exact_degree: int | None
    complete: bool
    enumerated_paths: int
    termination: str

    def require_complete(self) -> "AlgebraicDegreeResult":
        """Reject provisional parity or unfinished optimization."""
        if not self.complete:
            raise RuntimeError("exact algebraic degree is incomplete: " + self.termination)
        return self


def find_algebraic_degree(
    primitive,
    *,
    output_bit=0,
    variable_input="plaintext",
    solver=None,
    exact=False,
    maximum_paths=10_000,
    variable_positions=None,
) -> AlgebraicDegreeResult:
    """Optimize a division-property bound, optionally cancelling complete paths.

    Exact mode enumerates each candidate degree to UNSAT and projects complete
    input monomials before taking parity. If the leading terms cancel, it
    descends to the next reachable degree. Other inputs remain symbolic.

    EXAMPLES::

        >>> callable(find_algebraic_degree)
        True
    """
    from claasp.drivers.solvers import GLPKSolver, MILPStatus
    from claasp.representations.constraints.milp import (
        BooleanMonomialGraphMILPModel,
        ConstraintSense,
        LinearConstraint,
        LinearExpression,
        MILPModel,
    )

    if type(maximum_paths) is not int or maximum_paths <= 0:
        raise ValueError("maximum_paths must be a positive integer")
    solver = GLPKSolver() if solver is None else solver
    from claasp.representations.constraints.milp._boolean_circuit import _boolean_circuit

    compilation = BooleanMonomialGraphMILPModel(
        _boolean_circuit(primitive), output_bit, variable_input
    )
    base = compilation.milp_model()
    if variable_positions is not None:
        positions = tuple(variable_positions)
        width = compilation._width(primitive.graph.input_arrays[variable_input].array_type)
        if len(set(positions)) != len(positions) or any(
            type(bit) is not int or not 0 <= bit < width for bit in positions
        ):
            raise ValueError("variable_positions must be distinct input bit positions")
        base = MILPModel(
            base.variables,
            base.constraints,
            LinearExpression.from_terms(
                {compilation._wire(variable_input, bit): 1 for bit in positions}
            ),
            base.objective_sense,
            base.constraint_models,
        )
    constraints = list(base.constraints)
    paths = 0
    upper = None
    while True:
        query = MILPModel(
            base.variables,
            tuple(constraints),
            base.objective,
            base.objective_sense,
            base.constraint_models,
        )
        optimum = solver.solve(query)
        if optimum.status is MILPStatus.INFEASIBLE:
            return AlgebraicDegreeResult(-1, -1 if exact else None, exact, paths, "exhausted UNSAT")
        if (
            optimum.status is not MILPStatus.OPTIMAL
            or optimum.assignment is None
            or optimum.objective_value is None
        ):
            return AlgebraicDegreeResult(upper, None, False, paths, optimum.status.value)
        if not query.is_feasible(optimum.assignment):
            raise ValueError("invalid monomial optimization witness")
        degree = int(round(optimum.objective_value))
        if (
            abs(optimum.objective_value - degree) > 1e-6
            or abs(query.objective.evaluate(optimum.assignment) - degree) > 1e-6
        ):
            raise ValueError("monomial objective does not match its witness")
        upper = degree
        if not exact:
            return AlgebraicDegreeResult(degree, None, False, paths, "reachable upper bound")
        fixed = LinearConstraint(base.objective, ConstraintSense.EQUAL, degree, "candidate_degree")
        local = list(constraints) + [fixed]
        parity: set[tuple[tuple[str, int], ...]] = set()
        while True:
            bounded = MILPModel(
                base.variables,
                tuple(local),
                base.objective,
                base.objective_sense,
                base.constraint_models,
            )
            solved = solver.solve(bounded)
            if solved.status is MILPStatus.INFEASIBLE:
                break
            if solved.status is not MILPStatus.OPTIMAL or solved.assignment is None:
                return AlgebraicDegreeResult(upper, None, False, paths, solved.status.value)
            if not bounded.is_feasible(solved.assignment):
                raise ValueError("invalid monomial enumeration witness")
            if paths == maximum_paths:
                return AlgebraicDegreeResult(upper, None, False, paths, "path limit")
            assignment = solved.assignment
            monomial = tuple(
                (name, bit)
                for name, array in primitive.graph.input_arrays.items()
                for bit in range(compilation._width(array.array_type))
                if round(assignment[compilation._wire(name, bit)])
            )
            if monomial in parity:
                parity.remove(monomial)
            else:
                parity.add(monomial)
            paths += 1
            ones = {
                variable.name for variable in base.variables if round(assignment[variable.name])
            }
            no_good = LinearConstraint(
                LinearExpression.from_terms(
                    {
                        variable.name: -1 if variable.name in ones else 1
                        for variable in base.variables
                    }
                ),
                ConstraintSense.GREATER_EQUAL,
                1 - len(ones),
                f"exclude_path_{paths}",
            )
            local.append(no_good)
        if parity:
            return AlgebraicDegreeResult(
                degree, degree, True, paths, "complete leading-degree parity"
            )
        constraints.append(
            LinearConstraint(
                base.objective, ConstraintSense.LESS_EQUAL, degree - 1, f"descend_{degree}"
            )
        )


@dataclass(frozen=True, slots=True)
class SuperpolyAnalysisResult:
    """A solver-recovered cube coefficient, available only after path exhaustion.

    Variables outside the selected cube remain symbolic unless the caller
    explicitly requests zero_outside_cube. Truncated path parity is never exposed as an ANF.

    EXAMPLES::

        >>> SuperpolyAnalysisResult(None, False, 10, "path limit").complete
        False
    """

    polynomial: BooleanPolynomial | None
    complete: bool
    enumerated_paths: int
    termination: str

    def require_complete(self) -> "SuperpolyAnalysisResult":
        """Reject an unfinished superpoly computation."""
        if not self.complete:
            raise RuntimeError("superpoly is incomplete: " + self.termination)
        return self

    def to_terminal(self, *, file=None):
        """Print the exact recovered polynomial or the incomplete status."""
        if self.polynomial is None:
            print("Superpoly incomplete: " + self.termination, file=file)
        else:
            ANFResult(
                (self.polynomial,),
                tuple(
                    sorted({name for term in self.polynomial.monomials for name in term.variables})
                ),
            ).to_terminal(details=True, file=file)


def recover_superpoly(
    primitive,
    cube_positions,
    *,
    cube_input="plaintext",
    output_bit=0,
    solver=None,
    maximum_paths=10_000,
    zero_outside_cube=False,
) -> SuperpolyAnalysisResult:
    """Recover a cube coefficient by complete MILP monomial-path parity.

    Unlike exhaustive cube evaluation, the work is bounded by the number of
    model paths rather than 2**(cube width + symbolic width). Worst-case cost
    remains exponential. Unsupported operations and incomplete searches are
    explicit, and no incomplete polynomial is returned.

    EXAMPLES::

        >>> callable(recover_superpoly)
        True
    """
    from claasp.drivers.solvers import GLPKSolver, MILPStatus
    from claasp.representations.constraints.milp import (
        BooleanMonomialGraphMILPModel,
        ConstraintSense,
        LinearConstraint,
        LinearExpression,
        MILPModel,
    )
    from claasp.representations.constraints.polynomial import BooleanMonomial

    if type(maximum_paths) is not int or maximum_paths <= 0:
        raise ValueError("maximum_paths must be a positive integer")
    cube = tuple(cube_positions)
    if not cube:
        raise ValueError("cube_positions must not be empty")
    # Validate cube positions separately even when other public variables stay symbolic.
    from claasp.representations.constraints.milp._boolean_circuit import _boolean_circuit

    circuit = _boolean_circuit(primitive)
    validation = BooleanMonomialGraphMILPModel(circuit, output_bit, cube_input, cube)
    compilation = (
        validation
        if zero_outside_cube
        else BooleanMonomialGraphMILPModel(circuit, output_bit, cube_input)
    )
    base = compilation.milp_model()
    constraints = list(base.constraints)
    constraints.extend(
        LinearConstraint(
            LinearExpression.from_terms({compilation._wire(cube_input, bit): 1}),
            ConstraintSense.EQUAL,
            1,
            f"cube_{bit}",
        )
        for bit in cube
    )
    solver = GLPKSolver() if solver is None else solver
    parity: set[tuple[str, ...]] = set()
    paths = 0
    while True:
        query = MILPModel(
            base.variables,
            tuple(constraints),
            base.objective,
            base.objective_sense,
            base.constraint_models,
        )
        run = solver.solve(query)
        if run.status is MILPStatus.INFEASIBLE:
            polynomial = BooleanPolynomial(BooleanMonomial.from_variables(term) for term in parity)
            return SuperpolyAnalysisResult(polynomial, True, paths, "exhausted UNSAT")
        if run.status is not MILPStatus.OPTIMAL or run.assignment is None:
            return SuperpolyAnalysisResult(None, False, paths, run.status.value)
        if not query.is_feasible(run.assignment):
            raise ValueError("invalid superpoly path witness")
        if paths == maximum_paths:
            return SuperpolyAnalysisResult(None, False, paths, "path limit")
        assignment = run.assignment
        monomial: list[str] = []
        for name, array in primitive.graph.input_arrays.items():
            prefix = {"plaintext": "p", "key": "k", "state": "s", "iv": "i"}.get(name, name + "_")
            monomial.extend(
                f"{prefix}{bit}"
                for bit in range(compilation._width(array.array_type))
                if round(assignment[compilation._wire(name, bit)])
                and not (name == cube_input and bit in cube)
            )
        term = tuple(sorted(monomial))
        if term in parity:
            parity.remove(term)
        else:
            parity.add(term)
        paths += 1
        ones = {variable.name for variable in base.variables if round(assignment[variable.name])}
        constraints.append(
            LinearConstraint(
                LinearExpression.from_terms(
                    {
                        variable.name: -1 if variable.name in ones else 1
                        for variable in base.variables
                    }
                ),
                ConstraintSense.GREATER_EQUAL,
                1 - len(ones),
                f"exclude_path_{paths}",
            )
        )
