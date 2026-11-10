"""Signed quasidifferential trails and fixed-key differential probabilities.

This analysis retains the distinction between a key-averaged characteristic
and the signed trails whose complete sum recovers a fixed-key probability.
Resource-limited enumeration is explicitly incomplete, never a probability
proof. Solver witnesses and objective values are independently checked.
"""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from fractions import Fraction
from math import log2
from types import MappingProxyType

from claasp._result_presentation import PlotMixin as _PlotMixin
from claasp._result_presentation import TerminalMixin as _TerminalMixin
from claasp.drivers.solvers import SatStatus, Z3Solver
from claasp.representations.constraints.sat.quasidifferential import (
    QuasidifferentialSATModel,
    _packed,
)
from claasp.semantics.cryptanalysis.quasidifferential import QuasidifferentialTransition


@dataclass(frozen=True, slots=True)
class QuasidifferentialTrail(_PlotMixin):
    """One independently checked signed trail, including key-mask information.

    EXAMPLES::

        >>> result = QuasidifferentialTrail('toy', {}, {}, 1, 0, (), Fraction(-1, 2))
        >>> (result.coefficient, result.weight, result.is_optimal)
        (Fraction(-1, 2), 1.0, False)

    Plotting
    ~~~~~~~~

    Local signed factors and their cumulative product retain negative signs; they are not probabilities.

    EXAMPLES::

        >>> from fractions import Fraction
        >>> result = QuasidifferentialTrail('example', {}, {}, 1, 0, (), Fraction(-1, 2))
        >>> artifact = result.plot(show=False)
        >>> artifact.kind
        'search_evidence'
        >>> import matplotlib.pyplot as plt
        >>> plt.close(artifact.figure)
    """

    primitive: str
    input_differences: Mapping[str, int]
    input_masks: Mapping[str, int]
    output_difference: int
    output_mask: int
    steps: tuple[tuple[str, QuasidifferentialTransition], ...]
    coefficient: Fraction
    is_optimal: bool = False

    @property
    def weight(self):
        """Return -log2 of the magnitude for display; optimization stays exact."""
        return -log2(abs(self.coefficient))

    def to_terminal(self, *, details=False, file=None):
        """Print a compact signed-trail report, optionally with every local factor.

        EXAMPLES::

            >>> from io import StringIO
            >>> output = StringIO()
            >>> QuasidifferentialTrail('toy', {}, {}, 1, 0, (), Fraction(-1, 2)).to_terminal(file=output)
            >>> '-1/2' in output.getvalue()
            True
        """
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = [
            ("primitive", self.primitive),
            ("signed coefficient", str(self.coefficient)),
            ("weight", f"{self.weight:g}"),
            ("proved optimal", self.is_optimal),
            ("output difference", hex(self.output_difference)),
            ("output mask", hex(self.output_mask)),
        ]
        print(
            render_terminal_table(
                Table(
                    (TableColumn("field", "Field"), TableColumn("value", "Value")),
                    tuple(TableRow.of(*row) for row in rows),
                )
            ),
            file=file,
        )
        if details:
            columns = (
                "Component",
                "Input differences",
                "Output difference",
                "Input masks",
                "Output mask",
                "Coefficient",
            )
            detail_rows = tuple(
                TableRow.of(
                    name,
                    ",".join(hex(value) for value in step.input_differences),
                    hex(step.output_difference),
                    ",".join(hex(value) for value in step.input_masks),
                    hex(step.output_mask),
                    str(step.coefficient),
                )
                for name, step in self.steps
            )
            print(
                render_terminal_table(
                    Table(
                        tuple(TableColumn(str(i), name) for i, name in enumerate(columns)),
                        detail_rows,
                    )
                ),
                file=file,
            )


@dataclass(frozen=True, slots=True)
class QuasidifferentialEnumeration(_TerminalMixin, _PlotMixin):
    """A trail set with an explicit completeness verdict.

    EXAMPLES::

        >>> QuasidifferentialEnumeration((), True).require_complete().trails
        ()

    Terminal reporting
    ~~~~~~~~~~~~~~~~~~

    Signed coefficients are displayed per retained trail with explicit completeness.

    EXAMPLES::

        >>> result = QuasidifferentialEnumeration((), False, 'trail limit')
        >>> from io import StringIO
        >>> output = StringIO()
        >>> result.to_terminal(file=output)
        >>> bool(output.getvalue().strip())
        True

    Plotting
    ~~~~~~~~

    Signed coefficients are displayed per retained trail with explicit completeness.

    EXAMPLES::

        >>> result = QuasidifferentialEnumeration((), False, 'trail limit')
        >>> artifact = result.plot(show=False)
        >>> artifact.kind
        'search_evidence'
        >>> import matplotlib.pyplot as plt
        >>> plt.close(artifact.figure)
    """

    trails: tuple[QuasidifferentialTrail, ...]
    complete: bool
    diagnostic: str | None = None

    def require_complete(self):
        """Reject a truncated set before using it as a complete trail sum."""
        if not self.complete:
            raise RuntimeError(self.diagnostic or "incomplete quasidifferential enumeration")
        return self


@dataclass(frozen=True, slots=True)
class FixedKeyProbabilityResult(_PlotMixin):
    """A signed partial sum, with exact probability exposed only on completion.

    EXAMPLES::

        >>> result = FixedKeyProbabilityResult(Fraction(1, 2), True, 2)
        >>> result.probability
        Fraction(1, 2)

    Plotting
    ~~~~~~~~

    Signed partial sums may be negative; only complete enumeration can establish a probability.

    EXAMPLES::

        >>> from fractions import Fraction
        >>> result = FixedKeyProbabilityResult(Fraction(-1, 4), False, 2, 'trail limit')
        >>> artifact = result.plot(show=False)
        >>> artifact.kind
        'search_evidence'
        >>> import matplotlib.pyplot as plt
        >>> plt.close(artifact.figure)
    """

    signed_sum: Fraction
    complete: bool
    trail_count: int
    diagnostic: str | None = None
    key_averaged: bool = False
    trails: tuple[QuasidifferentialTrail, ...] = ()
    event: str = "differential"
    difference_constraints: tuple[tuple[str, int | str | None], ...] = ()

    @property
    def probability(self):
        """Return the exact probability only after exhaustive, unbounded enumeration."""
        self.require_complete()
        if not 0 <= self.signed_sum <= 1:
            raise RuntimeError("complete signed sum is not a probability")
        return self.signed_sum

    def require_complete(self):
        """Prevent a truncated or weight-limited estimate from becoming a proof."""
        if not self.complete:
            raise RuntimeError(self.diagnostic or "fixed-key probability sum is incomplete")
        return self

    def to_terminal(self, *, file=None):
        """Print the signed sum together with its completeness and trail count.

        EXAMPLES::

            >>> from io import StringIO
            >>> output = StringIO()
            >>> FixedKeyProbabilityResult(Fraction(1, 2), False, 1, 'trail limit').to_terminal(file=output)
            >>> 'False' in output.getvalue() and 'trail limit' in output.getvalue()
            True
        """
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        rows = (
            TableRow.of("signed sum", str(self.signed_sum)),
            TableRow.of("event", self.event),
            TableRow.of("complete", self.complete),
            TableRow.of("trails", self.trail_count),
            TableRow.of("key averaged", self.key_averaged),
            TableRow.of("diagnostic", self.diagnostic or "-"),
        )
        print(
            render_terminal_table(
                Table((TableColumn("field", "Field"), TableColumn("value", "Value")), rows)
            ),
            file=file,
        )


class _IncompleteSolve(RuntimeError):
    pass


def _solve(model, formula, solver):
    solved = solver.solve(formula)
    if solved.status is SatStatus.UNSATISFIABLE:
        return None
    if solved.status is not SatStatus.SATISFIABLE:
        raise _IncompleteSolve("solver did not complete the quasidifferential query")
    assignment = solved.assignment
    if assignment is None or not formula.is_satisfied(assignment):
        raise RuntimeError("solver returned an invalid quasidifferential witness")
    steps, coefficient = model.decode(assignment)
    variables = model.base_formula.variables
    differences = {
        name: _packed(model.differences[name], assignment, variables)
        for name in model.primitive.graph.input_arrays
    }
    masks = {
        name: _packed(model.masks[name], assignment, variables)
        for name in model.primitive.graph.input_arrays
    }
    trail = QuasidifferentialTrail(
        model.primitive.family_name,
        MappingProxyType(differences),
        MappingProxyType(masks),
        _packed(model.output_differences, assignment, variables),
        _packed(model.output_masks, assignment, variables),
        steps,
        coefficient,
    )
    return trail, assignment


class QuasidifferentialAnalysis:
    """Search signed QDT trails and sum them for a specified fixed key.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> analysis = QuasidifferentialAnalysis(Speck(number_of_rounds=1))
        >>> analysis.model().cnf_formula().variable_count > 0
        True
    """

    def __init__(self, primitive):
        self.primitive = primitive

    def model(self, **constraints):
        """Build the solver-independent Boolean model without running a solver.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> QuasidifferentialAnalysis(Speck(number_of_rounds=1)).model().weights != []
            True
        """
        return QuasidifferentialSATModel(self.primitive, **constraints)

    def find_one_trail(self, *, solver=None, **constraints):
        """Return one checked trail, or None after a proved infeasible query.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> analysis = QuasidifferentialAnalysis(Speck(number_of_rounds=1))
            >>> result = analysis.find_one_trail()  # doctest: +SKIP
            >>> result.coefficient != 0  # doctest: +SKIP
            True

        Executing the search requires ``z3`` or an explicitly supplied solver.
        """
        model = self.model(**constraints)
        found = _solve(model, model.cnf_formula(), Z3Solver() if solver is None else solver)
        return None if found is None else found[0]

    def find_lowest_weight_trail(self, *, solver=None, **constraints):
        """Prove an optimum using integer costs or exact dyadic products.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> analysis = QuasidifferentialAnalysis(Speck(number_of_rounds=1))
            >>> result = analysis.find_lowest_weight_trail()  # doctest: +SKIP
            >>> result.is_optimal  # doctest: +SKIP
            True
        """
        model = self.model(**constraints)
        selected = Z3Solver() if solver is None else solver
        found = _solve(model, model.cnf_formula(), selected)
        if found is None:
            raise ValueError("no quasidifferential trail satisfies the constraints")
        best, assignment = found
        if model.factors:
            denominator = model.probability_denominator
            assert denominator is not None
            lower = int(abs(best.coefficient) * denominator)
            upper = denominator
            while lower < upper:
                threshold = (lower + upper + 1) // 2
                found = _solve(model, model.cnf_formula(minimum_score=threshold), selected)
                if found is None:
                    upper = threshold - 1
                else:
                    best, assignment = found
                    lower = int(abs(best.coefficient) * denominator)
            if (
                lower < denominator
                and _solve(model, model.cnf_formula(minimum_score=lower + 1), selected) is not None
            ):
                raise RuntimeError("strict improvement was not proved infeasible")
        else:
            lower = 0
            upper = sum(bool(assignment[name]) for name in model.weights)
            while lower < upper:
                threshold = (lower + upper) // 2
                found = _solve(model, model.cnf_formula(maximum_cost=threshold), selected)
                if found is None:
                    lower = threshold + 1
                else:
                    best, assignment = found
                    upper = sum(bool(assignment[name]) for name in model.weights)
            if (
                lower
                and _solve(model, model.cnf_formula(maximum_cost=lower - 1), selected) is not None
            ):
                raise RuntimeError("strict improvement was not proved infeasible")
        return replace(best, is_optimal=True)

    def enumerate_trails(self, *, maximum_trails=10000, solver=None, **constraints):
        """Enumerate complete projected trails, with an explicit resource-limit result.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> analysis = QuasidifferentialAnalysis(Speck(number_of_rounds=1))
            >>> result = analysis.enumerate_trails(maximum_trails=1)  # doctest: +SKIP
            >>> len(result.trails) <= 1  # doctest: +SKIP
            True
        """
        if (
            not isinstance(maximum_trails, int)
            or isinstance(maximum_trails, bool)
            or maximum_trails < 1
        ):
            raise ValueError("maximum_trails must be positive")
        model = self.model(**constraints)
        selected = Z3Solver() if solver is None else solver
        formula = model.cnf_formula()
        trails: list[QuasidifferentialTrail] = []
        while True:
            try:
                found = _solve(model, formula, selected)
            except _IncompleteSolve as error:
                return QuasidifferentialEnumeration(tuple(trails), False, str(error))
            if found is None:
                return QuasidifferentialEnumeration(tuple(trails), True)
            if len(trails) == maximum_trails:
                return QuasidifferentialEnumeration(tuple(trails), False, "maximum_trails reached")
            trail, assignment = found
            trails.append(trail)
            blocking = tuple(
                -index if assignment[model.base_formula.variables[index - 1]] else index
                for index in model.projection
            )
            formula = replace(
                formula,
                clauses=formula.clauses + (blocking,),
                provenance=formula.provenance + ("projected_qdt_blocking",),
            )

    def estimate_fixed_key_probability(
        self,
        input_difference,
        output_difference,
        key=None,
        *,
        input_name="plaintext",
        maximum_trails=10000,
        solver=None,
        maximum_weight=None,
        minimum_weight=None,
        fixed_differences=None,
        maximum_table_entries=1 << 20,
    ):
        """Sum signed trails with the key-mask phase, retaining completeness.

        This averages over the public input values. All public differences
        except ``input_name`` are zero. The key may be a packed integer for
        one secret input, or a mapping for multiple secret inputs. With
        ``key=None`` the result is averaged over keys: nonzero key masks
        contribute zero. A weight cap makes the full-probability claim
        incomplete. Extra fixed differences select a characteristic event.

        EXAMPLES::

            >>> from claasp.primitives import Speck
            >>> analysis = QuasidifferentialAnalysis(Speck(number_of_rounds=1))
            >>> result = analysis.estimate_fixed_key_probability(1, 1, 0, maximum_trails=10)  # doctest: +SKIP
            >>> result.complete  # doctest: +SKIP
            True
        """
        secret = tuple(self.primitive.graph.secret_inputs)
        averaged = key is None
        if averaged:
            key = {}
        elif isinstance(key, int) and not isinstance(key, bool):
            if len(secret) != 1:
                raise ValueError("use a key mapping unless exactly one secret input exists")
            key = {secret[0]: key}
        else:
            key = dict(key)
        if not averaged and set(key) != set(secret):
            raise ValueError("key mapping must cover exactly the secret inputs")
        for name, value in key.items():
            width = self.primitive.graph.input_arrays[name].array_type.encoded_bit_size
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
                raise ValueError("key value does not fit its input")
        if input_name not in self.primitive.graph.input_arrays or input_name in secret:
            raise ValueError("input_name must select a public input")
        for value, width in (
            (
                input_difference,
                self.primitive.graph.input_arrays[input_name].array_type.encoded_bit_size,
            ),
            (output_difference, self.primitive.graph.output.array_type.encoded_bit_size),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << width:
                raise ValueError(
                    "probability estimation requires complete input/output differences"
                )
        differences = dict(fixed_differences or {})
        for name in self.primitive.graph.input_arrays:
            differences.setdefault(name, 0)
        if input_name in (fixed_differences or {}) and differences[input_name] != input_difference:
            raise ValueError("conflicting input difference")
        differences[input_name] = input_difference
        if any(differences[name] != 0 for name in secret):
            raise ValueError("fixed-key probability requires zero key differences")
        enumeration = self.enumerate_trails(
            maximum_trails=maximum_trails,
            solver=solver,
            fixed_differences=differences,
            output_difference=output_difference,
            maximum_weight=maximum_weight,
            minimum_weight=minimum_weight,
            maximum_table_entries=maximum_table_entries,
            nonzero_input=False,
        )
        total = Fraction(0)
        for trail in enumeration.trails:
            if averaged and any(trail.input_masks[name] for name in secret):
                continue
            parity = (
                sum((trail.input_masks[name] & value).bit_count() for name, value in key.items())
                & 1
            )
            total += (-1 if parity else 1) * trail.coefficient
        complete = enumeration.complete and maximum_weight is None and minimum_weight in (None, 0)
        diagnostic = enumeration.diagnostic
        if maximum_weight is not None or minimum_weight not in (None, 0):
            diagnostic = "weight-limited sum; not a complete fixed-key probability"
        result = FixedKeyProbabilityResult(
            total,
            complete,
            len(enumeration.trails),
            diagnostic,
            averaged,
            enumeration.trails,
            "constrained differential"
            if any(
                name not in self.primitive.graph.input_arrays for name in (fixed_differences or {})
            )
            else "differential",
            tuple(sorted(differences.items())),
        )
        if complete and not 0 <= total <= 1:
            raise RuntimeError("complete signed sum is not a probability")
        return result


__all__ = [
    "QuasidifferentialAnalysis",
    "QuasidifferentialTrail",
    "QuasidifferentialEnumeration",
    "FixedKeyProbabilityResult",
]
