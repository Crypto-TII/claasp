"""Automatic searches over declared impossible and differential-linear models."""

from dataclasses import dataclass, replace
from fractions import Fraction

from claasp.drivers.solvers import KissatSolver, SatStatus


@dataclass(frozen=True, slots=True)
class ImpossibleCandidate:
    """A checked contradiction at one internal round boundary.

    EXAMPLES::

        >>> ImpossibleCandidate(1, None, "bitwise").middle_round
        1
    """

    middle_round: int
    trail: object
    representation: str


@dataclass(frozen=True, slots=True)
class ImpossibleSearchResult:
    """Candidates and explicit exhaustion status for the selected split search.

    EXAMPLES::

        >>> ImpossibleSearchResult((), (), True, "exhausted UNSAT").found
        False
    """

    candidates: tuple[ImpossibleCandidate, ...]
    attempted_rounds: tuple[int, ...]
    complete: bool
    termination: str

    @property
    def found(self) -> bool:
        """Return whether at least one checked model contradiction was found."""
        return bool(self.candidates)

    def require_complete(self) -> "ImpossibleSearchResult":
        """Reject a bounded enumeration before claiming full exhaustion."""
        if not self.complete:
            raise RuntimeError("impossible search is incomplete: " + self.termination)
        return self

    def to_terminal(self, *, file=None):
        """Print candidate splits and the enumeration status."""
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        table = Table(
            (TableColumn("split", "Middle round"), TableColumn("model", "Representation")),
            tuple(TableRow.of(item.middle_round, item.representation) for item in self.candidates),
        )
        print(render_terminal_table(table), file=file)
        print(f"{len(self.candidates)} candidate(s); {self.termination}", file=file)


def search_impossible_differentials(
    primitive,
    *,
    middle_round=None,
    split_order=None,
    input_pattern=None,
    output_pattern=None,
    active_input="plaintext",
    zero_difference_inputs=None,
    representation="bitwise",
    solver=None,
    limit=1,
) -> ImpossibleSearchResult:
    """Search all internal splits or a selected split, retaining checked witnesses.

    A finite limit is not an exhaustion certificate. Wordwise candidates carry
    the existing model's abstract interpretation rather than a new concrete
    probability claim. Unsupported operations fail explicitly.
    Requires Kissat; these examples run in its integration job. A one-candidate
    limit finds a checked contradiction but does not exhaust the search.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> result = ToySpeck(3).analysis.search_impossible_differentials(limit=1)  # doctest: +SKIP
        >>> result.found, result.complete  # doctest: +SKIP
        (True, False)
        >>> result.candidates[0].trail.boundary.is_impossible  # doctest: +SKIP
        True
    """
    from claasp.representations.constraints.sat import (
        WordImpossibleSATModel,
        WordwiseImpossibleSATModel,
    )

    if type(limit) is not int or limit <= 0:
        raise ValueError("limit must be a positive integer")
    available = tuple(range(1, len(primitive.graph.rounds)))
    if middle_round is not None and split_order is not None:
        raise ValueError("choose middle_round or split_order")
    splits = (
        ((middle_round,) if middle_round is not None else available)
        if split_order is None
        else tuple(split_order)
    )
    if len(set(splits)) != len(splits) or any(
        type(value) is not int or value not in available for value in splits
    ):
        raise ValueError("splits must be distinct internal round numbers")
    if representation not in {"bitwise", "wordwise"}:
        raise ValueError("representation must be bitwise or wordwise")
    zeros = (
        tuple(name for name in primitive.graph.input_arrays if name != active_input)
        if zero_difference_inputs is None
        else tuple(zero_difference_inputs)
    )
    solver = KissatSolver() if solver is None else solver
    candidates: list[ImpossibleCandidate] = []
    attempted: list[int] = []
    for split in splits:
        attempted.append(split)
        options = dict(active_input=active_input, zero_difference_inputs=zeros)
        model: WordImpossibleSATModel | WordwiseImpossibleSATModel
        if representation == "bitwise":
            model = WordImpossibleSATModel(
                primitive,
                split,
                input_pattern=input_pattern,
                output_pattern=output_pattern,
                **options,
            )
        else:
            model = WordwiseImpossibleSATModel(
                primitive,
                split,
                input_differences=input_pattern,
                output_differences=output_pattern,
                **options,
            )
        formula = model.cnf_formula()
        blocks: list[tuple[int, ...]] = []
        # Block external pattern pairs, not irrelevant auxiliary assignments.
        if representation == "bitwise":
            names = tuple(
                model._forward_map[name]
                for pair in model.forward_model._unit_arrays[active_input]
                for name in pair
            ) + tuple(
                model._backward_map[name]
                for pair in model.backward_model._unit_arrays["output"]
                for name in pair
            )
        else:
            names = tuple(
                model._forward_map[name]
                for word in model.forward_model._unit_arrays[active_input]
                for group in word
                for name in group
            ) + tuple(
                model._backward_map[name]
                for word in model.backward_model._unit_arrays["output"]
                for group in word
                for name in group
            )
        indices = {name: index for index, name in enumerate(formula.variables, 1)}
        while True:
            query = replace(
                formula,
                clauses=formula.clauses + tuple(blocks),
                provenance=formula.provenance + ("external_pattern_block",) * len(blocks),
            )
            run = solver.solve(query)
            if run.status is SatStatus.UNSATISFIABLE:
                break
            if run.status is not SatStatus.SATISFIABLE:
                return ImpossibleSearchResult(
                    tuple(candidates), tuple(attempted), False, run.status.value
                )
            if run.assignment is None or not query.is_satisfied(run.assignment):
                raise RuntimeError("solver returned an invalid impossible-search witness")
            if len(candidates) == limit:
                return ImpossibleSearchResult(
                    tuple(candidates), tuple(attempted), False, "candidate limit"
                )
            trail = model.decode_trail(run.assignment)
            candidates.append(ImpossibleCandidate(split, trail, representation))
            blocks.append(
                tuple(-indices[name] if run.assignment[name] else indices[name] for name in names)
            )
            # A one-candidate query is a search, not an exhaustive enumeration.
            if len(candidates) == limit:
                return ImpossibleSearchResult(
                    tuple(candidates), tuple(attempted), False, "candidate limit"
                )
    return ImpossibleSearchResult(tuple(candidates), tuple(attempted), True, "exhausted UNSAT")


@dataclass(frozen=True, slots=True)
class DifferentialLinearSearchResult:
    """Exact optimum of a declared characteristic score, not measured correlation.

    score = differential component probability * linear component correlation².
    A deterministic-truncated middle provides support constraints, not a
    probability estimate. Optimality is relative to these constraints.

    EXAMPLES::

        >>> DifferentialLinearSearchResult(None, None, None, (), True).found
        False
    """

    trail: object | None
    partition: tuple[int, int, int] | None
    score: Fraction | None
    attempted_partitions: tuple[tuple[int, int, int], ...]
    complete: bool

    @property
    def found(self) -> bool:
        """Return whether a checked composed characteristic was found."""
        return self.trail is not None

    def require_complete(self) -> "DifferentialLinearSearchResult":
        """Reject an unfinished search before claiming model optimality."""
        if not self.complete:
            raise RuntimeError("differential-linear optimization is incomplete")
        return self

    def to_terminal(self, *, file=None):
        """Print the selected partition and exact model score."""
        print("Differential-linear characteristic search", file=file)
        print(f"partition: {self.partition}", file=file)
        print(f"component-product score: {self.score}", file=file)
        print(f"model optimization complete: {self.complete}", file=file)


def _objective_formula(model):
    from claasp.representations.constraints.sat import CNFFormula
    from claasp.representations.constraints.smt._probability_encoding import (
        _encode_probability_product,
    )

    formula = model.cnf_formula()
    variables, clauses, provenance = (
        list(formula.variables),
        list(formula.clauses),
        list(formula.provenance),
    )
    indices = {name: index for index, name in enumerate(variables, 1)}

    def allocate(name):
        if name not in indices:
            variables.append(name)
            indices[name] = len(variables)
        return name

    def add(clause, label):
        clauses.append(tuple(clause))
        provenance.append(label)

    factors, weights = [], []
    for namespace, local, copies in (
        ("differential", model._prefix._shared, 1),
        ("linear", model._linear._shared, 2),
    ):
        mapping = model._maps[namespace]
        if local._probability_bits:
            bits = tuple(
                bit
                if isinstance(bit, bool)
                else indices[mapping[local._formula.variables[abs(bit) - 1]]]
                * (1 if bit > 0 else -1)
                for bit in local._probability_bits
            )
            factors.extend([(local._probability_denominator.bit_length() - 1, bits)] * copies)
        else:
            weights.extend([mapping[name] for name in local._weight_names] * copies)
    bits, denominator = _encode_probability_product(factors, weights, allocate, indices, add)
    return (
        CNFFormula(tuple(variables), tuple(clauses), tuple(provenance), formula.constraint_models),
        bits,
        denominator,
    )


def find_optimal_differential_linear_trail(
    primitive,
    *,
    prefix_rounds=None,
    middle_rounds=None,
    input_difference=None,
    output_mask=None,
    solver=None,
) -> DifferentialLinearSearchResult:
    """Optimize all valid partitions using exact integer probability products.

    Specify prefix_rounds/middle_rounds to restrict the declared model search.
    Default execution uses the optional Kissat executable. No sampled or
    whole-primitive correlation is inferred from the characteristic score.

    Requires Kissat; these examples run in its integration job. The score is
    P_D * C_L**2 for this characteristic model, not a measured whole-primitive
    correlation. require_complete() is needed before claiming model optimality.

    EXAMPLES::

        >>> from claasp.primitives import ToySpeck
        >>> result = ToySpeck(3).analysis.find_optimal_differential_linear_trail().require_complete()  # doctest: +SKIP
        >>> result.partition, result.score  # doctest: +SKIP
        ((1, 1, 1), Fraction(1, 1))
    """
    from claasp.representations.constraints.sat import WordDeterministicDifferentialLinearSATModel
    from claasp.representations.constraints.smt._probability_encoding import (
        _comparison_clauses,
        _probability,
    )

    count = len(primitive.graph.rounds)
    for value in (prefix_rounds, middle_rounds):
        if value is not None and (type(value) is not int or value <= 0):
            raise ValueError("partition lengths must be positive integers")
    partitions = tuple(
        (prefix, middle, count - prefix - middle)
        for prefix in range(1, count - 1)
        for middle in range(1, count - prefix)
        if (prefix_rounds is None or prefix == prefix_rounds)
        and (middle_rounds is None or middle == middle_rounds)
    )
    if not partitions:
        raise ValueError("the selected partition needs nonempty prefix, middle and suffix")
    solver = KissatSolver() if solver is None else solver
    best, best_partition, best_score, attempted = None, None, None, []
    for prefix, middle, suffix in partitions:
        attempted.append((prefix, middle, suffix))
        model = WordDeterministicDifferentialLinearSATModel(
            primitive,
            prefix_rounds=prefix,
            middle_rounds=middle,
            differential_maximum_weight=None,
            linear_maximum_weight=None,
            input_difference=input_difference,
            output_mask=output_mask,
        )
        formula, bits, denominator = _objective_formula(model)
        lower, upper, witness = 0, denominator, None
        while lower < upper:
            threshold = (lower + upper + 1) // 2
            extra: list[tuple[int, ...]] = []
            for clause in _comparison_clauses(bits, threshold):
                extra.extend((clause,) if clause else ((1,), (-1,)))
            query = replace(
                formula,
                clauses=formula.clauses + tuple(extra),
                provenance=formula.provenance + ("composed_probability_bound",) * len(extra),
            )
            run = solver.solve(query)
            if run.status is SatStatus.UNSATISFIABLE:
                upper = threshold - 1
                continue
            if run.status is not SatStatus.SATISFIABLE:
                return DifferentialLinearSearchResult(
                    best, best_partition, best_score, tuple(attempted), False
                )
            if run.assignment is None or not query.is_satisfied(run.assignment):
                raise RuntimeError("invalid composed optimization witness")
            trail = model.decode_trail(run.assignment)
            score = _probability(trail.differential.steps) * _probability(trail.linear.steps) ** 2
            product = score * denominator
            encoded = sum(
                (
                    int(bit)
                    if isinstance(bit, bool)
                    else int(bool(run.assignment[formula.variables[abs(bit) - 1]]) == (bit > 0))
                )
                << index
                for index, bit in enumerate(bits)
            )
            if (
                product.denominator != 1
                or encoded != product.numerator
                or not threshold <= encoded <= upper
            ):
                raise RuntimeError("composed objective disagrees with exact transition products")
            lower, witness = encoded, trail
        if witness is not None:
            score = Fraction(lower, denominator)
            if best_score is None or score > best_score:
                best, best_partition, best_score = witness, (prefix, middle, suffix), score
    return DifferentialLinearSearchResult(best, best_partition, best_score, tuple(attempted), True)
