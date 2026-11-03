"""User-facing Boolean equation-system inspection and bounded algebra runs."""

from dataclasses import dataclass
from math import isfinite
from subprocess import TimeoutExpired
from time import monotonic

from claasp.representations.constraints.polynomial import BooleanEquationSystem


@dataclass(frozen=True, slots=True)
class GroebnerResult:
    """A completed basis or an explicit timeout, never a partial proof.

    Basis entries use the system's variable names in a GF(2) polynomial ring
    and include Boolean field equations. They are not flattened Boolean ANFs.

    EXAMPLES::

        >>> GroebnerResult((), False, 1.0, "timeout").complete
        False
    """

    basis: tuple[str, ...]
    complete: bool
    runtime_seconds: float
    diagnostic: str | None = None

    def require_complete(self) -> "GroebnerResult":
        """Reject an unfinished Gröbner computation before using its basis."""
        if not self.complete:
            raise RuntimeError(self.diagnostic or "incomplete Gröbner computation")
        return self


@dataclass(frozen=True, slots=True)
class PolynomialConnectionGraph:
    """A bipartite equation-variable incidence graph without layout dependencies.

    EXAMPLES::

        >>> PolynomialConnectionGraph(("v0",), ("e0",), (("v0", "e0"),)).edges
        (('v0', 'e0'),)
    """

    variables: tuple[str, ...]
    equations: tuple[str, ...]
    edges: tuple[tuple[str, str], ...]

    def plot(self, *, show=True, save_to=None):
        """Display the graph using the optional Matplotlib presentation layer."""
        from claasp.presentation.boolean_system import plot_connection_graph

        return plot_connection_graph(self, show=show, save_to=save_to)


@dataclass(frozen=True, slots=True)
class BooleanSystemAnalysis:
    """One reusable local system for statistics, graphs and solver experiments.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> result = Speck(number_of_rounds=2).analysis.polynomial_system()
        >>> result.statistics()
        ((1, 272, 208, 586, 2), (2, 368, 304, 871, 2))

    Each row contains round, variables, equations, terms and maximum degree.
    These are local equations retaining intermediate values and carry bits,
    not fully expanded output ANFs or a measure of attack complexity.
    """

    system: BooleanEquationSystem

    def statistics(self, *, cumulative=True):
        """Return round, variable, equation, term and maximum-degree counts.

        Counts include variables occurring in selected equations. With
        cumulative=False, each row covers only equations owned by that round.
        """
        rows = []
        for round_number in sorted(set(self.system.rounds)):
            selected = tuple(
                equation
                for equation, owner in zip(self.system.equations, self.system.rounds)
                if (owner <= round_number if cumulative else owner == round_number)
            )
            variables = {
                name
                for equation in selected
                for term in equation.monomials
                for name in term.variables
            }
            rows.append(
                (
                    round_number,
                    len(variables),
                    len(selected),
                    sum(len(equation.monomials) for equation in selected),
                    max((equation.degree for equation in selected), default=-1),
                )
            )
        return tuple(rows)

    def to_terminal(self, *, cumulative=True, file=None):
        """Print aligned round statistics using the shared table renderer.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> result = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system()
            >>> result.to_terminal()  # doctest: +NORMALIZE_WHITESPACE
            Round | Variables | Equations | Terms | Max degree
            ------+-----------+-----------+-------+-----------
            1     | 4         | 2         | 5     | 1
        """
        from claasp.presentation import Table, TableColumn, TableRow, render_terminal_table

        headings = ("Round", "Variables", "Equations", "Terms", "Max degree")
        table = Table(
            tuple(TableColumn(str(i), heading) for i, heading in enumerate(headings)),
            tuple(TableRow.of(*row) for row in self.statistics(cumulative=cumulative)),
        )
        print(render_terminal_table(table), file=file)

    def connection_graph(self, *, round_number=None) -> PolynomialConnectionGraph:
        """Return equation-variable incidence, optionally for one round.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> result = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system()
            >>> graph = result.connection_graph(round_number=1)
            >>> graph.variables, graph.equations
            (('v0', 'v1', 'v2', 'v3'), ('e0', 'e1'))
            >>> graph.edges[:2]
            (('v0', 'e0'), ('v2', 'e0'))

        Each edge links a variable to an equation containing it. Call
        graph.plot() with the presentation extra installed to display it.
        """
        selected = [
            (index, equation)
            for index, (equation, owner) in enumerate(
                zip(self.system.equations, self.system.rounds)
            )
            if round_number is None or owner == round_number
        ]
        if round_number is not None and round_number not in self.system.rounds:
            raise ValueError("round_number is not present in the system")
        edges = tuple(
            (name, f"e{index}")
            for index, equation in selected
            for name in sorted({name for term in equation.monomials for name in term.variables})
        )
        variables = tuple(
            name for name in self.system.variables if any(source == name for source, _ in edges)
        )
        return PolynomialConnectionGraph(
            variables, tuple(f"e{index}" for index, _ in selected), edges
        )

    def groebner(
        self, *, timeout_seconds=10.0, fixed_variables=None, executable="Singular"
    ) -> GroebnerResult:
        """Compute a Boolean ideal basis with an explicit wall-clock limit.

        Fixed variables use the registered names in system.inputs and
        system.variables. A timeout returns complete=False, not evidence of
        algebraic security or the absence of a solution.
        Requires Singular; this example runs in its integration job.

        EXAMPLES::

            >>> from claasp.primitives import BitVectorSBox
            >>> result = BitVectorSBox(2, [0, 1, 3, 2]).analysis.polynomial_system()
            >>> result.system.inputs
            (('input', ('v0', 'v1')),)
            >>> basis = result.groebner(  # doctest: +SKIP
            ...     fixed_variables={"v0": 0, "v1": 0, "v2": 1}, timeout_seconds=10,
            ... ).require_complete()
            >>> basis.basis  # doctest: +SKIP
            ('1',)

        Input 00 maps to output 00. Fixing its first output variable v2 to 1
        is inconsistent; a completed basis containing 1 certifies this.
        """
        from claasp.drivers.algebra import SingularDriver

        if (
            isinstance(timeout_seconds, bool)
            or not isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive and finite")
        program = self.system.singular_program(fixed_variables=fixed_variables)
        start = monotonic()
        try:
            run = SingularDriver(executable=executable, timeout_seconds=timeout_seconds).execute(
                program
            )
        except TimeoutExpired:
            return GroebnerResult((), False, monotonic() - start, "Singular time limit reached")
        lines = run.stdout.splitlines()
        if (
            lines.count("CLAASP_BASIS_BEGIN") != 1
            or lines.count("CLAASP_BASIS_END") != 1
            or "?" in run.stdout
        ):
            raise RuntimeError("Singular did not return a complete basis")
        first, last = lines.index("CLAASP_BASIS_BEGIN"), lines.index("CLAASP_BASIS_END")
        if first >= last or any(
            not line.startswith("CLAASP_POLY:") for line in lines[first + 1 : last]
        ):
            raise RuntimeError("malformed Singular basis output")
        return GroebnerResult(
            tuple(line.removeprefix("CLAASP_POLY:") for line in lines[first + 1 : last]),
            True,
            run.runtime_seconds,
        )
