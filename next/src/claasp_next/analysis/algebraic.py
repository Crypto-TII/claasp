"""Completeness-qualified algebraic evidence for Boolean primitive graphs."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from claasp_next.graph import Primitive
from claasp_next.representations.constraints.polynomial import BooleanPolynomial
from claasp_next.representations.execution import BooleanSymbolicEvaluator


@dataclass(frozen=True, slots=True)
class BooleanAlgebraicEvidence:
    """Exact output degrees and optional cube-superpoly evidence.

    A degree of ``-1`` denotes the zero polynomial.  ``complete`` is explicit
    so future bounded or solver-assisted implementations cannot accidentally
    present a heuristic result as a proof.
    """

    output_degrees: tuple[int, ...]
    cube: tuple[str, ...] | None
    cube_degrees: tuple[int, ...] | None
    cube_coefficients: tuple[BooleanPolynomial, ...] | None
    balanced_output_bits: tuple[int, ...] | None
    complete: bool
    method: str

    def require_complete(self) -> "BooleanAlgebraicEvidence":
        """Return this evidence or reject an incomplete proof claim."""

        if not self.complete:
            raise RuntimeError("algebraic evidence is incomplete and cannot establish a proof")
        return self


def analyze_boolean_algebra(
    primitive: Primitive,
    *,
    cube: Iterable[str] | None = None,
    fixed_variables: Mapping[str, int] | None = None,
) -> BooleanAlgebraicEvidence:
    """Expand a supported graph exactly and report degree/parity evidence.

    ``balanced_output_bits`` lists outputs whose cube coefficient is the zero
    polynomial after applying ``fixed_variables``.  Thus each listed bit is
    balanced over the complete cube for every assignment of variables that
    remain symbolic.
    """

    result = BooleanSymbolicEvaluator().evaluate(primitive)
    output_degrees = tuple(polynomial.degree for polynomial in result.output_anfs)
    if cube is None:
        if fixed_variables:
            raise ValueError("fixed_variables require a cube")
        return BooleanAlgebraicEvidence(
            output_degrees, None, None, None, None, True, "exact_sparse_anf"
        )

    selected = tuple(cube)
    if len(set(selected)) != len(selected):
        raise ValueError("cube variables must be unique")
    substitutions = dict(fixed_variables or {})
    coefficients = tuple(
        polynomial.cube_coefficient(selected).substitute(substitutions)
        for polynomial in result.output_anfs
    )
    cube_degrees = tuple(polynomial.degree for polynomial in coefficients)
    return BooleanAlgebraicEvidence(
        output_degrees=output_degrees,
        cube=selected,
        cube_degrees=cube_degrees,
        cube_coefficients=coefficients,
        balanced_output_bits=tuple(
            index for index, degree in enumerate(cube_degrees) if degree == -1
        ),
        complete=True,
        method="exact_sparse_anf",
    )
