"""Explicit bounded and MiniZinc drivers for linear branch numbers."""

from hashlib import sha256
from itertools import combinations, product
from subprocess import TimeoutExpired

from claasp_next.analysis.component_properties import (
    ComponentAnalysisProvenance,
    ComponentProperty,
    ComponentPropertyResult,
    DiagnosticCode,
    PropertyClaim,
    PropertyDomain,
    PropertyRequest,
    semantic_component_key,
    unavailable_result,
)
from claasp_next.analysis.linear_properties import (
    apply_matrix,
    expand_binary_field_matrix,
    matrix_rank,
)
from claasp_next.components import LinearMap
from claasp_next.domains import BinaryExtensionField, Bit, PrimeField
from claasp_next.provenance import DriverIdentity, DriverKind
from claasp_next.utils.matrices import transpose_matrix


def _identity(component, request, driver, method):
    key = semantic_component_key(component, request.domain)
    digest = sha256(repr(key).encode()).hexdigest()[:16]
    return ComponentAnalysisProvenance(
        f"{key.component_type.rsplit('.', 1)[-1]}:{request.domain.value}:{digest}",
        method,
        driver=driver,
    )


def _matrix_domain(component, request):
    if not isinstance(component, LinearMap):
        raise TypeError("branch-number drivers require a LinearMap component")
    matrix = component.matrix
    domain = component.inputs[0].value_type.domain
    if request.domain is PropertyDomain.BIT_LINEAR:
        if isinstance(domain, BinaryExtensionField):
            return expand_binary_field_matrix(matrix, domain), Bit()
        if isinstance(domain, Bit):
            return matrix, domain
        raise ValueError("bit-linear requests require Bit or binary-field matrices")
    if request.domain in {PropertyDomain.WORD_LINEAR, PropertyDomain.FINITE_FIELD_LINEAR}:
        if isinstance(domain, (BinaryExtensionField, PrimeField)):
            return matrix, domain
        raise ValueError("word/field requests require a non-binary finite field")
    raise ValueError("branch-number drivers require a linear analysis domain")


class BoundedBranchNumberDriver:
    """Enumerate inputs through a fixed support weight without overclaiming.

    A found candidate proves an upper bound on the minimum branch number.
    Results become exact only after complete support coverage or after reaching
    the mathematical lower bound (one, or two for an injective map).
    """

    identity = DriverIdentity(
        "bounded_branch_enumeration", DriverKind.EXECUTION_ENGINE
    )

    def __init__(self, maximum_input_weight: int = 2) -> None:
        if (
            not isinstance(maximum_input_weight, int)
            or isinstance(maximum_input_weight, bool)
            or maximum_input_weight <= 0
        ):
            raise ValueError("maximum_input_weight must be a positive integer")
        self.maximum_input_weight = maximum_input_weight

    def analyze(self, component, request: PropertyRequest) -> ComponentPropertyResult:
        provenance = _identity(component, request, self.identity, "bounded_support_enumeration")
        if request.property not in {
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        }:
            return unavailable_result(
                request, provenance, DiagnosticCode.UNSUPPORTED_PROPERTY,
                "bounded branch enumeration supports only differential/linear branch numbers",
            )
        try:
            matrix, domain = _matrix_domain(component, request)
        except (TypeError, ValueError) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN, str(error)
            )
        if request.property is ComponentProperty.LINEAR_BRANCH_NUMBER:
            matrix = transpose_matrix(matrix)
        cardinality = _cardinality(domain)
        column_count = len(matrix[0])
        limit = min(self.maximum_input_weight, column_count)
        best = len(matrix) + column_count + 1
        for weight in range(1, limit + 1):
            for support in combinations(range(column_count), weight):
                for values in product(range(1, cardinality), repeat=weight):
                    vector = [0] * column_count
                    for position, value in zip(support, values):
                        vector[position] = value
                    output = apply_matrix(matrix, vector, domain)
                    best = min(best, weight + sum(value != 0 for value in output))
        injective = matrix_rank(matrix, domain) == column_count
        lower_bound = 2 if injective else 1
        complete = limit == column_count or best == lower_bound
        claim = PropertyClaim.EXACT if complete else PropertyClaim.PROVED_UPPER_BOUND
        return ComponentPropertyResult(request, claim, best, complete, provenance)


class MiniZincBranchNumberDriver:
    """Optimize an exact binary branch number through optional MiniZinc."""

    def __init__(
        self,
        *,
        solver: str = "gecode",
        executable: str = "minizinc",
        timeout_seconds: float | None = 10,
    ) -> None:
        from claasp_next.drivers.solvers import MiniZincSolver

        self.solver = MiniZincSolver(solver, executable, timeout_seconds)
        self.identity = DriverIdentity(
            "minizinc_component_branch", DriverKind.EXTERNAL_TOOL, solver
        )

    def analyze(self, component, request: PropertyRequest) -> ComponentPropertyResult:
        provenance = _identity(component, request, self.identity, "minizinc_exact_optimization")
        if request.property not in {
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        }:
            return unavailable_result(
                request, provenance, DiagnosticCode.UNSUPPORTED_PROPERTY,
                "MiniZinc branch optimization supports only differential/linear branch numbers",
            )
        try:
            matrix, domain = _matrix_domain(component, request)
        except (TypeError, ValueError) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN, str(error)
            )
        if not isinstance(domain, Bit):
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN,
                "the MiniZinc baseline consumes binary matrices; request bit-linear expansion",
            )
        if request.property is ComponentProperty.LINEAR_BRANCH_NUMBER:
            matrix = transpose_matrix(matrix)
        model = _minizinc_model(matrix)
        try:
            solved = self.solver.solve(model)
        except (FileNotFoundError, RuntimeError, TimeoutExpired) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.DRIVER_UNAVAILABLE, str(error)
            )
        if (
            not solved.is_satisfied
            or solved.values is None
            or "==========" not in solved.stdout
        ):
            return unavailable_result(
                request, provenance, DiagnosticCode.DRIVER_UNAVAILABLE,
                "MiniZinc did not return an optimal branch number",
            )
        branch_number = sum(solved.values["input_bits"]) + sum(
            solved.values["output_bits"]
        )
        return ComponentPropertyResult(
            request, PropertyClaim.EXACT, branch_number, True, provenance,
        )


def _minizinc_model(matrix):
    from claasp_next.representations.constraints.cp import MiniZincModel

    rows, columns = len(matrix), len(matrix[0])
    literal = "[|" + "|".join(
        ",".join(str(value) for value in row) for row in matrix
    ) + "|]"
    return MiniZincModel(
        declarations=(
            f"int: input_size = {columns};",
            f"int: output_size = {rows};",
            f"array[1..output_size, 1..input_size] of 0..1: matrix = {literal};",
            "array[1..input_size] of var 0..1: input_bits;",
            "array[1..output_size] of var 0..1: output_bits;",
            "var int: branch_number = sum(input_bits) + sum(output_bits);",
        ),
        constraints=(
            "constraint sum(input_bits) >= 1;",
            "constraint forall(row in 1..output_size)(sum(column in 1..input_size)(matrix[row,column] * input_bits[column]) mod 2 = output_bits[row]);",
        ),
        solve="solve minimize branch_number;",
        provenance=("component_property", "exact_binary_branch_number"),
    )


def _cardinality(domain):
    if isinstance(domain, Bit):
        return 2
    if isinstance(domain, BinaryExtensionField):
        return 1 << domain.degree
    return domain.modulus


__all__ = ["BoundedBranchNumberDriver", "MiniZincBranchNumberDriver"]
