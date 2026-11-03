"""Explicit bounded and MiniZinc drivers for linear branch numbers."""

from hashlib import sha256
from itertools import combinations, product
from subprocess import TimeoutExpired

from claasp.analysis.component_properties import (
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
from claasp.analysis.linear_properties import (
    apply_matrix,
    expand_binary_field_matrix,
    matrix_rank,
)
from claasp.components import LinearMap
from claasp.provenance import DriverIdentity, DriverKind
from claasp.unit_types import BinaryExtensionField, Bit, PrimeField
from claasp.utils.matrices import transpose_matrix


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
    unit_type = component.inputs[0].array_type.unit_type
    if request.domain is PropertyDomain.BIT_LINEAR:
        if isinstance(unit_type, BinaryExtensionField):
            return expand_binary_field_matrix(matrix, unit_type), Bit()
        if isinstance(unit_type, Bit):
            return matrix, unit_type
        raise ValueError("bit-linear requests require Bit or binary-field matrices")
    if request.domain in {PropertyDomain.WORD_LINEAR, PropertyDomain.FINITE_FIELD_LINEAR}:
        if isinstance(unit_type, (BinaryExtensionField, PrimeField)):
            return matrix, unit_type
        raise ValueError("word/field requests require a non-binary finite field")
    raise ValueError("branch-number drivers require a linear analysis unit_type")


class BoundedBranchNumberDriver:
    """Enumerate inputs through a fixed support weight without overclaiming.

    A found candidate proves an upper bound on the minimum branch number.
    Results become exact only after complete support coverage or after reaching
    the mathematical lower bound (one, or two for an injective map).

    EXAMPLES::

        >>> from claasp import UnitArray, UnitArrayType
        >>> from claasp.unit_types import Bit
        >>> from claasp.analysis import ComponentProperty, PropertyDomain, PropertyRequest
        >>> from claasp.components import LinearMap
        >>> from claasp.drivers.analysis import BoundedBranchNumberDriver
        >>> component = LinearMap(UnitArray("x", UnitArrayType(Bit(), (2,))), ((1, 0), (0, 1)))
        >>> request = PropertyRequest(ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
        ...     PropertyDomain.BIT_LINEAR)
        >>> result = BoundedBranchNumberDriver(1).analyze(component, request)
        >>> (result.value, result.complete)
        (2, True)
    """

    identity = DriverIdentity("bounded_branch_enumeration", DriverKind.EXECUTION_ENGINE)

    def __init__(self, maximum_input_weight: int = 2) -> None:
        if (
            not isinstance(maximum_input_weight, int)
            or isinstance(maximum_input_weight, bool)
            or maximum_input_weight <= 0
        ):
            raise ValueError("maximum_input_weight must be a positive integer")
        self.maximum_input_weight = maximum_input_weight

    def analyze(self, component, request: PropertyRequest) -> ComponentPropertyResult:
        """Compute the analyze for this public typed contract."""

        provenance = _identity(component, request, self.identity, "bounded_support_enumeration")
        if request.property not in {
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        }:
            return unavailable_result(
                request,
                provenance,
                DiagnosticCode.UNSUPPORTED_PROPERTY,
                "bounded branch enumeration supports only differential/linear branch numbers",
            )
        try:
            matrix, unit_type = _matrix_domain(component, request)
        except (TypeError, ValueError) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN, str(error)
            )
        if request.property is ComponentProperty.LINEAR_BRANCH_NUMBER:
            matrix = transpose_matrix(matrix)
        cardinality = _cardinality(unit_type)
        column_count = len(matrix[0])
        limit = min(self.maximum_input_weight, column_count)
        best = len(matrix) + column_count + 1
        for weight in range(1, limit + 1):
            for support in combinations(range(column_count), weight):
                for values in product(range(1, cardinality), repeat=weight):
                    vector = [0] * column_count
                    for position, value in zip(support, values):
                        vector[position] = value
                    output = apply_matrix(matrix, vector, unit_type)
                    best = min(best, weight + sum(value != 0 for value in output))
        injective = matrix_rank(matrix, unit_type) == column_count
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
        from claasp.drivers.solvers import MiniZincSolver

        self.solver = MiniZincSolver(solver, executable, timeout_seconds)
        self._cache: dict[tuple, ComponentPropertyResult] = {}
        self.identity = DriverIdentity(
            "minizinc_component_branch", DriverKind.EXTERNAL_TOOL, solver
        )

    def analyze(self, component, request: PropertyRequest) -> ComponentPropertyResult:
        """Compute the analyze for this public typed contract."""

        provenance = _identity(component, request, self.identity, "minizinc_exact_optimization")
        cache_key = (semantic_component_key(component, request.domain), request)
        if cache_key in self._cache:
            return self._cache[cache_key]
        if request.property not in {
            ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER,
            ComponentProperty.LINEAR_BRANCH_NUMBER,
        }:
            return unavailable_result(
                request,
                provenance,
                DiagnosticCode.UNSUPPORTED_PROPERTY,
                "MiniZinc branch optimization supports only differential/linear branch numbers",
            )
        word_size = request.option_map.get("word_size", 1)
        try:
            if not isinstance(word_size, int) or isinstance(word_size, bool) or word_size < 1:
                raise ValueError("word_size must be a positive integer")
            if (
                isinstance(component, LinearMap)
                and isinstance(component.inputs[0].array_type.unit_type, Bit)
                and request.domain is PropertyDomain.WORD_LINEAR
            ):
                matrix, unit_type = component.matrix, Bit()
            else:
                matrix, unit_type = _matrix_domain(component, request)
                if isinstance(unit_type, BinaryExtensionField):
                    if "word_size" in request.option_map and word_size != unit_type.degree:
                        raise ValueError("word_size must match the field encoding width")
                    word_size = unit_type.degree
                    matrix = expand_binary_field_matrix(matrix, unit_type)
                    unit_type = Bit()
                elif request.domain is PropertyDomain.BIT_LINEAR and word_size != 1:
                    raise ValueError("grouped words require the word_linear domain")
            if not isinstance(unit_type, Bit):
                raise ValueError("MiniZinc branch optimization requires a binary encoding")
            if len(matrix) % word_size or len(matrix[0]) % word_size:
                raise ValueError("matrix dimensions must be multiples of word_size")
        except (TypeError, ValueError) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.INAPPLICABLE_DOMAIN, str(error)
            )
        if request.property is ComponentProperty.LINEAR_BRANCH_NUMBER:
            matrix = transpose_matrix(matrix)
        # Identical independent bit strands have the same minimum word support
        # as one strand: a union cannot have less support than any member,
        # and a single nonzero strand attains that member's weight.
        compressed = _identical_word_strands(matrix, word_size)
        if compressed is not None:
            matrix, word_size = compressed, 1
        model = _minizinc_model(matrix, word_size)
        try:
            solved = self.solver.solve(model)
        except (FileNotFoundError, RuntimeError, TimeoutExpired) as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.DRIVER_UNAVAILABLE, str(error)
            )
        if not solved.is_satisfied or solved.values is None or "==========" not in solved.stdout:
            return unavailable_result(
                request,
                provenance,
                DiagnosticCode.DRIVER_UNAVAILABLE,
                "MiniZinc did not return an optimal branch number",
            )
        try:
            branch_number = _checked_branch_number(matrix, word_size, solved.values)
        except ValueError as error:
            return unavailable_result(
                request, provenance, DiagnosticCode.DRIVER_UNAVAILABLE, str(error)
            )
        result = ComponentPropertyResult(
            request, PropertyClaim.EXACT, branch_number, True, provenance
        )
        self._cache[cache_key] = result
        return result


def _identical_word_strands(matrix, word_size):
    if word_size == 1:
        return None
    rows, columns = len(matrix), len(matrix[0])
    reduced = []
    for row in range(0, rows, word_size):
        coefficients = []
        for column in range(0, columns, word_size):
            coefficient = matrix[row][column]
            if any(
                matrix[row + i][column + j] != (coefficient if i == j else 0)
                for i in range(word_size)
                for j in range(word_size)
            ):
                return None
            coefficients.append(coefficient)
        reduced.append(tuple(coefficients))
    return tuple(reduced)


def _checked_branch_number(matrix, word_size, values):
    inputs, outputs = values.get("input_bits"), values.get("output_bits")
    if not isinstance(inputs, (list, tuple)) or not isinstance(outputs, (list, tuple)):
        raise ValueError("branch solver omitted its input/output witness")
    if len(inputs) != len(matrix[0]) or len(outputs) != len(matrix) or not any(inputs):
        raise ValueError("branch solver returned invalid witness dimensions or zero input")
    if any(bit not in (0, 1) for bit in (*inputs, *outputs)):
        raise ValueError("branch solver returned non-binary witness values")
    expected = tuple(sum(a * b for a, b in zip(row, inputs)) % 2 for row in matrix)
    if tuple(outputs) != expected:
        raise ValueError("branch witness fails independent matrix evaluation")
    return sum(
        any(bits[start : start + word_size])
        for bits in (inputs, outputs)
        for start in range(0, len(bits), word_size)
    )


def _minizinc_model(matrix, word_size=1):
    from claasp.representations.constraints.cp import MiniZincModel

    rows, columns = len(matrix), len(matrix[0])
    literal = "[|" + "|".join(",".join(str(value) for value in row) for row in matrix) + "|]"
    return MiniZincModel(
        declarations=(
            f"int: input_size = {columns};",
            f"int: output_size = {rows};",
            f"array[1..output_size, 1..input_size] of 0..1: matrix = {literal};",
            "array[1..input_size] of var 0..1: input_bits;",
            "array[1..output_size] of var 0..1: output_bits;",
            "var int: branch_number = "
            + (
                "sum(input_bits) + sum(output_bits);"
                if word_size == 1
                else f"sum(word in 0..{columns // word_size - 1})(bool2int(sum(bit in 1..{word_size})(input_bits[word*{word_size}+bit]) > 0)) + "
                f"sum(word in 0..{rows // word_size - 1})(bool2int(sum(bit in 1..{word_size})(output_bits[word*{word_size}+bit]) > 0));"
            ),
        ),
        constraints=(
            "constraint sum(input_bits) >= 1;",
            "constraint forall(row in 1..output_size)(sum(column in 1..input_size)(matrix[row,column] * input_bits[column]) mod 2 = output_bits[row]);",
        ),
        solve="solve minimize branch_number;",
        provenance=("component_property", "exact_binary_branch_number"),
    )


def _cardinality(unit_type):
    if isinstance(unit_type, Bit):
        return 2
    if isinstance(unit_type, BinaryExtensionField):
        return 1 << unit_type.degree
    return unit_type.modulus


__all__ = ["BoundedBranchNumberDriver", "MiniZincBranchNumberDriver"]
