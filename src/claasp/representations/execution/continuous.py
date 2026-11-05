"""Graph-wide continuous-diffusion execution.

The representation propagates the legacy ``[-1, 1]`` bit correlations while
retaining v5's typed graph boundary.  It is deliberately described as a
heuristic: these values are not probabilities and do not carry a proof claim.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import partial

from claasp.components.algebraic import Add, LinearMap
from claasp.components.structural import Constant, Identity, Permutation
from claasp.components.substitution import BitVectorSBox, SBox
from claasp.components.word import (
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    ModularAdd,
    ModularSubtract,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.graph import GraphPropagation, Primitive
from claasp.semantics.cryptanalysis.continuous import (
    continuous_and,
    continuous_differential_add,
    continuous_modular_add,
    continuous_modular_subtract,
    continuous_not,
    continuous_or,
    continuous_rotate_left,
    continuous_rotate_right,
    continuous_sbox,
    continuous_shift_left,
    continuous_shift_right,
    continuous_variable_rotate,
    continuous_variable_shift,
    continuous_xor,
)
from claasp.unit_types import BinaryExtensionField, Bit
from claasp.utils import binary_field_multiply

CorrelationBits = tuple[float, ...]
CorrelationValue = tuple[CorrelationBits, ...]


@dataclass(frozen=True, slots=True)
class ContinuousEvaluationResult:
    """Continuous values for every graph source and the selected output.

    EXAMPLES::

        >>> result = ContinuousEvaluationResult({"x": (-1.0,)}, (-1.0,), 1e-4, "test")
        >>> result.claim_kind
        'heuristic'
    """

    values: Mapping[str, CorrelationBits]
    output: CorrelationBits | None
    tolerance: float
    provenance: str
    precision: str = "binary64"
    claim_kind: str = "heuristic"

    def value_of(self, source_id: str) -> CorrelationBits:
        """Return one flattened continuous graph value.

        EXAMPLES::

            >>> ContinuousEvaluationResult({"x": (0.5,)}, (0.5,), 1e-4, "test").value_of("x")
            (0.5,)
        """

        try:
            return self.values[source_id]
        except KeyError as error:
            raise KeyError(f"continuous source {source_id!r} does not exist") from error


class ContinuousExecutionDriver:
    """Evaluate every supported component of a typed graph continuously.

    EXAMPLES::

        >>> from claasp.primitives.single_component_primitives import BitwiseNot
        >>> ContinuousExecutionDriver().evaluate(BitwiseNot(1), {"input": (-1.0,)}).output
        (1.0,)
    """

    def __init__(self, *, carry_order="lsb_first"):
        if carry_order not in {"lsb_first", "legacy_msb_first"}:
            raise ValueError("carry_order must be lsb_first or legacy_msb_first")
        self.carry_order = carry_order

    def evaluate(
        self,
        primitive: Primitive,
        inputs: Mapping[str, Sequence[float]],
        *,
        tolerance: float = 1e-4,
    ) -> ContinuousEvaluationResult:
        """Propagate input correlations through a supported typed graph.

        EXAMPLES::

            >>> from claasp.primitives.single_component_primitives import Shift
            >>> ContinuousExecutionDriver().evaluate(
            ...     Shift(2, 1, "left"), {"input": (0.0, 1.0)}
            ... ).output
            (1.0, -1.0)
        """

        if set(inputs) != set(primitive.graph.input_arrays):
            raise ValueError(
                f"continuous inputs must contain exactly {sorted(primitive.graph.input_arrays)!r}"
            )
        if tolerance <= 0:
            raise ValueError("tolerance must be positive")

        values: dict[str, CorrelationValue] = {}
        for name, unit_array in primitive.graph.input_arrays.items():
            values[name] = _pack(unit_array.array_type, inputs[name], name)

        propagated = GraphPropagation(primitive).run(
            values, lambda component, operands: self._component(primitive, component, operands)
        )
        output = None if propagated.output is None else _flatten(propagated.output)
        flattened = {
            name: _flatten(value)
            for name, value in (propagated.values | propagated.bindings).items()
        }
        return ContinuousEvaluationResult(
            flattened,
            output,
            tolerance,
            f"MUR2020 majority/carry model, carry_order={self.carry_order}",
        )

    def _component(self, primitive, component, inputs):
        if isinstance(component, Constant):
            width = component.output_type.unit_type.encoded_bit_size
            return tuple(_constant_bits(value, width) for value in component.values)
        if isinstance(component, Identity):
            return inputs[0]
        if isinstance(component, Permutation):
            return tuple(inputs[0][position] for position in component.mapping)
        if isinstance(component, Xor):
            return _fold_units(inputs, continuous_xor)
        if isinstance(component, Add) and isinstance(
            component.output_type.unit_type, (Bit, BinaryExtensionField)
        ):
            return _fold_units(inputs, continuous_xor)
        if isinstance(component, BitwiseAnd):
            return _fold_units(inputs, continuous_and)
        if isinstance(component, BitwiseOr):
            return _fold_units(inputs, continuous_or)
        if isinstance(component, BitwiseNot):
            return tuple(continuous_not(unit) for unit in inputs[0])
        if isinstance(component, (ModularAdd, ModularSubtract)):
            if isinstance(component, ModularAdd) and component.modulus is not None:
                raise self._unsupported(primitive, component, "non-power-of-two modular addition")
            if isinstance(component, ModularSubtract) and self.carry_order == "lsb_first":
                return _fold_units(inputs, continuous_modular_subtract)
            return _fold_units(
                inputs, partial(continuous_modular_add, carry_order=self.carry_order)
            )
        if isinstance(component, Rotate):
            operation = (
                continuous_rotate_left if component.direction == "left" else continuous_rotate_right
            )
            return tuple(operation(unit, component.amount) for unit in inputs[0])
        if isinstance(component, Shift):
            operation = (
                continuous_shift_left if component.direction == "left" else continuous_shift_right
            )
            return tuple(operation(unit, component.amount) for unit in inputs[0])
        if isinstance(component, VariableRotate):
            amount = _flatten(inputs[1])
            return tuple(
                continuous_variable_rotate(unit, amount, direction=component.direction)
                for unit in inputs[0]
            )
        if isinstance(component, VariableShift):
            amount = _flatten(inputs[1])
            return tuple(
                continuous_variable_shift(unit, amount, direction=component.direction)
                for unit in inputs[0]
            )
        if isinstance(component, BitVectorSBox):
            flat = _flatten(inputs[0])
            return tuple((value,) for value in continuous_sbox(flat, component.table))
        if isinstance(component, SBox):
            return tuple(continuous_sbox(unit, component.table) for unit in inputs[0])
        if isinstance(component, LinearMap):
            return self._linear_map(primitive, component, inputs[0])
        raise self._unsupported(primitive, component, "no continuous semantic rule")

    def _linear_map(self, primitive, component, vector):
        unit_type = component.output_type.unit_type
        if isinstance(unit_type, Bit):
            return tuple(
                (
                    _xor_many(
                        tuple(
                            vector[index][0] for index, coefficient in enumerate(row) if coefficient
                        )
                    ),
                )
                for row in component.matrix
            )
        if isinstance(unit_type, BinaryExtensionField):
            output = []
            for row in component.matrix:
                terms = []
                for coefficient, unit in zip(row, vector):
                    if coefficient:
                        table = tuple(
                            binary_field_multiply(unit_type, coefficient, value)
                            for value in range(1 << unit_type.degree)
                        )
                        terms.append(continuous_sbox(unit, table))
                output.append(_xor_bit_vectors(tuple(terms), unit_type.degree))
            return tuple(output)
        raise self._unsupported(primitive, component, f"linear map over {type(unit_type).__name__}")

    @staticmethod
    def _unsupported(primitive, component, reason):
        return NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis 'continuous_diffusion', "
            f"backend 'dependency_free': component {component.component_id!r} "
            f"({type(component).__name__}) is unsupported: {reason}"
        )


class ContinuousDifferentialExecutionDriver(ContinuousExecutionDriver):
    """Evaluate the legacy ARX differential-correlation heuristic separately.

    Round-key constants have zero difference, whatever their concrete value.
    This model supports the legacy MODADD/ROTATE/XOR operation set and is
    heuristic; it does not compute the generalized primitive's Boolean lift.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> result = ContinuousDifferentialExecutionDriver().evaluate(
        ...     Speck(number_of_rounds=1), {"plaintext": (-1.,)*32, "key": (-1.,)*64}
        ... )
        >>> result.claim_kind
        'heuristic'
    """

    def __init__(self):
        super().__init__()

    def evaluate(self, primitive, inputs, *, tolerance=1e-4):
        """Return the separate differential model with explicit provenance."""
        from dataclasses import replace

        result = super().evaluate(primitive, inputs, tolerance=tolerance)
        return replace(
            result, provenance="legacy CP ARX continuous differential-correlation heuristic"
        )

    def _component(self, primitive, component, inputs):
        if isinstance(component, Constant):
            width = component.output_type.unit_type.encoded_bit_size
            if width is None:
                raise self._unsupported(
                    primitive,
                    component,
                    "continuous differential constants require a binary encoding",
                )
            return tuple((-1.0,) * width for _ in component.values)
        if isinstance(component, ModularAdd) and component.modulus is None:
            return _fold_units(inputs, continuous_differential_add)
        if not isinstance(component, (Identity, Permutation, Xor, Rotate)):
            raise self._unsupported(
                primitive,
                component,
                "legacy continuous differential model supports MODADD/ROTATE/XOR only",
            )
        return super()._component(primitive, component, inputs)


def _pack(array_type, values, name):
    width = array_type.unit_type.encoded_bit_size
    if width is None:
        raise NotImplementedError(f"continuous input {name!r} has no canonical binary encoding")
    flat = tuple(float(value) for value in values)
    expected = array_type.unit_count * width
    if len(flat) != expected:
        raise ValueError(f"continuous input {name!r} requires {expected} correlations")
    if any(not -1.0 <= value <= 1.0 for value in flat):
        raise ValueError("continuous correlations must lie in [-1, 1]")
    return tuple(flat[index : index + width] for index in range(0, expected, width))


def _flatten(value):
    return tuple(bit for unit in value for bit in unit)


def _constant_bits(value, width):
    return tuple(1.0 if (value >> shift) & 1 else -1.0 for shift in reversed(range(width)))


def _fold_units(operands, operation):
    output = operands[0]
    for operand in operands[1:]:
        output = tuple(operation(left, right) for left, right in zip(output, operand))
    return output


def _xor_many(values):
    output = -1.0
    for value in values:
        output = -output * value
    return output


def _xor_bit_vectors(values, width):
    if not values:
        return (-1.0,) * width
    output = values[0]
    for value in values[1:]:
        output = continuous_xor(output, value)
    return output
