"""Graph-wide continuous-diffusion execution.

The representation propagates the legacy ``[-1, 1]`` bit correlations while
retaining v5's typed graph boundary.  It is deliberately described as a
heuristic: these values are not probabilities and do not carry a proof claim.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

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
from claasp.domains import BinaryExtensionField, Bit
from claasp.graph import Primitive
from claasp.semantics.cryptanalysis.continuous import (
    continuous_and,
    continuous_modular_add,
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

        if set(inputs) != set(primitive.graph.input_ports):
            raise ValueError(
                f"continuous inputs must contain exactly {sorted(primitive.graph.input_ports)!r}"
            )
        if tolerance <= 0:
            raise ValueError("tolerance must be positive")

        values: dict[str, CorrelationValue] = {}
        for name, port in primitive.graph.input_ports.items():
            values[name] = _pack(port.array_type, inputs[name], name)

        binding_cache: dict[str, CorrelationValue] = {}
        for component in primitive.graph.components:
            selected = tuple(
                primitive.graph.resolve_selection(item, values, binding_cache)
                for item in component.inputs
            )
            if component.component_id is None:
                raise ValueError("primitive contains an unbound component")
            values[component.component_id] = self._component(primitive, component, selected)

        output = None
        if primitive.graph.output is not None:
            output = _flatten(
                primitive.graph.resolve_selection(primitive.graph.output, values, binding_cache)
            )
        flattened = {name: _flatten(value) for name, value in (values | binding_cache).items()}
        return ContinuousEvaluationResult(
            flattened,
            output,
            tolerance,
            "legacy MUR2020 continuous-diffusion equations over the typed v5 graph",
        )

    def _component(self, primitive, component, inputs):
        if isinstance(component, Constant):
            width = component.output_type.domain.encoded_bit_size
            return tuple(_constant_bits(value, width) for value in component.values)
        if isinstance(component, Identity):
            return inputs[0]
        if isinstance(component, Permutation):
            return tuple(inputs[0][position] for position in component.mapping)
        if isinstance(component, Xor):
            return _fold_units(inputs, continuous_xor)
        if isinstance(component, Add) and isinstance(
            component.output_type.domain, (Bit, BinaryExtensionField)
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
            return _fold_units(inputs, continuous_modular_add)
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
        domain = component.output_type.domain
        if isinstance(domain, Bit):
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
        if isinstance(domain, BinaryExtensionField):
            output = []
            for row in component.matrix:
                terms = []
                for coefficient, unit in zip(row, vector):
                    if coefficient:
                        table = tuple(
                            binary_field_multiply(domain, coefficient, value)
                            for value in range(1 << domain.degree)
                        )
                        terms.append(continuous_sbox(unit, table))
                output.append(_xor_bit_vectors(tuple(terms), domain.degree))
            return tuple(output)
        raise self._unsupported(primitive, component, f"linear map over {type(domain).__name__}")

    @staticmethod
    def _unsupported(primitive, component, reason):
        return NotImplementedError(
            f"primitive {primitive.family_name!r}, analysis 'continuous_diffusion', "
            f"backend 'dependency_free': component {component.component_id!r} "
            f"({type(component).__name__}) is unsupported: {reason}"
        )


def _pack(array_type, values, name):
    width = array_type.domain.encoded_bit_size
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
