"""The legacy ARX continuous differential-correlation model over typed graphs."""

from math import isfinite

from claasp.components import Add, Constant, Identity, ModularAdd, Permutation, Rotate, Xor
from claasp.representations.constraints import (
    ConstraintBackend,
    ConstraintModelApplication,
    _direct_model,
)
from claasp.representations.constraints.cp.model import MiniZincModel
from claasp.unit_types import BinaryExtensionField, Bit


class ContinuousDifferentialCPModel:
    """Export the separate legacy quarter-scaled continuous carry recurrence.

    Inputs are MSB-first correlations in [-1, 1]; None entries are free real
    variables. The output mask is a nonempty Boolean selection. The objective
    maximizes its absolute product correlation, equivalently minimizing its
    actual negative logarithm. This remains a heuristic model of a primitive.

    EXAMPLES::

        >>> from claasp.primitives import Speck
        >>> model = ContinuousDifferentialCPModel(
        ...     Speck(number_of_rounds=1), {"plaintext": (-1.,)*32, "key": (-1.,)*64}
        ... )
        >>> "solve maximize correlation" in model.minizinc_model().source()
        True
    """

    model_provenance = _direct_model(
        ConstraintBackend.CP,
        "ContinuousDifferentialCPModel",
        "continuous_differential_linear",
        "legacy continuous XOR and quarter-scaled ARX carry polynomials",
        "Direct serialization of the legacy CP heuristic, independently replayed on returned inputs; no exact cryptographic probability claim.",
    )

    def __init__(self, primitive, inputs, *, output_mask=None, maximize=True):
        self.primitive = primitive
        self.inputs = {name: tuple(values) for name, values in inputs.items()}
        if set(self.inputs) != set(primitive.graph.input_arrays):
            raise ValueError("continuous inputs must cover exactly the primitive inputs")
        for name, array in primitive.graph.input_arrays.items():
            width = array.array_type.encoded_bit_size
            if width is None or len(self.inputs[name]) != width:
                raise ValueError(f"wrong continuous input width for {name}")
            if any(
                value is not None and (not isfinite(value) or not -1 <= value <= 1)
                for value in self.inputs[name]
            ):
                raise ValueError("input correlations must be finite values in [-1, 1] or None")
        output = primitive.graph.output
        if output is None:
            raise ValueError("primitive needs an output")
        output_width = output.array_type.encoded_bit_size
        if output_width is None:
            raise TypeError("continuous output needs a fixed binary encoding")
        self.output = output
        self.output_width = output_width
        self.output_mask = _mask_pattern(output_mask, self.output_width)
        self.maximize = maximize
        self._wires: dict[str, tuple[str, ...]] = {}
        self._declarations: list[str] = []
        self._constraints: list[str] = []
        self._serial = 0

    def _array(self, width, prefix="wire"):
        name = f"{prefix}_{self._serial}"
        self._serial += 1
        self._declarations.append(f"array[0..{width - 1}] of var -1.0..1.0: {name};")
        return tuple(f"{name}[{bit}]" for bit in range(width))

    def _selected(self, selection):
        return tuple(
            self._wires[name][bit]
            for name, bit in self.primitive.graph.selection_bit_sources(selection)
        )

    def _addition(self, left, right, width):
        result = self._array(len(left))
        for start in range(0, len(left), width):
            carry = self._array(width, "carry")
            self._constraints.append(f"constraint {carry[-1]} = -1.0;")
            for bit in reversed(range(width)):
                a, b = left[start + bit], right[start + bit]
                self._constraints.append(
                    f"constraint {result[start + bit]} = {a}*{b}*{carry[bit]};"
                )
                if bit:
                    self._constraints.append(
                        f"constraint {carry[bit - 1]} = 0.25*({a}+{b}+{carry[bit]}+{a}*{b}*{carry[bit]});"
                    )
        return result

    def minizinc_model(self):
        """Build deterministic MiniZinc, rejecting every unsupported operation."""
        self._wires, self._declarations, self._constraints, self._serial = {}, [], [], 0
        for name, values in self.inputs.items():
            refs = self._array(len(values), "input")
            self._wires[name] = refs
            for ref, value in zip(refs, values):
                if value is not None:
                    self._constraints.append(f"constraint {ref} = {float(value)!r};")
        for component in self.primitive.graph.components:
            operands = tuple(self._selected(selection) for selection in component.inputs)
            width = component.output_type.unit_type.encoded_bit_size
            if width is None:
                raise TypeError("continuous components need a fixed binary encoding")
            if isinstance(component, Constant):
                output = ("-1.0",) * (width * component.output_type.unit_count)
            elif isinstance(component, Identity):
                output = operands[0]
            elif isinstance(component, Permutation):
                output = tuple(
                    operands[0][unit * width + bit]
                    for unit in component.mapping
                    for bit in range(width)
                )
            elif isinstance(component, Rotate):
                rotated: list[str] = []
                amount = component.amount % width
                if component.direction == "right":
                    amount = -amount
                for start in range(0, len(operands[0]), width):
                    rotated.extend(
                        operands[0][start + (bit + amount) % width] for bit in range(width)
                    )
                output = tuple(rotated)
            elif isinstance(component, ModularAdd) and component.modulus is None:
                output = operands[0]
                for other in operands[1:]:
                    output = self._addition(output, other, width)
            elif isinstance(component, Xor) or (
                isinstance(component, Add)
                and isinstance(component.output_type.unit_type, (Bit, BinaryExtensionField))
            ):
                output = operands[0]
                for other in operands[1:]:
                    values = self._array(len(output))
                    self._constraints.extend(
                        f"constraint {ref} = -({a})*({b});"
                        for ref, a, b in zip(values, output, other)
                    )
                    output = values
            else:
                raise NotImplementedError(
                    f"continuous differential model does not support {type(component).__name__}: {component.component_id}"
                )
            assert component.component_id is not None
            self._wires[component.component_id] = output
        selected = self._selected(self.output)
        self._declarations.extend(
            (
                f"array[0..{self.output_width - 1}] of var bool: output_mask;",
                f"array[0..{self.output_width - 1}] of var -1.0..1.0: output_values;",
                "var 0.0..1.0: correlation;",
            )
        )
        self._constraints.extend(
            f"constraint output_values[{bit}] = {ref};" for bit, ref in enumerate(selected)
        )
        for bit, value in enumerate(self.output_mask):
            if value is not None:
                self._constraints.append(
                    f"constraint output_mask[{bit}] = {str(bool(value)).lower()};"
                )
        self._constraints.extend(
            (
                "constraint sum([bool2int(bit) | bit in output_mask]) >= 1;",
                "constraint correlation = product([if output_mask[i] then abs(output_values[i]) else 1.0 endif | i in index_set(output_mask)]);",
            )
        )
        return MiniZincModel(
            tuple(self._declarations),
            tuple(self._constraints),
            solve="solve maximize correlation;" if self.maximize else "solve satisfy;",
            constraint_models=(ConstraintModelApplication(self.model_provenance),),
        )

    @property
    def input_variables(self):
        """Map logical input names to emitted input-array names after building."""
        return {
            name: refs[0].split("[")[0] for name, refs in self._wires.items() if name in self.inputs
        }


def _mask_pattern(value, width):
    if value is None:
        return (None,) * width
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 < value < 1 << width:
            raise ValueError("output_mask must be a nonzero mask fitting the output")
        return tuple((value >> shift) & 1 for shift in reversed(range(width)))
    if isinstance(value, str):
        if len(value) != width or any(bit not in "01?" for bit in value) or set(value) == {"0"}:
            raise ValueError("output mask pattern must fit the output and use 0, 1 or ?")
        return tuple(None if bit == "?" else int(bit) for bit in value)
    raise TypeError("output mask must be a packed integer or a 0/1/? pattern")


__all__ = ["ContinuousDifferentialCPModel"]
