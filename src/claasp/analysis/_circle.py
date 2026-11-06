"""Shared binary-circle boundary validation and concrete execution context.

Both analyses use the ordinary evaluator and its GraphPropagation schedule.
This module does not maintain a separate implementation of any primitive.
"""

from collections.abc import Mapping

from claasp.graph import Primitive
from claasp.semantics.cryptanalysis._circle_algebra import integer
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.unit_types import BinaryExtensionField, Bit, Word


class _BinaryCircleAnalysis:
    _analysis_name = "circle"

    def __init__(
        self,
        primitive: Primitive,
        *,
        bibrace: BinaryBibrace | None = None,
        input_basis: CircleBasis | None = None,
        output_basis: CircleBasis | None = None,
        input_name: str = "plaintext",
    ) -> None:
        self.primitive = primitive
        self.input_name = input_name
        if input_name not in primitive.graph.input_arrays:
            raise ValueError("input_name must identify a declared primitive input")
        if input_name in primitive.graph.secret_inputs:
            raise ValueError("the varying input must be public; fix the secret inputs explicitly")
        if primitive.graph.output is None:
            raise ValueError(f"{self._analysis_name} analysis requires a declared output")
        arrays = tuple(primitive.graph.input_arrays.values()) + tuple(primitive.graph.components)
        for array in arrays:
            array_type = array.array_type if hasattr(array, "array_type") else array.output_type
            if not isinstance(array_type.unit_type, (Bit, Word, BinaryExtensionField)):
                raise NotImplementedError(
                    f"binary {self._analysis_name} analysis excludes odd-prime and nonbinary units"
                )
        n = primitive.graph.input_arrays[input_name].array_type.encoded_bit_size
        m = primitive.graph.output.array_type.encoded_bit_size
        assert n is not None and m is not None
        if bibrace is not None and (input_basis is not None or output_basis is not None):
            raise ValueError("supply bibrace or explicit boundary bases, not both")
        if bibrace is not None:
            if n % bibrace.width or m % bibrace.width:
                raise ValueError("bibrace cells must tile both boundaries exactly")
            input_basis = CircleBasis((bibrace,) * (n // bibrace.width))
            output_basis = CircleBasis((bibrace,) * (m // bibrace.width))
        self.input_basis = (
            input_basis if input_basis is not None else CircleBasis((BinaryBibrace(n),))
        )
        self.output_basis = (
            output_basis if output_basis is not None else CircleBasis((BinaryBibrace(m),))
        )
        if self.input_basis.width != n or self.output_basis.width != m:
            raise ValueError("circle bases must match the primitive's packed boundary widths")

    def _fixed(self, fixed_inputs: Mapping[str, int] | None) -> dict[str, int]:
        fixed = dict(fixed_inputs or {})
        expected = set(self.primitive.graph.input_arrays) - {self.input_name}
        if set(fixed) != expected:
            raise ValueError(f"fixed_inputs must contain exactly {sorted(expected)}")
        for name, value in fixed.items():
            width = self.primitive.graph.input_arrays[name].array_type.encoded_bit_size
            assert width is not None
            integer(value, width, name)
        return fixed

    def _evaluate(self, value: int, fixed: dict[str, int]) -> int:
        result = self.primitive.evaluate({**fixed, self.input_name: value})
        if not isinstance(result, int):
            raise TypeError("binary primitive evaluator did not return a packed integer")
        return result
