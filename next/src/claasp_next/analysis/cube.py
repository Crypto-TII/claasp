"""Direct, dependency-free verification of Boolean cube coefficients."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from claasp_next.graph import Primitive


@dataclass(frozen=True, slots=True)
class CubeSumResult:
    """An exact output-bit sum over every point of a Boolean cube."""

    parity: int
    evaluations: int
    complete: bool
    method: str = "exhaustive_cube_sum"


def evaluate_cube_sum(
    primitive: Primitive,
    inputs: Mapping[str, int],
    *,
    variable_input: str,
    cube_positions: Sequence[int],
    output_bit: int,
) -> CubeSumResult:
    """Evaluate the exact coefficient selected by a cube at one assignment.

    Bit positions are MSB-first, consistently with graph selections and the
    symbolic variable names. The supplied value of each cube bit is ignored.
    """

    if variable_input not in primitive.input_ports:
        raise ValueError(f"unknown variable input: {variable_input}")
    if set(inputs) != set(primitive.input_ports):
        raise ValueError("inputs must provide every primitive input exactly once")
    width = primitive.input_ports[variable_input].value_type.encoded_bit_size
    output_width = primitive.output.value_type.encoded_bit_size if primitive.output else 0
    if width is None or output_width is None:
        raise TypeError("cube sums require canonically bit-encoded input and output domains")
    positions = tuple(cube_positions)
    if len(set(positions)) != len(positions):
        raise ValueError("cube positions must be unique")
    if any(not isinstance(position, int) or isinstance(position, bool)
           or not 0 <= position < width for position in positions):
        raise ValueError("cube positions must fit the selected input")
    if not isinstance(output_bit, int) or isinstance(output_bit, bool) \
            or not 0 <= output_bit < output_width:
        raise ValueError("output_bit must fit the primitive output")

    cleared = int(inputs[variable_input])
    for position in positions:
        cleared &= ~(1 << (width - 1 - position))
    parity = 0
    for assignment in range(1 << len(positions)):
        varied = cleared
        for index, position in enumerate(positions):
            if assignment & (1 << index):
                varied |= 1 << (width - 1 - position)
        point = dict(inputs)
        point[variable_input] = varied
        output = primitive.evaluate(point)
        parity ^= (output >> (output_width - 1 - output_bit)) & 1
    return CubeSumResult(parity, 1 << len(positions), True)
