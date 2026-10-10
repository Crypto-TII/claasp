"""Sage-independent structural and linear permutation layers."""

from collections.abc import Callable, Iterable
from functools import lru_cache

from claasp.components.algebraic import LinearMap
from claasp.components.structural import Permutation
from claasp.domains import Bit
from claasp.graph import PortLike
from claasp.graph.port import as_selection

BitState = tuple[int, ...]


def _bit_selection(component_input: PortLike, operation: str):
    selection = as_selection(component_input)
    if not isinstance(selection.array_type.domain, Bit):
        raise ValueError(f"{operation} requires the Bit domain")
    return selection


def _rotate_left(values: tuple[int, ...], amount: int) -> tuple[int, ...]:
    amount %= len(values)
    return values[amount:] + values[:amount]


def _binary_matrix(size: int, transform: Callable[[BitState], BitState]):
    rows = [[0] * size for _ in range(size)]
    for column in range(size):
        basis = (0,) * column + (1,) + (0,) * (size - column - 1)
        output = transform(basis)
        if len(output) != size or any(value not in (0, 1) for value in output):
            raise ValueError("binary transform must preserve the state size and Bit domain")
        for row, value in enumerate(output):
            rows[row][column] = value
    return tuple(tuple(row) for row in rows)


def shift_rows(
    component_input: PortLike,
    row_width: int,
    offsets: Iterable[int],
    component_id: str | None = None,
) -> Permutation:
    """Permute row-major logical units, with positive offsets shifting right.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Word
        >>> from claasp.components import shift_rows
        >>> graph = Primitive("rows", {"state": ArrayType(Word(8), (8,))})
        >>> shift_rows(graph.graph.input("state"), 4, (1, 2)).mapping
        (3, 0, 1, 2, 6, 7, 4, 5)
    """

    selection = as_selection(component_input)
    if not isinstance(row_width, int) or isinstance(row_width, bool) or row_width <= 0:
        raise ValueError("row width must be a positive integer")
    frozen_offsets = tuple(offsets)
    if not frozen_offsets or any(
        not isinstance(offset, int) or isinstance(offset, bool) for offset in frozen_offsets
    ):
        raise ValueError("row offsets must be a non-empty iterable of integers")
    if row_width * len(frozen_offsets) != selection.array_type.unit_count:
        raise ValueError("row dimensions must cover every selected unit exactly")
    mapping = tuple(
        row * row_width + (column - offset) % row_width
        for row, offset in enumerate(frozen_offsets)
        for column in range(row_width)
    )
    return Permutation(selection, mapping, component_id=component_id)


def sigma(
    component_input: PortLike,
    rotation_amounts: Iterable[int],
    component_id: str | None = None,
) -> LinearMap:
    """XOR a bit vector with right rotations by every supplied amount.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Bit
        >>> from claasp.components import sigma
        >>> graph = Primitive("sigma", {"x": ArrayType(Bit(), (4,))})
        >>> sigma(graph.graph.input("x"), (1, 3)).matrix[0]
        (1, 1, 0, 1)
    """

    selection = _bit_selection(component_input, "sigma")
    width = selection.array_type.unit_count
    rotations = tuple(rotation_amounts)
    if any(not isinstance(amount, int) or isinstance(amount, bool) for amount in rotations):
        raise TypeError("sigma rotation amounts must be integers")
    matrix = tuple(
        tuple(
            (int(column == row) + sum(column == (row - amount) % width for amount in rotations)) % 2
            for column in range(width)
        )
        for row in range(width)
    )
    return LinearMap(selection, matrix, component_id=component_id)


def _keccak_values(state: BitState, lane_width: int) -> BitState:
    parity = tuple(
        tuple(
            state[(x * 5 + y) * lane_width + z]
            ^ state[(x * 5 + y + 1) * lane_width + z]
            ^ state[(x * 5 + y + 2) * lane_width + z]
            ^ state[(x * 5 + y + 3) * lane_width + z]
            ^ state[(x * 5 + y + 4) * lane_width + z]
            for z in range(lane_width)
        )
        for x in range(5)
        for y in (0,)
    )
    delta = tuple(
        tuple(
            parity[(x - 1) % 5][z] ^ parity[(x + 1) % 5][(z + 1) % lane_width]
            for z in range(lane_width)
        )
        for x in range(5)
    )
    return tuple(
        state[(x * 5 + y) * lane_width + z] ^ delta[x][z]
        for x in range(5)
        for y in range(5)
        for z in range(lane_width)
    )


def keccak_theta(component_input: PortLike, component_id: str | None = None) -> LinearMap:
    """Construct the Keccak theta map for any positive lane width.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Bit
        >>> from claasp.components import keccak_theta
        >>> graph = Primitive("theta", {"x": ArrayType(Bit(), (25,))})
        >>> len(keccak_theta(graph.graph.input("x")).matrix)
        25
    """

    selection = _bit_selection(component_input, "Keccak theta")
    size = selection.array_type.unit_count
    if size % 25:
        raise ValueError("Keccak theta state size must be divisible by 25")
    return LinearMap(selection, _keccak_matrix(size), component_id=component_id)


@lru_cache(maxsize=8)
def _keccak_matrix(size: int):
    lane_width = size // 25
    return _binary_matrix(size, lambda state: _keccak_values(state, lane_width))


def _xoodoo_values(state: BitState, lane_width: int) -> BitState:
    plane_size = 4 * lane_width
    parity = tuple(
        state[index] ^ state[plane_size + index] ^ state[2 * plane_size + index]
        for index in range(plane_size)
    )
    lanes = tuple(parity[x * lane_width : (x + 1) * lane_width] for x in range(4))
    shifted_5 = tuple(_rotate_left(lanes[(x - 1) % 4], 5) for x in range(4))
    shifted_14 = tuple(_rotate_left(lanes[(x - 1) % 4], 14) for x in range(4))
    effect = tuple(shifted_5[x][z] ^ shifted_14[x][z] for x in range(4) for z in range(lane_width))
    return tuple(value ^ effect[index % plane_size] for index, value in enumerate(state))


def xoodoo_theta(component_input: PortLike, component_id: str | None = None) -> LinearMap:
    """Construct the Xoodoo theta map for three planes of four lanes.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Bit
        >>> from claasp.components import xoodoo_theta
        >>> graph = Primitive("theta", {"x": ArrayType(Bit(), (12,))})
        >>> len(xoodoo_theta(graph.graph.input("x")).matrix)
        12
    """

    selection = _bit_selection(component_input, "Xoodoo theta")
    size = selection.array_type.unit_count
    if size % 12:
        raise ValueError("Xoodoo theta state size must be divisible by 12")
    return LinearMap(selection, _xoodoo_matrix(size), component_id=component_id)


@lru_cache(maxsize=8)
def _xoodoo_matrix(size: int):
    lane_width = size // 12
    return _binary_matrix(size, lambda state: _xoodoo_values(state, lane_width))


def _gaston_values(state: BitState, rotations: tuple[int, ...]) -> BitState:
    row_width = len(state) // 5
    r, s, u, *row_rotations = rotations
    rows = tuple(state[index * row_width : (index + 1) * row_width] for index in range(5))
    parity = tuple(
        rows[0][z] ^ rows[1][z] ^ rows[2][z] ^ rows[3][z] ^ rows[4][z] for z in range(row_width)
    )
    twisted = tuple(_rotate_left(rows[index], row_rotations[index]) for index in range(5))
    second = tuple(
        twisted[0][z] ^ twisted[1][z] ^ twisted[2][z] ^ twisted[3][z] ^ twisted[4][z]
        for z in range(row_width)
    )
    effect = tuple(
        parity[z] ^ _rotate_left(parity, r)[z] ^ second[z] ^ _rotate_left(second, s)[z]
        for z in range(row_width)
    )
    shifted = _rotate_left(effect, u)
    return tuple(rows[row][z] ^ shifted[z] for row in range(5) for z in range(row_width))


def gaston_theta(
    component_input: PortLike,
    rotation_amounts: Iterable[int] = (1, 18, 23, 25, 32, 52, 60, 63),
    component_id: str | None = None,
) -> LinearMap:
    """Construct Gaston's twin-column parity mixer for five equal rows.

    EXAMPLES::

        >>> from claasp import Primitive, ArrayType
        >>> from claasp.domains import Bit
        >>> from claasp.components import gaston_theta
        >>> graph = Primitive("theta", {"x": ArrayType(Bit(), (320,))})
        >>> len(gaston_theta(graph.graph.input("x")).matrix)
        320
    """

    selection = _bit_selection(component_input, "Gaston theta")
    size = selection.array_type.unit_count
    rotations = tuple(rotation_amounts)
    if len(rotations) != 8 or any(
        not isinstance(amount, int) or isinstance(amount, bool) for amount in rotations
    ):
        raise ValueError("Gaston theta requires exactly eight integer rotation amounts")
    if size % 5:
        raise ValueError("Gaston theta state size must be divisible by five")
    return LinearMap(selection, _gaston_matrix(size, rotations), component_id=component_id)


@lru_cache(maxsize=8)
def _gaston_matrix(size: int, rotations: tuple[int, ...]):
    return _binary_matrix(size, lambda state: _gaston_values(state, rotations))
