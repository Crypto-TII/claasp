"""Private compact realizations used by reviewed inversion equivalents."""

from claasp_next.components import Add, Constant, LinearMap, Multiply, Permutation
from claasp_next.domains import Bit
from claasp_next.graph import Primitive, PrimitiveInput, PrimitiveKind, ValueType
from claasp_next.graph.bit_builder import (
    BitState,
    calculate_inputs,
    simplify_inputs,
)
from claasp_next.primitives.block_ciphers._word_graph import word_type
from claasp_next.primitives.block_ciphers.aradi.sbox_compact_linear_map import (
    AradiSBoxCompactLinearMap,
    create_linear_layers,
)
from claasp_next.primitives.permutations.gimli.primitive import N_COLS, N_ROWS, ROT_TABLE, Gimli
from claasp_next.primitives.permutations.keccak.sbox import (
    X_NUM,
    Y_NUM,
    KeccakSbox,
)
from claasp_next.primitives.permutations.norx import Norx
from claasp_next.primitives.permutations.xoodoo.sbox import (
    LANE_NUM,
    LANE_SIZE,
    PLANE_NUM,
    XoodooSbox,
)
from claasp_next.primitives.tweakable_block_ciphers.qarmav2.primitive import QARMAv2
from claasp_next.transformations.inverse_rules import _inverse_matrix

# Each output bit is the XOR of three rotated input words.
_QARMAV2_M_MATRIX = tuple(
    tuple(
        sum(
            input_word == (output_word + rotation + 1) % 4
            and input_bit == (output_bit + rotation + 1) % 4
            for rotation in range(3)
        )
        & 1
        for input_word in range(4)
        for input_bit in range(4)
    )
    for output_word in range(4)
    for output_bit in range(4)
)


class AradiCompactWord(AradiSBoxCompactLinearMap):
    """Compact Aradi graph with the canonical word-typed public boundary.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import AradiCompactWord
        >>> graph = AradiCompactWord(number_of_rounds=1)
        >>> (graph.family_name, len(graph.rounds), graph.output.value_type.encoded_bit_size)
        ('aradi', 1, 128)
    """

    def __init__(self, number_of_rounds=16):
        self.block_bit_size = 128
        self.key_bit_size = 256
        self.WORD_SIZE = 32
        self.SBOX = [0, 1, 2, 3, 4, 13, 15, 6, 8, 11, 5, 14, 12, 7, 10, 9]
        Primitive.__init__(
            self,
            "aradi",
            {"plaintext": word_type(16, 8), "key": word_type(32, 8)},
            kind=PrimitiveKind.BLOCK_CIPHER,
        )
        self._declared_output_bit_size = self.block_bit_size
        self.output_bit_size = self.block_bit_size
        self._construction_rounds = []
        self.A = [11, 10, 9, 8]
        self.B = [8, 9, 4, 9]
        self.C = [14, 11, 14, 7]
        self.linear_layers = create_linear_layers(self.A, self.B, self.C)
        state = self.unpack_bits(self.input("plaintext")).owner_id
        key = self.unpack_bits(self.input("key")).owner_id
        for round_i in range(number_of_rounds):
            self.add_round()
            round_key = self.get_round_key_id(key, round_i)
            state = self.round_function(state, round_key, round_i)
            key = self.update_key(key, round_i)
        round_key = self.get_round_key_id(key, 0)
        outputs = [
            self.add_xor_component(
                [round_key, state],
                [list(range(start, start + 32)), list(range(start, start + 32))],
                32,
            ).id
            for start in range(0, 128, 32)
        ]
        bits = self.join(*(self.port(output) for output in outputs))
        self.set_output(self.pack_bits(bits, 16))


class KeccakSboxTheta(KeccakSbox):
    """Keccak S-box realization with theta represented as one linear map.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import KeccakSboxTheta
        >>> graph = KeccakSboxTheta(number_of_rounds=1, word_size=8)
        >>> (len(graph.rounds), any(type(item).__name__ == "LinearMap" for item in graph.components))
        (1, True)
    """

    def theta_definition(self, state):
        """Author Keccak theta as one exact binary linear-map component."""
        inputs_id = []
        inputs_pos = []
        for x in range(X_NUM):
            for y in range(Y_NUM):
                inputs_id += state[x][y].id
                inputs_pos += state[x][y].input_bit_positions
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_theta_keccak_component(inputs_id, inputs_pos, self.state_bit_size)
        component_id = self.get_current_component_id()
        return [
            [
                BitState(
                    [component_id],
                    [
                        list(
                            range(
                                (x * Y_NUM + y) * self.word_bit_size,
                                (x * Y_NUM + y + 1) * self.word_bit_size,
                            )
                        )
                    ],
                )
                for y in range(Y_NUM)
            ]
            for x in range(X_NUM)
        ]


class XoodooSboxTheta(XoodooSbox):
    """Xoodoo S-box realization with theta represented as one linear map.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import XoodooSboxTheta
        >>> graph = XoodooSboxTheta(number_of_rounds=1)
        >>> (len(graph.rounds), any(type(item).__name__ == "LinearMap" for item in graph.components))
        (1, True)
    """

    def theta_definition(self, planes):
        """Author Xoodoo theta as one exact binary linear-map component."""
        inputs_id, inputs_pos = calculate_inputs(planes)
        inputs_id, inputs_pos = simplify_inputs(inputs_id, inputs_pos)
        self.add_theta_xoodoo_component(inputs_id, inputs_pos, self.state_bit_size)
        component_id = self.get_current_component_id()
        replacement = [
            BitState(
                [component_id for _ in range(LANE_NUM)],
                [
                    list(
                        range(
                            (plane * LANE_NUM + lane) * LANE_SIZE,
                            (plane * LANE_NUM + lane + 1) * LANE_SIZE,
                        )
                    )
                    for lane in range(LANE_NUM)
                ],
            )
            for plane in range(PLANE_NUM)
        ]
        planes[:] = replacement
        return planes


class QARMAv2Compact(QARMAv2):
    """Canonical QARMAv2 with each authored M function kept as one linear map.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import QARMAv2Compact
        >>> graph = QARMAv2Compact(number_of_rounds=1)
        >>> (len(graph.rounds), graph.realization.name)
        (3, 'permutation_linear_layer')
    """

    def M_function(self, input_ids, input_pos):
        """Author the reversible M function as one linear-map component."""
        component_id = self._component_id("linear_layer")
        self._add(
            LinearMap(
                self._selection(input_ids, input_pos),
                _QARMAV2_M_MATRIX,
                component_id,
            ),
            input_pos,
        )
        port = self.port(component_id)
        return [
            self.view(port[tuple(range(word * 4, (word + 1) * 4))]).owner_id for word in range(4)
        ]


class NorxTriangular(Norx):
    """NORX with H authored as its reversible triangular bit recurrence.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import NorxTriangular
        >>> graph = NorxTriangular(number_of_rounds=1, word_size=32)
        >>> (len(graph.rounds), graph.word_bit_size)
        (1, 32)
    """

    def h_function(self, x, y):
        """Author NORX H through its bit-triangular recurrence."""
        output_ids = []
        for bit in range(self.word_bit_size):
            inputs_id = [x.id[0], y.id[0]]
            inputs_pos = [
                [x.input_bit_positions[0][bit]],
                [y.input_bit_positions[0][bit]],
            ]
            if bit + 1 < self.word_bit_size:
                product = self.add_and_component(
                    [x.id[0], y.id[0]],
                    [
                        [x.input_bit_positions[0][bit + 1]],
                        [y.input_bit_positions[0][bit + 1]],
                    ],
                    1,
                )
                inputs_id.append(product.id)
                inputs_pos.append([0])
            output_ids.append(self.add_xor_component(inputs_id, inputs_pos, 1).id)
        joined = self.add_intermediate_output_component(
            output_ids,
            [[0]] * self.word_bit_size,
            self.word_bit_size,
            "triangular_h",
        )
        return BitState([joined.id], [list(range(self.word_bit_size))])


class GimliTriangular(Gimli):
    """Gimli with each SP box authored as its triangular bit recurrence.

    EXAMPLES::

        >>> from claasp_next.transformations._inverse_realizations import GimliTriangular
        >>> graph = GimliTriangular(number_of_rounds=1, word_size=8)
        >>> (len(graph.rounds), graph.word_bit_size)
        (1, 8)
    """

    def _source_bit(self, state, position):
        return self.port(state.id[0])[state.input_bit_positions[0][position]]

    def _sum_bits(self, *values):
        return values[0] if len(values) == 1 else self.add_component(Add(values))

    def _product_bits(self, left, right):
        return self.add_component(Multiply((left, right)))

    def _or_bits(self, left, right):
        return self._sum_bits(left, right, self._product_bits(left, right))

    def sp_box(self, states):
        """Author one Gimli SP box as a reversible triangular recurrence."""
        rotated = [[None for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column in range(N_COLS):
            for row in range(N_ROWS - 1):
                component = self.add_rotate_component(
                    states[row][column].id,
                    states[row][column].input_bit_positions,
                    self.word_bit_size,
                    ROT_TABLE[row],
                )
                rotated[row][column] = BitState(
                    [component.id],
                    [list(range(self.word_bit_size))],
                )
            rotated[2][column] = states[2][column]

        result = [[None for _ in range(N_COLS)] for _ in range(N_ROWS)]
        for column in range(N_COLS):
            x, y, z = (rotated[row][column] for row in range(N_ROWS))
            output_bits = [[None] * self.word_bit_size for _ in range(N_ROWS)]
            for bit in range(self.word_bit_size - 1, -1, -1):
                z_inputs = [self._source_bit(x, bit)]
                if bit + 1 < self.word_bit_size:
                    z_inputs.append(self._source_bit(z, bit + 1))
                if bit + 2 < self.word_bit_size:
                    z_inputs.append(
                        self._product_bits(
                            self._source_bit(y, bit + 2),
                            self._source_bit(z, bit + 2),
                        )
                    )
                output_bits[2][bit] = self._sum_bits(*z_inputs)

                y_inputs = [self._source_bit(y, bit), self._source_bit(x, bit)]
                if bit + 1 < self.word_bit_size:
                    y_inputs.append(
                        self._or_bits(
                            self._source_bit(x, bit + 1),
                            self._source_bit(z, bit + 1),
                        )
                    )
                output_bits[1][bit] = self._sum_bits(*y_inputs)

                x_inputs = [self._source_bit(z, bit), self._source_bit(y, bit)]
                if bit + 3 < self.word_bit_size:
                    x_inputs.append(
                        self._product_bits(
                            self._source_bit(x, bit + 3),
                            self._source_bit(y, bit + 3),
                        )
                    )
                output_bits[0][bit] = self._sum_bits(*x_inputs)

            for row in range(N_ROWS):
                joined = self.view(self.join(*output_bits[row]))
                result[row][column] = BitState(
                    [joined.owner_id],
                    [list(range(self.word_bit_size))],
                )
        return result


def subterranean_inverse(source, output_name="output"):
    """Author the exact inverse of the keyed Subterranean v1 round graph.

    EXAMPLES::

        >>> from claasp_next.primitives import Subterranean
        >>> from claasp_next.transformations._inverse_realizations import subterranean_inverse
        >>> tuple(subterranean_inverse(Subterranean()).input_ports)
        ('output', 'key')
    """

    size = source.output.value_type.unit_count
    derived = Primitive(
        f"{source.family_name}_inverse",
        {
            output_name: PrimitiveInput(source.output.value_type, role=output_name),
            "key": source.input_descriptor("key"),
        },
        kind=source.kind,
        provenance=source.provenance,
    )
    derived.add_round()
    state = derived.input(output_name).select_all()
    key = derived.input("key").select_all()
    forward_matrix = tuple(
        tuple(int(column in (row, (row + 3) % size, (row + 8) % size)) for column in range(size))
        for row in range(size)
    )
    inverse_matrix = _inverse_matrix(forward_matrix, Bit())
    permutations = [
        component for component in source.components if isinstance(component, Permutation)
    ]
    if len(permutations) != len(source.rounds):
        raise ValueError("Subterranean inverse requires one terminal permutation per round")
    one = derived.add_component(Constant(ValueType(Bit(), (1,)), (1,)))
    ones = derived.add_component(Constant(ValueType(Bit(), (size,)), (1,) * size))

    for permutation in reversed(permutations):
        inverse_mapping = [0] * size
        for output_position, input_position in enumerate(permutation.mapping):
            inverse_mapping[input_position] = output_position
        state = derived.add_component(Permutation(state, inverse_mapping))
        keyed_tail = derived.add_component(Add((state[tuple(range(1, size))], key)))
        state = derived.join(state[0], keyed_tail)
        state = derived.add_component(LinearMap(state, inverse_matrix))
        state = derived.join(
            derived.add_component(Add((state[0], one))), state[tuple(range(1, size))]
        )
        chi_output = derived.add_component(Add((state, ones)))
        fixed = tuple(chi_output[index] for index in range(size))
        recovered = list(fixed)
        for step in range(3 * (size - 1) // 2):
            index = ((size - 2) * step) % size
            negated = derived.add_component(Add((fixed[(index + 1) % size], one)))
            product = derived.add_component(Multiply((recovered[(index + 2) % size], negated)))
            recovered[index] = derived.add_component(Add((fixed[index], product)))
        state = derived.join(*recovered)
    derived.set_output(state)
    return derived


def _chichi_inverse_bits(derived, output_bits, zero, one):
    """Return ChiChi's input bits in its specification's least-significant indexing."""

    size = len(output_bits)
    middle = size // 2
    half = middle // 2
    negated = {}

    def negate(bit):
        if bit not in negated:
            negated[bit] = derived.add_component(Add((bit, one)))
        return negated[bit]

    def add(*bits):
        return zero if not bits else bits[0] if len(bits) == 1 else derived.add_component(Add(bits))

    def multiply(*bits):
        return (
            one
            if not bits
            else bits[0]
            if len(bits) == 1
            else derived.add_component(Multiply(bits))
        )

    def product(indices, *, complement=False):
        return multiply(
            *(negate(output_bits[index]) if complement else output_bits[index] for index in indices)
        )

    def sum_of_products(terms):
        return add(
            *(
                multiply(output_bits[index], product(factors, complement=True))
                for index, factors in terms
            )
        )

    # Lemmas 3--6 in the ChiChi bijectivity proof recover the four bits
    # needed by lambda without expanding the high-degree inverse into a table.
    left = sum_of_products((2 * index, range(1, 2 * index, 2)) for index in range(half - 1))
    right = add(
        negate(output_bits[middle]),
        sum_of_products(
            (2 * index + middle, range(middle + 1, 2 * index + middle, 2))
            for index in range(1, half)
        ),
        multiply(
            output_bits[middle - 2],
            product(range(middle + 1, 2 * middle + 1, 2), complement=True),
        ),
    )
    x_middle = add(output_bits[middle - 3], multiply(left, right))

    upper_odd = sum_of_products(
        (2 * index - 1, range(middle + 2, 2 * index, 2)) for index in range(half + 1, middle + 1)
    )
    x_middle_plus_m3 = add(
        output_bits[middle - 1],
        multiply(
            add(
                negate(output_bits[middle - 3]),
                multiply(negate(output_bits[middle]), left),
            ),
            upper_odd,
        ),
    )

    lower_odd = sum_of_products(
        (2 * index - 1, range(0, 2 * index, 2)) for index in range(1, half - 1)
    )
    upper_odd_tail = sum_of_products(
        (2 * index - 1, range(middle + 2, 2 * index, 2)) for index in range(half + 2, middle + 1)
    )
    x_middle_m1 = add(
        output_bits[middle - 2],
        lower_odd,
        multiply(
            add(
                negate(output_bits[middle - 1]),
                multiply(
                    add(negate(output_bits[middle + 1]), upper_odd_tail),
                    negate(output_bits[middle - 3]),
                ),
            ),
            product(range(0, middle - 2, 2), complement=True),
        ),
    )

    upper_even = sum_of_products(
        (2 * index, range(middle + 1, 2 * index + 1, 2)) for index in range(half + 1, middle)
    )
    lower_odd_long = sum_of_products(
        (2 * index - 1, range(0, 2 * index, 2)) for index in range(1, half)
    )
    x_middle_m2 = add(
        output_bits[middle],
        upper_even,
        multiply(
            add(
                output_bits[middle - 2],
                lower_odd_long,
                multiply(
                    output_bits[middle - 1],
                    product(range(0, middle - 2, 2), complement=True),
                ),
            ),
            product(range(middle + 1, 2 * middle + 1, 2), complement=True),
        ),
    )

    chi_outputs = list(output_bits)
    corrections = {
        middle - 3: x_middle_plus_m3,
        middle - 2: add(x_middle_m1, x_middle_m2),
        middle - 1: add(x_middle_plus_m3, x_middle_m1),
        middle: add(x_middle, x_middle_m2),
    }
    for index, correction in corrections.items():
        chi_outputs[index] = add(chi_outputs[index], correction)

    def inverse_odd_chi(bits):
        fixed = tuple(bits)
        recovered = list(fixed)
        length = len(bits)
        for step in range(3 * (length - 1) // 2):
            index = ((length - 2) * step) % length
            recovered[index] = add(
                fixed[index],
                multiply(recovered[(index + 2) % length], negate(fixed[(index + 1) % length])),
            )
        return recovered

    return inverse_odd_chi(chi_outputs[: middle - 1]) + inverse_odd_chi(chi_outputs[middle - 1 :])


def chilow_inverse(source, output_name="output"):
    """Author the exact one-round ChiLow-40 inverse with retained tweak and key.

    EXAMPLES::

        >>> from claasp_next.primitives import Chilow
        >>> from claasp_next.transformations._inverse_realizations import chilow_inverse
        >>> tuple(chilow_inverse(Chilow()).input_ports)
        ('output', 'input_tweak', 'key')
    """

    if len(source.rounds) != 1 or source.output.value_type.unit_count != 40:
        raise ValueError("direct ChiLow inverse currently requires the catalogue ChiLow-40 graph")
    derived = Primitive(
        f"{source.family_name}_inverse",
        {
            output_name: PrimitiveInput(source.output.value_type, role=output_name),
            "input_tweak": source.input_descriptor("input_tweak"),
            "key": source.input_descriptor("key"),
        },
        kind=source.kind,
        provenance=source.provenance,
    )
    derived.add_round()
    zero = derived.add_component(Constant(ValueType(Bit(), (1,)), (0,)))
    one = derived.add_component(Constant(ValueType(Bit(), (1,)), (1,)))

    def abstract_bits(port):
        return [port[index] for index in range(port.value_type.unit_count - 1, -1, -1)]

    def add(left, right):
        return derived.add_component(Add((left, right)))

    output = abstract_bits(derived.input(output_name).select_all())
    tweak = abstract_bits(derived.input("input_tweak").select_all())
    key = abstract_bits(derived.input("key").select_all())
    whitened_tweak = [add(tweak[index], key[index]) for index in range(64)]
    alpha, offsets = 3, (1, 26, 50)
    final_tweak = [
        derived.add_component(
            Add(tuple(whitened_tweak[(alpha * index + offset) % 64] for offset in offsets))
        )
        for index in range(64)
    ]
    chichi_output = [add(output[index], final_tweak[index]) for index in range(40)]
    whitened_plaintext = _chichi_inverse_bits(derived, chichi_output, zero, one)
    plaintext = [add(whitened_plaintext[index], key[64 + index]) for index in range(40)]
    derived.set_output(derived.join(*reversed(plaintext)))
    return derived


__all__ = [
    "AradiCompactWord",
    "GimliTriangular",
    "KeccakSboxTheta",
    "NorxTriangular",
    "QARMAv2Compact",
    "XoodooSboxTheta",
    "chilow_inverse",
    "subterranean_inverse",
]
