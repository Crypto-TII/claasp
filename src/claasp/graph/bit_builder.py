"""Concise source authoring for bit-oriented primitive graphs.

This module is intentionally an authoring facade, not a second graph model.
Every operation immediately creates an ordinary immutable v5 component and
returns only a small reference used while the Python constructor is running.
Evaluators and representations therefore consume the same typed DAG as graphs
written with :meth:`PrimitiveBuilder.add_component` directly.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from claasp.components import (
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    FeedbackRegister,
    FeedbackRegisterSpec,
    FeedbackTerm,
    IDEAMultiply,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Permutation,
    Rotate,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
    gaston_theta,
    keccak_theta,
    sigma,
    xoodoo_theta,
)
from claasp.domains import BinaryExtensionField, Bit
from claasp.encoding import bits_from_int
from claasp.graph.array_type import ArrayType
from claasp.graph.metadata import (
    LEGACY_KIND_NAMES,
    InputVisibility,
    PrimitiveInput,
    infer_primitive_kind,
)
from claasp.graph.port import PortLike, Selection, as_selection
from claasp.graph.primitive import Primitive
from claasp.utils.integers import coerce_exact_int as coerce_exact_int

# Stable boundary-role and taxonomy values used by primitive source modules.
BLOCK_CIPHER = "block_cipher"
STREAM_CIPHER = "stream_cipher"
TWEAKABLE_BLOCK_CIPHER = "tweakable_block_cipher"
PERMUTATION = "permutation"
HASH_FUNCTION = "hash_function"
INPUT_KEY = "key"
INPUT_PLAINTEXT = "plaintext"
INPUT_INITIALIZATION_VECTOR = "initialization_vector"
INPUT_NONCE = "nonce"
INPUT_MESSAGE = "input_message"
INPUT_STATE = "input_state"
INPUT_BLOCK_COUNT = "input_block_count"
INPUT_TWEAK = "input_tweak"
INPUT_FRAME = "input_frame"
INTERMEDIATE_OUTPUT = "intermediate_output"


@dataclass(frozen=True, slots=True)
class BitState:
    """A construction-time reference to selected bits of graph sources."""

    id: list[str]
    input_bit_positions: list[list[int]]


@dataclass(frozen=True, slots=True)
class BitComponent:
    """Construction-time view matching a newly authored component boundary."""

    id: str
    input_bit_positions: list[list[int]]


def _bit_type(width: int) -> ArrayType:
    return ArrayType(Bit(), (width,))


def simplify_inputs(inputs_id, inputs_pos):
    """Merge adjacent selections from the same source."""

    if not inputs_id:
        return [], []
    new_ids = [inputs_id[0]]
    new_positions = [deepcopy(inputs_pos[0])]
    for source_id, positions in zip(inputs_id[1:], inputs_pos[1:]):
        if source_id == new_ids[-1]:
            new_positions[-1] += positions
        else:
            new_ids.append(source_id)
            new_positions.append(deepcopy(positions))
    return new_ids, new_positions


def get_inputs_parameter(inputs_list):
    ids: list[str] = []
    positions: list[list[int]] = []
    for state in inputs_list:
        ids += deepcopy(state.id)
        positions += deepcopy(state.input_bit_positions)
    if not ids:
        raise ValueError("inputs_id must have at least one element")
    return simplify_inputs(ids, positions)


def extract_inputs(input_ids_list, input_bit_positions_list, positions):
    """Select flattened bit positions while retaining their source grouping."""

    flattened = [
        (source_id, position)
        for source_id, source_positions in zip(input_ids_list, input_bit_positions_list)
        for position in source_positions
    ]
    selected = [flattened[position] for position in positions]
    if not selected:
        return [], []
    ids = [selected[0][0]]
    grouped = [[selected[0][1]]]
    for source_id, position in selected[1:]:
        if source_id == ids[-1]:
            grouped[-1].append(position)
        else:
            ids.append(source_id)
            grouped.append([position])
    return ids, grouped


def get_number_of_rounds_from(block_bit_size, key_bit_size, number_of_rounds, configurations):
    if number_of_rounds is None:
        for parameters in configurations:
            if (
                parameters["block_bit_size"] == block_bit_size
                and parameters["key_bit_size"] == key_bit_size
            ):
                number_of_rounds = parameters["number_of_rounds"]
                break
        else:
            raise ValueError("No available number of rounds for the given parameters.")
    if (
        not isinstance(number_of_rounds, int)
        or isinstance(number_of_rounds, bool)
        or number_of_rounds <= 0
    ):
        raise ValueError("number_of_rounds must be a positive integer")
    return number_of_rounds


def bytes_positions_to_little_endian_for_multiple_of_32(values, number_of_blocks):
    output = []
    for block in range(number_of_blocks):
        word = values[block * 32 : (block + 1) * 32]
        output.append(sum((word[index * 8 : (index + 1) * 8] for index in (3, 2, 1, 0)), []))
    return output


def wordlist_to_int(words, word_size, endianess="big"):
    ordered = words if endianess == "little" else reversed(words)
    return sum(word * 2 ** (word_size * index) for index, word in enumerate(ordered))


class _BinaryVector(list):
    def __xor__(self, other):
        return _BinaryVector(left ^ right for left, right in zip(self, other))

    def __getitem__(self, key):
        value = super().__getitem__(key)
        return _BinaryVector(value) if isinstance(key, slice) else value

    def __add__(self, other):
        return _BinaryVector(super().__add__(other))


class _BinaryMatrix(tuple):
    def rows(self):
        return self


def linear_layer_to_binary_matrix(transform, input_bit_size, output_bit_size, specific_inputs):
    """Derive a row-major binary matrix by evaluating basis vectors."""

    rows = [[0] * input_bit_size for _ in range(output_bit_size)]
    for column in range(input_bit_size):
        basis = _BinaryVector([0] * input_bit_size)
        basis[column] = 1
        result = transform(basis, *specific_inputs)
        if len(result) != output_bit_size:
            raise ValueError("linear transform returned an unexpected output width")
        for row, value in enumerate(result):
            rows[row][column] = int(value) & 1
    return _BinaryMatrix(tuple(row) for row in rows)


def get_2d_array_element_from_1d_array_index(index, values, width):
    return values[index // width][index % width]


def set_2d_array_element_from_1d_array_index(index, values, element, width):
    values[index // width][index % width] = element


def get_input_bit_positions_latin_dances(component, word_size=32):
    return (
        component.input_bit_positions
        if component.id == INPUT_PLAINTEXT
        else [list(range(word_size))]
    )


def init_state_latin_dances(primitive, input_plaintext):
    for row in range(4):
        for column in range(4):
            start = (row * 4 + column) * primitive.WORD_SIZE
            primitive.state_of_components[row][column] = BitState(
                input_plaintext, [list(range(start, start + primitive.WORD_SIZE))]
            )


def add_intermediate_output_component_latin_dances_permutations(
    primitive, round_index, number_of_rounds
):
    ids = []
    positions = []
    for row in primitive.state_of_components:
        for component in row:
            ids.append(component.id if isinstance(component.id, str) else component.id[0])
            positions.append(list(range(primitive.WORD_SIZE)))
    method = (
        primitive.add_primitive_output_component
        if round_index == number_of_rounds - 1
        else primitive.add_round_output_component
    )
    method(ids, positions, primitive.block_bit_size)


_XOODOO_ROUND_CONSTANTS = (
    0x00000058,
    0x00000038,
    0x000003C0,
    0x000000D0,
    0x00000120,
    0x00000014,
    0x00000060,
    0x0000002C,
    0x00000380,
    0x000000F0,
    0x000001A0,
    0x00000012,
)


def get_ci(round_index, qi=None, si=None, t=None):
    """Return the standardized Xoodoo round constant for indices -11..0."""

    del qi, si, t
    if not -11 <= round_index <= 0:
        raise ValueError("Xoodoo round index must be in -11..0")
    return _XOODOO_ROUND_CONSTANTS[round_index + 11]


def layer_and_lane_initialization(plane_num=3, lane_num=4, lane_size=32):
    plane_size = lane_num * lane_size
    return [
        BitState(
            [INPUT_PLAINTEXT for _ in range(lane_num)],
            [
                [bit + lane * lane_size + plane * plane_size for bit in range(lane_size)]
                for lane in range(lane_num)
            ],
        )
        for plane in range(plane_num)
    ]


def create_new_state_for_calculation(plane_num=3):
    return [BitState([[], [], [], []], [[], [], [], []]) for _ in range(plane_num)]


def calculate_inputs(planes, plane_num=3, lane_num=4):
    ids = []
    positions = []
    for plane in planes[:plane_num]:
        if plane.id and isinstance(plane.id[0], list):
            for lane in range(lane_num):
                ids += plane.id[lane]
                positions += plane.input_bit_positions[lane]
        else:
            ids += plane.id
            positions += plane.input_bit_positions
    return ids, positions


class BitGraphPrimitive(Primitive):
    """Author a typed v5 primitive with compact MSB-first bit selections."""

    def __init__(
        self,
        family_name,
        primitive_type,
        primitive_inputs,
        primitive_inputs_bit_size,
        primitive_output_bit_size,
        primitive_reference_code=None,
    ) -> None:
        del primitive_reference_code
        descriptors = {
            name: PrimitiveInput(
                _bit_type(width),
                role=name,
                visibility=InputVisibility.SECRET if name == INPUT_KEY else InputVisibility.PUBLIC,
            )
            for name, width in zip(primitive_inputs, primitive_inputs_bit_size)
        }
        kind = (
            infer_primitive_kind(descriptors)
            if any(descriptor.is_secret for descriptor in descriptors.values())
            else LEGACY_KIND_NAMES.get(primitive_type)
        )
        super().__init__(
            family_name,
            descriptors,
            kind=kind,
        )
        self._declared_output_bit_size = primitive_output_bit_size
        self.output_bit_size = primitive_output_bit_size
        self._construction_rounds: list[list[BitComponent]] = []

    @property
    def current_round_number(self):
        return len(self.graph.rounds) - 1 if self.graph.rounds else None

    @property
    def current_round_number_of_components(self):
        return len(self.graph.rounds[-1].components) if self.graph.rounds else 0

    @property
    def number_of_rounds(self):
        return len(self.graph.rounds)

    def _add_round(self):
        result = super()._add_round()
        self._construction_rounds.append([])
        return result

    def component_from(self, round_number, index):
        return self._construction_rounds[round_number][index]

    def get_number_of_components_in_round(self, round_number):
        return len(self._construction_rounds[round_number])

    def get_current_component_id(self):
        return self._construction_rounds[-1][-1].id

    def _component_id(self, prefix: str) -> str:
        if not self.graph.rounds:
            raise ValueError("add a round before adding components")
        return f"{prefix}_{self.current_round_number}_{self.current_round_number_of_components}"

    def _selection(self, ids, positions) -> Selection:
        selections = tuple(
            self.graph.port(source_id)[tuple(selected)]
            for source_id, selected in zip(ids, positions)
            if selected
        )
        if not selections:
            raise ValueError("component input must select at least one bit")
        if len(selections) == 1:
            return selections[0]
        return self._builder.join(*selections).select_all()

    def _record(self, port: PortLike, input_positions=None) -> BitComponent:
        selection = as_selection(port)
        state = BitComponent(
            selection.source.owner_id,
            deepcopy(input_positions)
            if input_positions is not None
            else [list(selection.positions)],
        )
        self._construction_rounds[-1].append(state)
        return state

    def _add(self, component, input_positions=None) -> BitComponent:
        return self._record(self._builder.add_component(component), input_positions)

    def _add_word_operation(self, ids, positions, width, operation, parameter=None, modulus=None):
        source = self._selection(ids, positions)
        component_id = self._component_id(
            {
                "XOR": "xor",
                "AND": "and",
                "OR": "or",
                "NOT": "not",
                "MODADD": "modadd",
                "MODSUB": "modsub",
                "MODMUL": "modmul",
                "IDEA": "modmul",
                "ROTATE": "rot",
                "SHIFT": "shift",
                "ROTATE_BY_VARIABLE_AMOUNT": "var_rot",
                "SHIFT_BY_VARIABLE_AMOUNT": "var_shift",
            }[operation]
        )
        unary = operation in {"NOT", "ROTATE", "SHIFT"}
        if operation in {"ROTATE_BY_VARIABLE_AMOUNT", "SHIFT_BY_VARIABLE_AMOUNT"}:
            operands = (source[:width], source[width:])
        else:
            count = 1 if unary else source.array_type.unit_count // width
            operands = tuple(source[index * width : (index + 1) * width] for index in range(count))
        if operation in {"ROTATE_BY_VARIABLE_AMOUNT", "SHIFT_BY_VARIABLE_AMOUNT"}:
            words = (self._builder.pack_bits(operands[0], width),)
        else:
            words = tuple(self._builder.pack_bits(value, width) for value in operands)
        if operation in {"XOR", "AND", "OR"} and len(words) == 1:
            return self._record(operands[0], positions)
        elif operation == "XOR":
            output = self._builder.add_component(Xor(words, component_id=component_id))
        elif operation == "AND":
            output = self._builder.add_component(BitwiseAnd(words, component_id=component_id))
        elif operation == "OR":
            output = self._builder.add_component(BitwiseOr(words, component_id=component_id))
        elif operation == "NOT":
            output = self._builder.add_component(BitwiseNot(words[0], component_id=component_id))
        elif operation == "MODADD":
            output = self._builder.add_component(
                ModularAdd(words, modulus=modulus, component_id=component_id)
            )
        elif operation == "MODSUB":
            output = self._builder.add_component(ModularSubtract(words, component_id=component_id))
        elif operation == "MODMUL":
            output = self._builder.add_component(ModularMultiply(words, component_id=component_id))
        elif operation == "IDEA":
            output = self._builder.add_component(IDEAMultiply(words, component_id=component_id))
        elif operation in {"ROTATE", "SHIFT"}:
            cls = Rotate if operation == "ROTATE" else Shift
            direction = "right" if parameter >= 0 else "left"
            output = self._builder.add_component(
                cls(words[0], abs(parameter), direction, component_id=component_id)
            )
        else:
            cls = VariableRotate if operation == "ROTATE_BY_VARIABLE_AMOUNT" else VariableShift
            amount = self._builder.pack_bits(operands[1], operands[1].array_type.unit_count)
            direction = "right" if parameter >= 0 else "left"
            output = self._builder.add_component(
                cls(words[0], amount, direction, component_id=component_id)
            )
        if isinstance(output.array_type.domain, Bit):
            return self._record(output, positions)
        return self._record(self._builder.unpack_bits(output), positions)

    def add_xor_component(self, ids, positions, output_bit_size):
        return self._add_word_operation(ids, positions, output_bit_size, "XOR")

    def add_and_component(self, ids, positions, output_bit_size):
        return self._add_word_operation(ids, positions, output_bit_size, "AND")

    def add_or_component(self, ids, positions, output_bit_size):
        return self._add_word_operation(ids, positions, output_bit_size, "OR")

    def add_not_component(self, ids, positions, output_bit_size):
        return self._add_word_operation(ids, positions, output_bit_size, "NOT")

    def add_modadd_component(self, ids, positions, output_bit_size, modulus=None):
        return self._add_word_operation(ids, positions, output_bit_size, "MODADD", modulus=modulus)

    def add_modsub_component(self, ids, positions, output_bit_size, modulus=None):
        return self._add_word_operation(ids, positions, output_bit_size, "MODSUB", modulus=modulus)

    def add_modmul_component(self, ids, positions, output_bit_size, modulus=None):
        return self._add_word_operation(ids, positions, output_bit_size, "MODMUL", modulus=modulus)

    def add_idea_modmul_component(self, ids, positions, output_bit_size, modulus=None):
        return self._add_word_operation(ids, positions, output_bit_size, "IDEA", modulus=modulus)

    def add_rotate_component(self, ids, positions, output_bit_size, parameter):
        return self._add_word_operation(ids, positions, output_bit_size, "ROTATE", parameter)

    def add_shift_component(self, ids, positions, output_bit_size, parameter):
        return self._add_word_operation(ids, positions, output_bit_size, "SHIFT", parameter)

    def add_variable_rotate_component(self, ids, positions, output_bit_size, parameter):
        return self._add_word_operation(
            ids, positions, output_bit_size, "ROTATE_BY_VARIABLE_AMOUNT", parameter
        )

    def add_variable_shift_component(self, ids, positions, output_bit_size, parameter):
        return self._add_word_operation(
            ids, positions, output_bit_size, "SHIFT_BY_VARIABLE_AMOUNT", parameter
        )

    def add_constant_component(self, output_bit_size, value):
        component_id = self._component_id("constant")
        normalized = int(value) & ((1 << output_bit_size) - 1)
        return self._add(
            Constant(
                _bit_type(output_bit_size), bits_from_int(normalized, output_bit_size), component_id
            ),
            [[]],
        )

    def add_sbox_component(self, ids, positions, output_bit_size, description):
        return self._add(
            BitVectorSBox(
                self._selection(ids, positions),
                description,
                self._component_id("sbox"),
                output_bit_size,
            ),
            positions,
        )

    def add_linear_layer_component(self, ids, positions, output_bit_size, description):
        del output_bit_size
        return self._add(
            LinearMap(
                self._selection(ids, positions),
                tuple(zip(*description)),
                self._component_id("linear_layer"),
            ),
            positions,
        )

    @staticmethod
    def _mix_matrix(description):
        coefficients, modulus, word_size = description
        mask = (1 << word_size) - 1

        def multiply(left, right):
            result = 0
            for _ in range(word_size):
                if right & 1:
                    result ^= left
                right >>= 1
                carry = left & (1 << (word_size - 1))
                left = (left << 1) & mask
                if carry:
                    left ^= modulus & mask
            return result

        input_words = len(coefficients[0])
        input_size = input_words * word_size
        output_size = len(coefficients) * word_size
        rows = [[0] * input_size for _ in range(output_size)]
        for column in range(input_size):
            words = [0] * input_words
            words[column // word_size] = 1 << (word_size - 1 - column % word_size)
            transformed = [
                __import__("functools").reduce(
                    int.__xor__, (multiply(c, w) for c, w in zip(row, words)), 0
                )
                for row in coefficients
            ]
            bits = tuple(bit for word in transformed for bit in bits_from_int(word, word_size))
            for row, value in enumerate(bits):
                rows[row][column] = value
        return tuple(tuple(row) for row in rows)

    def add_mix_column_component(self, ids, positions, output_bit_size, description):
        del output_bit_size
        return self._add(
            LinearMap(
                self._selection(ids, positions),
                self._mix_matrix(description),
                self._component_id("mix_column"),
            ),
            positions,
        )

    def add_permutation_component(self, ids, positions, output_bit_size, description, word_size=1):
        del output_bit_size
        expanded = tuple(
            destination * word_size + offset
            for destination in description
            for offset in range(word_size)
        )
        mapping = tuple(expanded.index(index) for index in range(len(expanded)))
        return self._add(
            Permutation(
                self._selection(ids, positions), mapping, self._component_id("permutation")
            ),
            positions,
        )

    def add_word_permutation_component(
        self, ids, positions, output_bit_size, description, word_size
    ):
        return self.add_permutation_component(
            ids, positions, output_bit_size, description, word_size
        )

    def add_reverse_component(self, ids, positions, output_bit_size):
        return self._add(
            Permutation(
                self._selection(ids, positions),
                reversed(range(output_bit_size)),
                self._component_id("reverse"),
            ),
            positions,
        )

    def add_shift_rows_component(
        self, ids, positions, rotation_amount=1, word_bit_size=8, number_of_words=4
    ):
        return self._add_word_operation(
            ids,
            positions,
            word_bit_size * number_of_words,
            "ROTATE",
            rotation_amount * word_bit_size,
        )

    def add_sigma_component(self, ids, positions, output_bit_size, amounts):
        del output_bit_size
        return self._add(
            sigma(self._selection(ids, positions), amounts, self._component_id("sigma")), positions
        )

    def add_theta_keccak_component(self, ids, positions, output_bit_size):
        del output_bit_size
        return self._add(
            keccak_theta(self._selection(ids, positions), self._component_id("theta_keccak")),
            positions,
        )

    def add_theta_xoodoo_component(self, ids, positions, output_bit_size):
        del output_bit_size
        return self._add(
            xoodoo_theta(self._selection(ids, positions), self._component_id("theta_xoodoo")),
            positions,
        )

    def add_theta_gaston_component(self, ids, positions, output_bit_size, amounts):
        del output_bit_size
        return self._add(
            gaston_theta(
                self._selection(ids, positions), amounts, self._component_id("theta_gaston")
            ),
            positions,
        )

    def add_fsr_component(self, ids, positions, output_bit_size, description):
        del output_bit_size
        base_id = self._component_id("fsr")
        source = self._selection(ids, positions)
        registers, bits_inside_word, *clock_values = description
        clocks = clock_values[0] if clock_values else 1
        if bits_inside_word != 1:
            field = BinaryExtensionField(
                bits_inside_word, {8: 0x11D, 16: 0x1002D, 32: 0x100008299}[bits_inside_word]
            )
            source = self._builder.pack_bits(source, bits_inside_word, output_domain=field)
            terms = lambda values: tuple(
                FeedbackTerm(tuple(term[1]), int(term[0])) for term in values
            )
        else:
            terms = lambda values: tuple(FeedbackTerm(tuple(term)) for term in values)
        specifications = tuple(
            FeedbackRegisterSpec(
                int(length), terms(feedback), None if not rest or not rest[0] else terms(rest[0])
            )
            for length, feedback, *rest in registers
        )
        register_size = sum(register[0] for register in registers)
        if bits_inside_word != 1 or source.array_type.unit_count == register_size:
            output = self._builder.add_component(
                FeedbackRegister(source, specifications, clocks=clocks, component_id=base_id)
            )
            if bits_inside_word != 1:
                output = self._builder.unpack_bits(output)
            return self._record(output, positions)

        # Some source descriptions feed key/control bits into nonlinear
        # feedback terms without making them part of the stored registers.
        state = source
        for clock in range(clocks):
            outputs = []
            start = 0
            for length, feedback, *clock_terms in registers:
                feedback_terms = []
                for term_index, term_positions in enumerate(feedback):
                    selected = tuple(state[position] for position in term_positions)
                    if len(selected) == 1:
                        term = selected[0]
                    else:
                        packed = tuple(self._builder.pack_bits(value, 1) for value in selected)
                        term = self._builder.unpack_bits(
                            self._builder.add_component(
                                BitwiseAnd(
                                    packed,
                                    component_id=f"{base_id}_and_{clock}_{start}_{term_index}",
                                ),
                            )
                        )
                    feedback_terms.append(term)
                if len(feedback_terms) == 1:
                    feedback_bit = feedback_terms[0]
                else:
                    packed = tuple(self._builder.pack_bits(value, 1) for value in feedback_terms)
                    feedback_bit = self._builder.unpack_bits(
                        self._builder.add_component(
                            Xor(packed, component_id=f"{base_id}_feedback_{clock}_{start}")
                        )
                    )
                if clock_terms and clock_terms[0]:
                    raise ValueError("conditional registers with external inputs are unsupported")
                outputs.extend(state[position] for position in range(start + 1, start + length))
                outputs.append(feedback_bit)
                start += length
            outputs.append(state[register_size:])
            state = self._builder.join(*outputs)
        output = state[:register_size]
        return self._record(output, positions)

    def _output_component(self, ids, positions, output_bit_size, prefix, final=False):
        source = self._selection(ids, positions)
        if source.array_type.unit_count != output_bit_size:
            raise ValueError("output selection size does not match output_bit_size")
        output = self._builder.view(source)
        state = self._record(output)
        if final:
            self._builder.set_output(output)
        return state

    def add_primitive_output_component(self, ids, positions, output_bit_size):
        return self._output_component(ids, positions, output_bit_size, "primitive_output", True)

    def add_round_output_component(self, ids, positions, output_bit_size):
        return self._output_component(ids, positions, output_bit_size, "round_output")

    def add_round_key_output_component(self, ids, positions, output_bit_size):
        return self._output_component(ids, positions, output_bit_size, "round_key_output")

    def add_intermediate_output_component(self, ids, positions, output_bit_size, output_tag):
        return self._output_component(ids, positions, output_bit_size, output_tag)
