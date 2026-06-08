from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.name_mappings import BLOCK_CIPHER, INPUT_KEY, INPUT_PLAINTEXT

PARAMETERS_CONFIGURATION_LIST = [{"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 32}]
SBOX = [0xA, 0xD, 0xC, 0xF, 0x9, 0xE, 0x1, 0x0, 0x7, 0x2, 0x5, 0x4, 0x3, 0x6, 0xB, 0x8]
M = [
    [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0],
    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
]


class SplightBlockCipher(Cipher):
    """
    Construct an instance of the SplightBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `64`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `128`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `32`); number of rounds of the cipher

    EXAMPLES::

    sage: from claasp.ciphers.block_ciphers.splight_block_cipher import SplightBlockCipher
    sage: splight = SplightBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=32)
    sage: splight.number_of_rounds
    32

    sage: splight.component_from(0, 0).id
    'sbox_0_0'
    """

    def __init__(self, block_bit_size=64, key_bit_size=128, number_of_rounds=32):
        super().__init__(
            family_name="splight",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.block_bit_size = block_bit_size
        self.key_bit_size = key_bit_size

        self.half_size = self.block_bit_size // 2

        states = [
            ComponentState([INPUT_PLAINTEXT], [list(range(0 * self.half_size, 1 * self.half_size))]),
            ComponentState([INPUT_PLAINTEXT], [list(range(1 * self.half_size, 2 * self.half_size))]),
        ]
        keys = [
            ComponentState([INPUT_KEY], [list(range(0 * self.half_size, 1 * self.half_size))]),
            ComponentState([INPUT_KEY], [list(range(1 * self.half_size, 2 * self.half_size))]),
            ComponentState([INPUT_KEY], [list(range(2 * self.half_size, 3 * self.half_size))]),
            ComponentState([INPUT_KEY], [list(range(3 * self.half_size, 4 * self.half_size))]),
        ]

        for round_number in range(number_of_rounds):
            self.add_round()
            keys = self.key_schedule(keys, round_number)
            self.add_round_key_output_component(keys[0].id, keys[0].input_bit_positions, self.half_size)
            new_state = self.sbox(states[0])
            new_state = self.linear_layer(new_state)
            new_state = self.xor_key(new_state, keys[0])
            new_state = self.sbox(new_state)
            new_state = self.xor_state_right(new_state, states[1])
            new_state = self.rotation(new_state)
            if round_number < number_of_rounds - 1:
                self.add_round_output_component(
                    states[0].id + new_state.id,
                    states[0].input_bit_positions + new_state.input_bit_positions,
                    self.block_bit_size,
                )
            else:
                self.add_cipher_output_component(
                    states[0].id + new_state.id,
                    states[0].input_bit_positions + new_state.input_bit_positions,
                    self.block_bit_size,
                )
            states = new_state, states[0]

    def sbox(self, state):
        state_ids = [""] * 8
        for i in range(8):
            self.add_sbox_component(state.id, [state.input_bit_positions[0][4 * i : 4 * (i + 1)]], 4, SBOX)
            state_ids[i] = self.get_current_component_id()

        return ComponentState(state_ids, [list(range(4)) for _ in range(8)])

    def linear_layer(self, state):
        self.add_linear_layer_component(state.id[:4], state.input_bit_positions[:4], self.half_size // 2, M)
        state_id_col0 = self.get_current_component_id()
        self.add_linear_layer_component(state.id[4:], state.input_bit_positions[4:], self.half_size // 2, M)
        state_id_col1 = self.get_current_component_id()

        return ComponentState([state_id_col0, state_id_col1], [list(range(self.half_size // 2)) for _ in range(2)])

    def xor_key(self, state, key):
        self.add_xor_component(state.id + key.id, state.input_bit_positions + key.input_bit_positions, self.half_size)

        return ComponentState([self.get_current_component_id()], [list(range(self.half_size))])

    def xor_state_right(self, state_left, state_right):
        self.add_xor_component(
            state_left.id + state_right.id,
            state_left.input_bit_positions + state_right.input_bit_positions,
            self.half_size,
        )

        return ComponentState([self.get_current_component_id()], [list(range(self.half_size))])

    def rotation(self, state):
        self.add_rotate_component(state.id, state.input_bit_positions, self.half_size, -8)

        return ComponentState([self.get_current_component_id()], [list(range(self.half_size))])

    def key_schedule(self, keys, round_number):
        self.add_sbox_component(keys[0].id, [keys[0].input_bit_positions[0][12:16]], 4, SBOX)
        key_sbox0_id = self.get_current_component_id()
        self.add_sbox_component(keys[0].id, [keys[0].input_bit_positions[0][28:32]], 4, SBOX)
        key_sbox1_id = self.get_current_component_id()
        self.add_rotate_component(
            keys[0].id + [key_sbox0_id] + keys[0].id + [key_sbox1_id],
            [keys[0].input_bit_positions[0][:12]]
            + [list(range(4))]
            + [keys[0].input_bit_positions[0][16:28]]
            + [list(range(4))],
            self.half_size,
            -4,
        )
        key_rotate_id = self.get_current_component_id()
        self.add_xor_component(
            [key_rotate_id] + keys[1].id, [list(range(self.half_size))] + keys[1].input_bit_positions, self.half_size
        )
        xor_key = ComponentState([self.get_current_component_id()], [list(range(self.half_size))])
        self.add_constant_component(self.half_size, round_number)
        constant_id = self.get_current_component_id()
        self.add_xor_component(
            xor_key.id + [constant_id], xor_key.input_bit_positions + [list(range(self.half_size))], self.half_size
        )
        round_key = ComponentState([self.get_current_component_id()], [list(range(self.half_size))])

        return round_key, keys[2], keys[3], keys[0]
