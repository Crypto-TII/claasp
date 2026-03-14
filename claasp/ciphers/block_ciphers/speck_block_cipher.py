# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************


from claasp.cipher import Cipher
from claasp.DTOs.component_state import ComponentState
from claasp.utils.utils import get_number_of_rounds_from
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY

PARAMETERS_CONFIGURATION_LIST = [
    {"block_bit_size": 32, "key_bit_size": 64, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 72, "number_of_rounds": 22},
    {"block_bit_size": 48, "key_bit_size": 96, "number_of_rounds": 23},
    {"block_bit_size": 64, "key_bit_size": 96, "number_of_rounds": 26},
    {"block_bit_size": 64, "key_bit_size": 128, "number_of_rounds": 27},
    {"block_bit_size": 96, "key_bit_size": 96, "number_of_rounds": 28},
    {"block_bit_size": 96, "key_bit_size": 144, "number_of_rounds": 29},
    {"block_bit_size": 128, "key_bit_size": 128, "number_of_rounds": 32},
    {"block_bit_size": 128, "key_bit_size": 192, "number_of_rounds": 33},
    {"block_bit_size": 128, "key_bit_size": 256, "number_of_rounds": 34},
]


class SpeckBlockCipher(Cipher):
    """
    Construct an instance of the SpeckBlockCipher class.

    This class is used to store compact representations of a cipher, used to generate the corresponding cipher.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `32`); cipher input and output block bit size of the cipher
    - ``key_bit_size`` -- **integer** (default: `64`); cipher key bit size of the cipher
    - ``rotation_alpha`` -- **integer** (default: `None`)
    - ``rotation_beta`` -- **integer** (default: `None`)
    - ``number_of_rounds`` -- **integer** (default: `0`); number of rounds of the cipher. The cipher uses the
      corresponding amount given the other parameters (if available) when number_of_rounds is 0

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
        sage: speck = SpeckBlockCipher()
        sage: speck.number_of_rounds
        22

        sage: speck.component_from(0, 0).id
        'rot_0_0'
    """

    def __init__(self, block_bit_size=32, key_bit_size=64, rotation_alpha=None, rotation_beta=None, number_of_rounds=0):
        self.word_size = int(block_bit_size / 2)
        if self.word_size == 16:
            self.rot_alpha = 7 if rotation_alpha is None else rotation_alpha
            self.rot_beta = 2 if rotation_beta is None else rotation_beta
        else:
            self.rot_alpha = 8 if rotation_alpha is None else rotation_alpha
            self.rot_beta = 3 if rotation_beta is None else rotation_beta

        super().__init__(
            family_name="speck",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        key_schedule, left_schedule = self.key_initialization(key_bit_size)
        p1, p2 = self.round_initialization()

        # round function
        n = get_number_of_rounds_from(block_bit_size, key_bit_size, number_of_rounds, PARAMETERS_CONFIGURATION_LIST)

        for round_number in range(n):
            self.add_round()

            # key schedule
            if round_number != 0:
                # constant r-1
                self.add_constant_component(self.word_size, round_number - 1)
                const_r = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])
                key_left, key_right = self.round_function(key_left, key_right, const_r)
                left_schedule.append(key_left)
                key_schedule.append(key_right)

            # round parameter
            key_left = left_schedule[round_number]
            key_right = key_schedule[round_number]

            # round encryption
            p1, p2 = self.round_function(p1, p2, key_right)
            self.add_round_key_output_component(key_right.id, key_right.input_bit_positions, self.word_size)
            self.add_output_component(block_bit_size, n, p1, p2, round_number)

    def add_output_component(self, block_bit_size, n, p1, p2, round_number):
        if round_number == n - 1:
            self.add_cipher_output_component(
                p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, block_bit_size
            )
        else:
            self.add_round_output_component(
                p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, block_bit_size
            )

    def evaluate_gpu_cupy(self, cipher_input, evaluate_api=False):
        """
        Return the output of Speck-32/64 for multiple inputs using CuPy.

        INPUT:

        - ``cipher_input`` -- **list**; block cipher inputs
        - ``evaluate_api`` -- **boolean** (default: `False`); if set to True, takes integer inputs and returns integer
          outputs
        """
        import importlib
        import numpy as np

        if self.inputs_bit_size != [32, 64] or self.output_bit_size != 32:
            raise NotImplementedError("evaluate_gpu_cupy is implemented only for Speck-32/64.")

        try:
            cp = importlib.import_module("cupy")
        except ImportError as exc:
            raise ImportError("evaluate_gpu_cupy requires cupy.") from exc

        try:
            if cp.cuda.runtime.getDeviceCount() == 0:
                raise RuntimeError("No GPUs available")
            cp.cuda.Device(0).use()
        except Exception as exc:
            raise RuntimeError("CUDA is not available.") from exc

        if evaluate_api:
            from claasp.cipher_modules.generic_functions_vectorized_byte import cipher_inputs_to_evaluate_vectorized_inputs
            cipher_input = cipher_inputs_to_evaluate_vectorized_inputs(cipher_input, self.inputs_bit_size)

        plaintext = np.asarray(cipher_input[0], dtype=np.uint8)
        key = np.asarray(cipher_input[1], dtype=np.uint8)

        if plaintext.shape[0] != 4 or key.shape[0] != 8:
            raise ValueError("evaluate_gpu_cupy expects 4 plaintext rows and 8 key rows.")
        if plaintext.shape[1] != key.shape[1]:
            raise ValueError("evaluate_gpu_cupy expects the same number of plaintext and key samples.")

        number_of_samples = plaintext.shape[1]
        if number_of_samples == 0:
            outputs = [np.empty((0, 4), dtype=np.uint8)]
            if evaluate_api:
                from claasp.cipher_modules.generic_functions_vectorized_byte import evaluate_vectorized_outputs_to_integers
                return evaluate_vectorized_outputs_to_integers(outputs, self.output_bit_size)
            return outputs

        plaintext_words = np.empty((2, number_of_samples), dtype=np.uint16)
        plaintext_words[0] = (plaintext[0].astype(np.uint16) << 8) | plaintext[1].astype(np.uint16)
        plaintext_words[1] = (plaintext[2].astype(np.uint16) << 8) | plaintext[3].astype(np.uint16)

        key_words = np.empty((4, number_of_samples), dtype=np.uint16)
        key_words[0] = (key[0].astype(np.uint16) << 8) | key[1].astype(np.uint16)
        key_words[1] = (key[2].astype(np.uint16) << 8) | key[3].astype(np.uint16)
        key_words[2] = (key[4].astype(np.uint16) << 8) | key[5].astype(np.uint16)
        key_words[3] = (key[6].astype(np.uint16) << 8) | key[7].astype(np.uint16)

        device_plaintext_words = cp.asarray(plaintext_words)
        device_key_words = cp.asarray(key_words)

        left_word = device_plaintext_words[0]
        right_word = device_plaintext_words[1]

        l2 = device_key_words[0]
        l1 = device_key_words[1]
        l0 = device_key_words[2]
        round_key = device_key_words[3]

        mask = cp.uint16(0xFFFF)

        try:
            for round_number in range(self.number_of_rounds):
                left_word = ((left_word >> 7) | (left_word << 9)) & mask
                left_word = (left_word + right_word) & mask
                left_word ^= round_key

                right_word = ((right_word << 2) | (right_word >> 14)) & mask
                right_word ^= left_word

                if round_number < self.number_of_rounds - 1:
                    new_l_word = ((l0 >> 7) | (l0 << 9)) & mask
                    new_l_word = (new_l_word + round_key) & mask
                    new_l_word ^= cp.uint16(round_number)

                    round_key = ((round_key << 2) | (round_key >> 14)) & mask
                    round_key ^= new_l_word

                    l0 = l1
                    l1 = l2
                    l2 = new_l_word

            cp.cuda.runtime.deviceSynchronize()
        except Exception as exc:
            raise RuntimeError(f"CUDA execution failed: {exc}") from exc

        ciphertext_words = cp.asnumpy(cp.stack((left_word, right_word)))
        ciphertext = np.empty((number_of_samples, 4), dtype=np.uint8)
        ciphertext[:, 0] = np.uint8(ciphertext_words[0] >> 8)
        ciphertext[:, 1] = np.uint8(ciphertext_words[0] & 0xFF)
        ciphertext[:, 2] = np.uint8(ciphertext_words[1] >> 8)
        ciphertext[:, 3] = np.uint8(ciphertext_words[1] & 0xFF)

        outputs = [ciphertext]
        if evaluate_api:
            from claasp.cipher_modules.generic_functions_vectorized_byte import evaluate_vectorized_outputs_to_integers
            return evaluate_vectorized_outputs_to_integers(outputs, self.output_bit_size)

        return outputs

    def key_initialization(self, key_bit_size):
        l_schedule = []
        key_schedule = []
        for i in range(0, key_bit_size - self.word_size, self.word_size):
            l_component = ComponentState([INPUT_KEY], [list(range(i, i + self.word_size))])
            l_schedule.append(l_component)
        l_schedule.reverse()
        key_component = ComponentState([INPUT_KEY], [[(key_bit_size - j) for j in range(self.word_size, 0, -1)]])
        key_schedule.append(key_component)

        return key_schedule, l_schedule

    def round_function(self, p1, p2, key):
        # p1 >>> alpha
        self.add_rotate_component(p1.id, p1.input_bit_positions, self.word_size, self.rot_alpha)
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        # p1 = modadd(p1, p2)
        self.add_MODADD_component(p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, self.word_size)
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        # p1 = p1 ^ round_key
        self.add_XOR_component(p1.id + key.id, p1.input_bit_positions + key.input_bit_positions, self.word_size)
        p1 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        # p2 <<< beta
        self.add_rotate_component(p2.id, p2.input_bit_positions, self.word_size, -self.rot_beta)
        p2 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        # p2 = p1 ^ p2
        self.add_XOR_component(p1.id + p2.id, p1.input_bit_positions + p2.input_bit_positions, self.word_size)
        p2 = ComponentState([self.get_current_component_id()], [list(range(self.word_size))])

        return p1, p2

    def round_initialization(self):
        p1 = ComponentState([INPUT_PLAINTEXT], [list(range(self.word_size))])
        p2 = ComponentState([INPUT_PLAINTEXT], [[(i + self.word_size) for i in range(self.word_size)]])

        return p1, p2
