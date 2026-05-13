from claasp.cipher import Cipher
from claasp.name_mappings import BLOCK_CIPHER, INPUT_PLAINTEXT, INPUT_KEY


class Heys_SPN(Cipher):
    """
    Construct an instance of the Heys toy SPN class.

    INPUT:

    - ``block_bit_size`` -- **integer** (default: `16`); cipher input and output block bit size of the cipher
    - ``self.key_bit_size`` -- **integer** (default: `80`); cipher key bit size of the cipher
    - ``number_of_rounds`` -- **integer** (default: `4`); number of rounds of the cipher.

    EXAMPLES::

        sage: from claasp.ciphers.toys.heys_spn_cipher import Heys_SPN
        sage: cipher = Heys_SPN()
        sage: hex(cipher.evaluate([0x1234, 0x0123456789ABCDEF0123])) == "0xe582"
        True
    """

    def __init__(
        self,
        block_bit_size=16,
        key_bit_size=80,  # split into 5 round keys of 16 bits
        number_of_rounds=4
    ):
        super().__init__(
            family_name="heys_toy_cipher",
            cipher_type=BLOCK_CIPHER,
            cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
            cipher_inputs_bit_size=[block_bit_size, key_bit_size],
            cipher_output_bit_size=block_bit_size,
        )

        self.sbox_bit_size = 4
        self.number_of_sboxes = block_bit_size // self.sbox_bit_size
        sbox = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
              0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
        permutation = [0,4,8,12, 1,5,9,13, 2,6,10,14, 3,7,11,15]

        state = INPUT_PLAINTEXT

        # --- key schedule: split key into K1..K5 ---
        round_keys = []
        for r in range(number_of_rounds + 1):
            if r < number_of_rounds:
                self.add_round()
            rk = self.add_round_key_output_component(
                [INPUT_KEY],
                [[i + r * block_bit_size for i in range(block_bit_size)]],
                block_bit_size,
            )
            round_keys.append(rk.id)

        for r in range(number_of_rounds):
            # --- XOR with round key ---
            xor = self.add_xor_component(
                [state, round_keys[r]],
                [list(range(block_bit_size)), list(range(block_bit_size))],
                block_bit_size,
            )

            # --- S-box layer ---
            sbox_ids = []
            for i in range(self.number_of_sboxes):
                comp = self.add_sbox_component(
                    [xor.id],
                    [[i * 4 + j for j in range(4)]],
                    4,
                    sbox,
                )
                sbox_ids.append(comp.id)

            # --- permutation layer (skip in last round) ---
            if r < number_of_rounds - 1:
                state = self.add_permutation_component(
                    sbox_ids,
                    [list(range(4)) for _ in range(self.number_of_sboxes)],
                    block_bit_size,
                    permutation,
                ).id
            else:
                state = sbox_ids

            self.add_round_output_component(
                sbox_ids if isinstance(state, list) else [state],
                [list(range(4)) for _ in range(self.number_of_sboxes)] if isinstance(state, list)
                else [list(range(block_bit_size))],
                block_bit_size,
            )

        # --- final key mixing ---
        final_xor_inputs = (state if isinstance(state, list) else [state]) + [round_keys[number_of_rounds]]
        final_xor_input_positions = ([list(range(4)) for _ in range(self.number_of_sboxes)] if isinstance(state, list)
                                     else [list(range(block_bit_size))]) + [list(range(block_bit_size))]

        final_xor = self.add_xor_component(
            final_xor_inputs,
            final_xor_input_positions,
            block_bit_size,
        )

        self.add_cipher_output_component(
            [final_xor.id],
            [list(range(block_bit_size))],
            block_bit_size,
        )