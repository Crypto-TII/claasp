from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_PLAINTEXT, INPUT_KEY
from math import ceil
from sage.symbolic.constants import e, golden_ratio

PARAMETERS_CONFIGURATION_LIST = [{'word_size': 32, 'key_size': 128, 'number_of_rounds': 20}]


def compute_magic_constants(word_size):

    Pw = int((e - 2) * (2 ** word_size))
    Qw = int((golden_ratio - 1) * (2 ** word_size))

    if Pw % 2 == 0:
        Pw = Pw + 1

    if Qw % 2 == 0:
        Qw = Qw + 1

    return Pw, Qw


class RC5BlockCipher(Cipher):

    def __init__(self, number_of_rounds=12, word_size=32, key_size=128):

        self.CIPHER_BLOCK_SIZE = 2 * word_size
        self.KEY_BLOCK_SIZE = key_size
        self.NROUNDS = number_of_rounds

        self.u = int(word_size / 8)
        self.t = 2 * (number_of_rounds + 1)
        self.c = int(ceil(self.KEY_BLOCK_SIZE / (8 * self.u)))

        if self.c == 0:
            self.c = 1

        super().__init__(family_name="rc5_block_cipher",
                         cipher_type="block_cipher",
                         cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
                         cipher_inputs_bit_size=[self.KEY_BLOCK_SIZE, self.CIPHER_BLOCK_SIZE],
                         cipher_output_bit_size=self.CIPHER_BLOCK_SIZE)

        # Magic constants are defined by the choice of word size. since the word size can be any value from 0 to 2040 bits,
        # Pw = Odd((e-2) * 2^w)
        # Qw = Pdd((phi - 1) * 2^w)
        #
        # Odd(x) is the closest odd integer to x, rounded up. phi is the golden ratio, w is the word_size in bytes.

        Pw, Qw = compute_magic_constants(word_size)

        # First magic constant, in function of word size

        # Key Initialization

        self.add_round()

        # we use a dummy component to generate constant components representing the split parts of the key after the first step of the key expansion

        dummy_component = self.add_constant_component(word_size, 0x0)

        # split bit positions orders to adapt to little endian standard

        little_endian_order = [[i for i in range(self.KEY_BLOCK_SIZE)][x:x + 8] for x in
                               range(0, self.KEY_BLOCK_SIZE, 8)][::-1]

        L = []

        # Key Expansion

        # Step 1 - store the key bytes in an array in groups of 4, using little endian order

        i = 0


        if self.c == 1:
            L.append(dummy_component)
        else:
            for i in range(self.c):
                    if i == self.c - 1:
                        block = (i+1) * self.u - len(little_endian_order)
                    else :
                        block = self.u

                    L.append(self.add_XOR_component(
                        [dummy_component.id] + [INPUT_KEY for _ in range(min(self.u, len(little_endian_order) - i * self.u ))],
                        [[i for i in range(block * 8 )]] + [little_endian_order[-j-1] for j in range(i * self.u, min((i + 1) * self.u, len(little_endian_order)))][::-1],
                        word_size))



        # Step 2 - initialize the S vector

        S = [self.add_constant_component(word_size, Pw)]
        S_value = [Pw]
        for i in range(1, self.t):
            S_value.append((S_value[i - 1] + Qw) % (2 ** word_size))

            S.append(self.add_constant_component(word_size, S_value[i]))


        # Step 3 - Mix in the secret key

        i = 0
        j = 0
        A = dummy_component
        B = dummy_component




        for n in range(3 * max(self.t, self.c)):
            # A = (S[i] + A + B) shift 3


            A_modadd_B = self.add_MODADD_component([A.id, B.id],
                                                   [[i for i in range(word_size)] for _ in range(2)],
                                                   word_size)

            Si_modadd_A_modadd_B = self.add_MODADD_component([S[i].id, A_modadd_B.id],
                                                             [[i for i in range(word_size)] for _ in range(2)],
                                                             word_size)

            S[i] = self.add_rotate_component([Si_modadd_A_modadd_B.id],
                                             [[i for i in range(word_size)]],
                                             word_size,
                                             -3)

            A = S[i]


            # B = (key_array[j] + A + B) shift (A + B)




            B_modadd_A = self.add_MODADD_component([B.id, A.id],
                                                   [[i for i in range(word_size)] for _ in range(2)],
                                                   word_size)

            Lj_modadd_A_modadd_B = self.add_MODADD_component([L[j].id, B_modadd_A.id],
                                                             [[i for i in range(word_size)] for _ in range(2)],
                                                             word_size)


            L[j] = self.add_variable_rotate_component([Lj_modadd_A_modadd_B.id, B_modadd_A.id],
                                                      [[i for i in range(word_size)] for _ in range(2)],
                                                      word_size,
                                                      -1)

            B = L[j]

            i = (i + 1) % self.t
            j = (j + 1) % self.c

        # Encryption

        # Round 1

        A = dummy_component
        B = dummy_component

        little_endian_order_pt = [[i for i in range(2 * word_size)][x:x + 8] for x in range(0, 2 * word_size, 8)][::-1]

        A = self.add_XOR_component([INPUT_PLAINTEXT for _ in range(int(word_size / 8))] + [dummy_component.id],
                                   [little_endian_order_pt[j] for j in range(int(word_size / 8))] + [
                                       [i for i in range(word_size)]],
                                   word_size)

        B = self.add_XOR_component([INPUT_PLAINTEXT for _ in range(int(word_size / 8))] + [dummy_component.id],
                                   [little_endian_order_pt[j] for j in
                                    range(int(word_size / 8), int(word_size / 4))] + [[i for i in range(word_size)]],
                                   word_size)

        S0_modadd = self.add_MODADD_component([A.id, S[0].id],
                                              [[i for i in range(word_size)] for _ in range(2)],
                                              word_size)

        S1_modadd = self.add_MODADD_component([B.id, S[0].id],
                                              [[i for i in range(word_size)] for _ in range(2)],
                                              word_size)

        A = S0_modadd
        B = S1_modadd


        # ----

        for i in range(number_of_rounds):

            A_xor_B = self.add_XOR_component([A.id, B.id],
                                             [[i for i in range(word_size)] for _ in range(2)],
                                             word_size)

            B_shift = self.add_variable_rotate_component([A_xor_B.id, B.id],
                                                         [[i for i in range(word_size)] for _ in range(2)],
                                                         word_size,
                                                         -1)
            S_2i_modadd = self.add_MODADD_component([B_shift.id, S[2 * i].id],
                                                    [[i for i in range(word_size)] for _ in range(2)],
                                                    word_size)

            A = S_2i_modadd

            A_xor_B = self.add_XOR_component([A.id, B.id],
                                             [[i for i in range(word_size)] for _ in range(2)],
                                             word_size)

            A_shift = self.add_variable_rotate_component([A_xor_B.id, A.id],
                                                         [[i for i in range(word_size)] for _ in range(2)],
                                                         word_size,
                                                         -1)

            S_2i_1_modadd = self.add_MODADD_component([A_shift.id, S[2 * i + 1].id],
                                                      [[i for i in range(word_size)] for _ in range(2)],
                                                      word_size)

            B = S_2i_1_modadd

            if i != number_of_rounds - 1:
                self.add_round()

        self.add_cipher_output_component([A.id, B.id],
                                         [[i for i in range(word_size)] for _ in range(2)],
                                         2 * word_size)
