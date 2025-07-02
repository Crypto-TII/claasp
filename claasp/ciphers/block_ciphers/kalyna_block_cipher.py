from claasp.cipher import Cipher
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT
import numpy as np

PARAMETERS_CONFIGURATION_LIST = [
    {"word_size": 8, "state_size": 4, "number_of_rounds": 10}
]


class KalynaBlockCipher(Cipher):
    """EXAMPLES::

    sage: from claasp.ciphers.block_ciphers.kalyna_block_cipher import KalynaBlockCipher
    sage: kalyna = KalynaBlockCipher()
    sage: key = 0x0F0E0D0C0B0A09080706050403020100 #0x000102030405060708090A0B0C0D0E0F
    sage: plaintext =0x101112131415161718191A1B1C1D1E1F
    sage: kalyna.evaluate([key, plaintext], verbosity = 1)

    sage: from claasp.ciphers.block_ciphers.kalyna_block_cipher import KalynaBlockCipher
    sage: kalyna = KalynaBlockCipher()
    sage: key = 0x000102030405060708090A0B0C0D0E0F
    sage: plaintext =0x101112131415161718191A1B1C1D1E1F
    sage: ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    sage: kalyna.evaluate([key, plaintext]) == ciphertext
    """

    def __init__(self, number_of_rounds=10, word_size=8, state_size=8):
        # cipher dictionary initialize
        self.CIPHER_BLOCK_SIZE = 128
        self.KEY_BLOCK_SIZE = 128
        self.NROUNDS = number_of_rounds
        self.NUM_ROWS = state_size
        self.SBOX_BIT_SIZE = word_size
        self.ROW_SIZE = state_size * word_size
        self.round_keys = {}

        super().__init__(
            family_name="kalyna_block_cipher",
            cipher_type="block_cipher",
            cipher_inputs=[INPUT_KEY, INPUT_PLAINTEXT],
            cipher_inputs_bit_size=[self.KEY_BLOCK_SIZE, self.CIPHER_BLOCK_SIZE],
            cipher_output_bit_size=self.CIPHER_BLOCK_SIZE,
        )
        pi0_e = [
            0xA8,
            0x43,
            0x5F,
            0x06,
            0x6B,
            0x75,
            0x6C,
            0x59,
            0x71,
            0xDF,
            0x87,
            0x95,
            0x17,
            0xF0,
            0xD8,
            0x09,
            0x6D,
            0xF3,
            0x1D,
            0xCB,
            0xC9,
            0x4D,
            0x2C,
            0xAF,
            0x79,
            0xE0,
            0x97,
            0xFD,
            0x6F,
            0x4B,
            0x45,
            0x39,
            0x3E,
            0xDD,
            0xA3,
            0x4F,
            0xB4,
            0xB6,
            0x9A,
            0x0E,
            0x1F,
            0xBF,
            0x15,
            0xE1,
            0x49,
            0xD2,
            0x93,
            0xC6,
            0x92,
            0x72,
            0x9E,
            0x61,
            0xD1,
            0x63,
            0xFA,
            0xEE,
            0xF4,
            0x19,
            0xD5,
            0xAD,
            0x58,
            0xA4,
            0xBB,
            0xA1,
            0xDC,
            0xF2,
            0x83,
            0x37,
            0x42,
            0xE4,
            0x7A,
            0x32,
            0x9C,
            0xCC,
            0xAB,
            0x4A,
            0x8F,
            0x6E,
            0x04,
            0x27,
            0x2E,
            0xE7,
            0xE2,
            0x5A,
            0x96,
            0x16,
            0x23,
            0x2B,
            0xC2,
            0x65,
            0x66,
            0x0F,
            0xBC,
            0xA9,
            0x47,
            0x41,
            0x34,
            0x48,
            0xFC,
            0xB7,
            0x6A,
            0x88,
            0xA5,
            0x53,
            0x86,
            0xF9,
            0x5B,
            0xDB,
            0x38,
            0x7B,
            0xC3,
            0x1E,
            0x22,
            0x33,
            0x24,
            0x28,
            0x36,
            0xC7,
            0xB2,
            0x3B,
            0x8E,
            0x77,
            0xBA,
            0xF5,
            0x14,
            0x9F,
            0x08,
            0x55,
            0x9B,
            0x4C,
            0xFE,
            0x60,
            0x5C,
            0xDA,
            0x18,
            0x46,
            0xCD,
            0x7D,
            0x21,
            0xB0,
            0x3F,
            0x1B,
            0x89,
            0xFF,
            0xEB,
            0x84,
            0x69,
            0x3A,
            0x9D,
            0xD7,
            0xD3,
            0x70,
            0x67,
            0x40,
            0xB5,
            0xDE,
            0x5D,
            0x30,
            0x91,
            0xB1,
            0x78,
            0x11,
            0x01,
            0xE5,
            0x00,
            0x68,
            0x98,
            0xA0,
            0xC5,
            0x02,
            0xA6,
            0x74,
            0x2D,
            0x0B,
            0xA2,
            0x76,
            0xB3,
            0xBE,
            0xCE,
            0xBD,
            0xAE,
            0xE9,
            0x8A,
            0x31,
            0x1C,
            0xEC,
            0xF1,
            0x99,
            0x94,
            0xAA,
            0xF6,
            0x26,
            0x2F,
            0xEF,
            0xE8,
            0x8C,
            0x35,
            0x03,
            0xD4,
            0x7F,
            0xFB,
            0x05,
            0xC1,
            0x5E,
            0x90,
            0x20,
            0x3D,
            0x82,
            0xF7,
            0xEA,
            0x0A,
            0x0D,
            0x7E,
            0xF8,
            0x50,
            0x1A,
            0xC4,
            0x07,
            0x57,
            0xB8,
            0x3C,
            0x62,
            0xE3,
            0xC8,
            0xAC,
            0x52,
            0x64,
            0x10,
            0xD0,
            0xD9,
            0x13,
            0x0C,
            0x12,
            0x29,
            0x51,
            0xB9,
            0xCF,
            0xD6,
            0x73,
            0x8D,
            0x81,
            0x54,
            0xC0,
            0xED,
            0x4E,
            0x44,
            0xA7,
            0x2A,
            0x85,
            0x25,
            0xE6,
            0xCA,
            0x7C,
            0x8B,
            0x56,
            0x80,
        ]

        pi1_e = [
            0xCE,
            0xBB,
            0xEB,
            0x92,
            0xEA,
            0xCB,
            0x13,
            0xC1,
            0xE9,
            0x3A,
            0xD6,
            0xB2,
            0xD2,
            0x90,
            0x17,
            0xF8,
            0x42,
            0x15,
            0x56,
            0xB4,
            0x65,
            0x1C,
            0x88,
            0x43,
            0xC5,
            0x5C,
            0x36,
            0xBA,
            0xF5,
            0x57,
            0x67,
            0x8D,
            0x31,
            0xF6,
            0x64,
            0x58,
            0x9E,
            0xF4,
            0x22,
            0xAA,
            0x75,
            0x0F,
            0x02,
            0xB1,
            0xDF,
            0x6D,
            0x73,
            0x4D,
            0x7C,
            0x26,
            0x2E,
            0xF7,
            0x08,
            0x5D,
            0x44,
            0x3E,
            0x9F,
            0x14,
            0xC8,
            0xAE,
            0x54,
            0x10,
            0xD8,
            0xBC,
            0x1A,
            0x6B,
            0x69,
            0xF3,
            0xBD,
            0x33,
            0xAB,
            0xFA,
            0xD1,
            0x9B,
            0x68,
            0x4E,
            0x16,
            0x95,
            0x91,
            0xEE,
            0x4C,
            0x63,
            0x8E,
            0x5B,
            0xCC,
            0x3C,
            0x19,
            0xA1,
            0x81,
            0x49,
            0x7B,
            0xD9,
            0x6F,
            0x37,
            0x60,
            0xCA,
            0xE7,
            0x2B,
            0x48,
            0xFD,
            0x96,
            0x45,
            0xFC,
            0x41,
            0x12,
            0x0D,
            0x79,
            0xE5,
            0x89,
            0x8C,
            0xE3,
            0x20,
            0x30,
            0xDC,
            0xB7,
            0x6C,
            0x4A,
            0xB5,
            0x3F,
            0x97,
            0xD4,
            0x62,
            0x2D,
            0x06,
            0xA4,
            0xA5,
            0x83,
            0x5F,
            0x2A,
            0xDA,
            0xC9,
            0x00,
            0x7E,
            0xA2,
            0x55,
            0xBF,
            0x11,
            0xD5,
            0x9C,
            0xCF,
            0x0E,
            0x0A,
            0x3D,
            0x51,
            0x7D,
            0x93,
            0x1B,
            0xFE,
            0xC4,
            0x47,
            0x09,
            0x86,
            0x0B,
            0x8F,
            0x9D,
            0x6A,
            0x07,
            0xB9,
            0xB0,
            0x98,
            0x18,
            0x32,
            0x71,
            0x4B,
            0xEF,
            0x3B,
            0x70,
            0xA0,
            0xE4,
            0x40,
            0xFF,
            0xC3,
            0xA9,
            0xE6,
            0x78,
            0xF9,
            0x8B,
            0x46,
            0x80,
            0x1E,
            0x38,
            0xE1,
            0xB8,
            0xA8,
            0xE0,
            0x0C,
            0x23,
            0x76,
            0x1D,
            0x25,
            0x24,
            0x05,
            0xF1,
            0x6E,
            0x94,
            0x28,
            0x9A,
            0x84,
            0xE8,
            0xA3,
            0x4F,
            0x77,
            0xD3,
            0x85,
            0xE2,
            0x52,
            0xF2,
            0x82,
            0x50,
            0x7A,
            0x2F,
            0x74,
            0x53,
            0xB3,
            0x61,
            0xAF,
            0x39,
            0x35,
            0xDE,
            0xCD,
            0x1F,
            0x99,
            0xAC,
            0xAD,
            0x72,
            0x2C,
            0xDD,
            0xD0,
            0x87,
            0xBE,
            0x5E,
            0xA6,
            0xEC,
            0x04,
            0xC6,
            0x03,
            0x34,
            0xFB,
            0xDB,
            0x59,
            0xB6,
            0xC2,
            0x01,
            0xF0,
            0x5A,
            0xED,
            0xA7,
            0x66,
            0x21,
            0x7F,
            0x8A,
            0x27,
            0xC7,
            0xC0,
            0x29,
            0xD7,
        ]

        pi2_e = [
            0x93,
            0xD9,
            0x9A,
            0xB5,
            0x98,
            0x22,
            0x45,
            0xFC,
            0xBA,
            0x6A,
            0xDF,
            0x02,
            0x9F,
            0xDC,
            0x51,
            0x59,
            0x4A,
            0x17,
            0x2B,
            0xC2,
            0x94,
            0xF4,
            0xBB,
            0xA3,
            0x62,
            0xE4,
            0x71,
            0xD4,
            0xCD,
            0x70,
            0x16,
            0xE1,
            0x49,
            0x3C,
            0xC0,
            0xD8,
            0x5C,
            0x9B,
            0xAD,
            0x85,
            0x53,
            0xA1,
            0x7A,
            0xC8,
            0x2D,
            0xE0,
            0xD1,
            0x72,
            0xA6,
            0x2C,
            0xC4,
            0xE3,
            0x76,
            0x78,
            0xB7,
            0xB4,
            0x09,
            0x3B,
            0x0E,
            0x41,
            0x4C,
            0xDE,
            0xB2,
            0x90,
            0x25,
            0xA5,
            0xD7,
            0x03,
            0x11,
            0x00,
            0xC3,
            0x2E,
            0x92,
            0xEF,
            0x4E,
            0x12,
            0x9D,
            0x7D,
            0xCB,
            0x35,
            0x10,
            0xD5,
            0x4F,
            0x9E,
            0x4D,
            0xA9,
            0x55,
            0xC6,
            0xD0,
            0x7B,
            0x18,
            0x97,
            0xD3,
            0x36,
            0xE6,
            0x48,
            0x56,
            0x81,
            0x8F,
            0x77,
            0xCC,
            0x9C,
            0xB9,
            0xE2,
            0xAC,
            0xB8,
            0x2F,
            0x15,
            0xA4,
            0x7C,
            0xDA,
            0x38,
            0x1E,
            0x0B,
            0x05,
            0xD6,
            0x14,
            0x6E,
            0x6C,
            0x7E,
            0x66,
            0xFD,
            0xB1,
            0xE5,
            0x60,
            0xAF,
            0x5E,
            0x33,
            0x87,
            0xC9,
            0xF0,
            0x5D,
            0x6D,
            0x3F,
            0x88,
            0x8D,
            0xC7,
            0xF7,
            0x1D,
            0xE9,
            0xEC,
            0xED,
            0x80,
            0x29,
            0x27,
            0xCF,
            0x99,
            0xA8,
            0x50,
            0x0F,
            0x37,
            0x24,
            0x28,
            0x30,
            0x95,
            0xD2,
            0x3E,
            0x5B,
            0x40,
            0x83,
            0xB3,
            0x69,
            0x57,
            0x1F,
            0x07,
            0x1C,
            0x8A,
            0xBC,
            0x20,
            0xEB,
            0xCE,
            0x8E,
            0xAB,
            0xEE,
            0x31,
            0xA2,
            0x73,
            0xF9,
            0xCA,
            0x3A,
            0x1A,
            0xFB,
            0x0D,
            0xC1,
            0xFE,
            0xFA,
            0xF2,
            0x6F,
            0xBD,
            0x96,
            0xDD,
            0x43,
            0x52,
            0xB6,
            0x08,
            0xF3,
            0xAE,
            0xBE,
            0x19,
            0x89,
            0x32,
            0x26,
            0xB0,
            0xEA,
            0x4B,
            0x64,
            0x84,
            0x82,
            0x6B,
            0xF5,
            0x79,
            0xBF,
            0x01,
            0x5F,
            0x75,
            0x63,
            0x1B,
            0x23,
            0x3D,
            0x68,
            0x2A,
            0x65,
            0xE8,
            0x91,
            0xF6,
            0xFF,
            0x13,
            0x58,
            0xF1,
            0x47,
            0x0A,
            0x7F,
            0xC5,
            0xA7,
            0xE7,
            0x61,
            0x5A,
            0x06,
            0x46,
            0x44,
            0x42,
            0x04,
            0xA0,
            0xDB,
            0x39,
            0x86,
            0x54,
            0xAA,
            0x8C,
            0x34,
            0x21,
            0x8B,
            0xF8,
            0x0C,
            0x74,
            0x67,
        ]

        pi3_e = [
            0x68,
            0x8D,
            0xCA,
            0x4D,
            0x73,
            0x4B,
            0x4E,
            0x2A,
            0xD4,
            0x52,
            0x26,
            0xB3,
            0x54,
            0x1E,
            0x19,
            0x1F,
            0x22,
            0x03,
            0x46,
            0x3D,
            0x2D,
            0x4A,
            0x53,
            0x83,
            0x13,
            0x8A,
            0xB7,
            0xD5,
            0x25,
            0x79,
            0xF5,
            0xBD,
            0x58,
            0x2F,
            0x0D,
            0x02,
            0xED,
            0x51,
            0x9E,
            0x11,
            0xF2,
            0x3E,
            0x55,
            0x5E,
            0xD1,
            0x16,
            0x3C,
            0x66,
            0x70,
            0x5D,
            0xF3,
            0x45,
            0x40,
            0xCC,
            0xE8,
            0x94,
            0x56,
            0x08,
            0xCE,
            0x1A,
            0x3A,
            0xD2,
            0xE1,
            0xDF,
            0xB5,
            0x38,
            0x6E,
            0x0E,
            0xE5,
            0xF4,
            0xF9,
            0x86,
            0xE9,
            0x4F,
            0xD6,
            0x85,
            0x23,
            0xCF,
            0x32,
            0x99,
            0x31,
            0x14,
            0xAE,
            0xEE,
            0xC8,
            0x48,
            0xD3,
            0x30,
            0xA1,
            0x92,
            0x41,
            0xB1,
            0x18,
            0xC4,
            0x2C,
            0x71,
            0x72,
            0x44,
            0x15,
            0xFD,
            0x37,
            0xBE,
            0x5F,
            0xAA,
            0x9B,
            0x88,
            0xD8,
            0xAB,
            0x89,
            0x9C,
            0xFA,
            0x60,
            0xEA,
            0xBC,
            0x62,
            0x0C,
            0x24,
            0xA6,
            0xA8,
            0xEC,
            0x67,
            0x20,
            0xDB,
            0x7C,
            0x28,
            0xDD,
            0xAC,
            0x5B,
            0x34,
            0x7E,
            0x10,
            0xF1,
            0x7B,
            0x8F,
            0x63,
            0xA0,
            0x05,
            0x9A,
            0x43,
            0x77,
            0x21,
            0xBF,
            0x27,
            0x09,
            0xC3,
            0x9F,
            0xB6,
            0xD7,
            0x29,
            0xC2,
            0xEB,
            0xC0,
            0xA4,
            0x8B,
            0x8C,
            0x1D,
            0xFB,
            0xFF,
            0xC1,
            0xB2,
            0x97,
            0x2E,
            0xF8,
            0x65,
            0xF6,
            0x75,
            0x07,
            0x04,
            0x49,
            0x33,
            0xE4,
            0xD9,
            0xB9,
            0xD0,
            0x42,
            0xC7,
            0x6C,
            0x90,
            0x00,
            0x8E,
            0x6F,
            0x50,
            0x01,
            0xC5,
            0xDA,
            0x47,
            0x3F,
            0xCD,
            0x69,
            0xA2,
            0xE2,
            0x7A,
            0xA7,
            0xC6,
            0x93,
            0x0F,
            0x0A,
            0x06,
            0xE6,
            0x2B,
            0x96,
            0xA3,
            0x1C,
            0xAF,
            0x6A,
            0x12,
            0x84,
            0x39,
            0xE7,
            0xB0,
            0x82,
            0xF7,
            0xFE,
            0x9D,
            0x87,
            0x5C,
            0x81,
            0x35,
            0xDE,
            0xB4,
            0xA5,
            0xFC,
            0x80,
            0xEF,
            0xCB,
            0xBB,
            0x6B,
            0x76,
            0xBA,
            0x5A,
            0x7D,
            0x78,
            0x0B,
            0x95,
            0xE3,
            0xAD,
            0x74,
            0x98,
            0x3B,
            0x36,
            0x64,
            0x6D,
            0xDC,
            0xF0,
            0x59,
            0xA9,
            0x4C,
            0x17,
            0x7F,
            0x91,
            0xB8,
            0xC9,
            0x57,
            0x1B,
            0xE0,
            0x61,
        ]
        sboxes = {0: pi0_e, 1: pi1_e, 2: pi2_e, 3: pi3_e}
        # Define the byte-level mapping
        mapping = [0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7]

        # Initialize a 128x128 binary matrix
        M = np.zeros((128, 128), dtype=int)

        # Fill the matrix with 1s where output bits map from input bits
        for output_byte_index in range(16):
            input_byte_index = mapping[output_byte_index]
            for bit_index in range(8):
                output_bit = output_byte_index * 8 + bit_index
                input_bit = input_byte_index * 8 + bit_index
                M[output_bit, input_bit] = 1

        self.kalyna_matrix = """[
            [0x01, 0x04, 0x07, 0x06, 0x08, 0x01, 0x05, 0x01],
            [0x01, 0x01, 0x04, 0x07, 0x06, 0x08, 0x01, 0x05],
            [0x05, 0x01, 0x01, 0x04, 0x07, 0x06, 0x08, 0x01],
            [0x01, 0x05, 0x01, 0x01, 0x04, 0x07, 0x06, 0x08],
            [0x08, 0x01, 0x05, 0x01, 0x01, 0x04, 0x07, 0x06],
            [0x06, 0x08, 0x01, 0x05, 0x01, 0x01, 0x04, 0x07],
            [0x07, 0x06, 0x08, 0x01, 0x05, 0x01, 0x01, 0x04],
            [0x04, 0x07, 0x06, 0x08, 0x01, 0x05, 0x01, 0x01],
        ]"""
        [
            [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04],
            [0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07],
            [0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08, 0x06],
            [0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01, 0x08],
            [0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05, 0x01],
            [0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01, 0x05],
            [0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01, 0x01],
            [0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04, 0x01],
        ]

        self.irreducible_polynomial = {8: 0x11D}
        self.kalyna_matrix_description = [
            self.kalyna_matrix,
            0x11D,
            64,
        ]

        #######################
        # Step A: Initial MODADD using round key K₀
        self.add_round()

        ################### Key Scheduling (Sec 7)######################
        # Computes K_sigma for Kalyna block cipher as specified in Section 7.1.
        # Step 0: S₀ = 128-bit zero block 0x00000000000000050000000000000000
        # S0 = self.add_constant_component(128, 0x0)
        S0 = self.add_constant_component(128, 0x00000000000000000000000000000005)

        # Step 1: G1 = Enc_K(S0 + K)
        g1_first = self.add_MODADD_component(
            [INPUT_KEY, S0.id],
            [[i for i in range(64, 128)], [i for i in range(64, 128)]],
            64,
        )
        g1_second = self.add_MODADD_component(
            [INPUT_KEY, S0.id],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )

        """self.add_cipher_output_component(
            [g1_second.id, g1_first.id],
            [[i for i in range(64)], [i for i in range(64)]],
            128,
        )"""

        sboxes_components = []
        for i in range(8):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g1_first.id],
                    [list(range((8 * i), (8 * i + 8)))],
                    8,
                    sboxes[3 - (i % 4)],
                )
            )
        for i in range(8, 16):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g1_second.id],
                    [list(range((8 * i) - 64, (8 * i + 8) - 64))],
                    8,
                    sboxes[3 - (i % 4)],
                )
            )

        """self.add_cipher_output_component(
            [sboxes_components[i].id for i in range(16)],
            [[i for i in range(8)]] * 16,
            self.CIPHER_BLOCK_SIZE,
        )"""

        """input_ids = [c.id for c in sboxes_components]
        input_positions = [list(range(8)) for _ in range(16)]
        after_circular_right_sheft = self.add_rotate_component(
            [input_ids], [input_positions], 128, 32 * i
        )"""

        input_ids = [c.id for c in sboxes_components]
        input_positions = [list(range(8)) for _ in range(16)]
        shift1 = self.add_linear_layer_component(
            input_ids, input_positions, 128, M.tolist()
        )
        """self.add_cipher_output_component(
            [shift1.id],
            [[i for i in range(128)]],
            self.CIPHER_BLOCK_SIZE,
        )"""

        """g1_first = self.add_mix_column_component(
            [shift1.id], [[i for i in range(64)]], 64, self.kalyna_matrix_description
        )"""

        # g1_first = self.add_mix_column_component(
        #     [shift1.id],
        #     [[i + j for i in range(0, 128, 16) for j in range(8)]],
        #     64,
        #     self.kalyna_matrix_description,
        # )
        """g1_second = self.add_mix_column_component(
            [shift1.id],
            [[i for i in range(64, 128)]],
            64,
            self.kalyna_matrix_description,
        )"""
        # g1_second = self.add_mix_column_component(
        #     [shift1.id],
        #     [[i + j for i in range(0, 128, 16) for j in range(8, 16)]],
        #     64,
        #     self.kalyna_matrix_description,
        # )
        col_2 = [i + j for i in range(0, 128, 16) for j in range(8, 16)]
        col_1 = [i + j for i in range(0, 128, 16) for j in range(0, 8)]
        g_matrix = self.add_mix_column_component(
            [shift1.id, shift1.id], [col_1, col_2], 128, self.kalyna_matrix_description
        )
        self.add_cipher_output_component(
            [g_matrix.id],
            [[i for i in range(128)]],
            self.CIPHER_BLOCK_SIZE,
        )
        """self.add_cipher_output_component(
            [g1_first.id, g1_second.id],
            [[i for i in range(64)], [i for i in range(64)]],
            self.CIPHER_BLOCK_SIZE,
        )"""
        '''
        # Step 2: G2 = Enc_K(G1 XOR K)
        g2_first = self.add_XOR_component(
            [g1_first.id, INPUT_KEY],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )
        g2_second = self.add_XOR_component(
            [g1_second.id, INPUT_KEY],
            [[i for i in range(64)], [i for i in range(64, 128)]],
            64,
        )

        sboxes_components = []
        for i in range(8):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g2_first.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
            )
        for i in range(8, 16):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g2_second.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
            )
        input_ids = [c.id for c in sboxes_components]
        input_positions = [list(range(8)) for _ in range(16)]
        shift2 = self.add_linear_layer_component(
            input_ids, input_positions, 128, M.tolist()
        )
        g2_first = self.add_mix_column_component(
            [shift2.id], [[i for i in range(64)]], 64, self.kalyna_matrix_description
        )
        g2_second = self.add_mix_column_component(
            [shift2.id],
            [[i for i in range(64, 128)]],
            64,
            self.kalyna_matrix_description,
        )

        # Step 3: K_sigma = Enc_K(G2 + K)
        g3_first = self.add_MODADD_component(
            [INPUT_KEY, g2_first.id],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )
        g3_second = self.add_MODADD_component(
            [INPUT_KEY, g2_second.id],
            [[i for i in range(64, 128)], [i for i in range(64)]],
            64,
        )

        sboxes_components = []
        for i in range(8):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g3_first.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
            )
        for i in range(8, 16):
            sboxes_components.append(
                self.add_SBOX_component(
                    [g3_second.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
            )
        input_ids = [c.id for c in sboxes_components]
        input_positions = [list(range(8)) for _ in range(16)]
        shift3 = self.add_linear_layer_component(
            input_ids, input_positions, 128, M.tolist()
        )

        k_sigma_first = self.add_mix_column_component(
            [shift3.id], [[i for i in range(64)]], 64, self.kalyna_matrix_description
        )
        k_sigma_second = self.add_mix_column_component(
            [shift3.id],
            [[i for i in range(64, 128)]],
            64,
            self.kalyna_matrix_description,
        )
        # print(f"this is K_sigma{k_sigma_first}")

        ############################# K_even #############################
        # Even Round Key Generation (Matches Kalyna Spec Section 7.2)
        for i in range(0, 10 + 1, 2):
            print(f"this round {i}")
            # Step 1: Generate round constant TMV_i (e.g., 0x00010001...)
            base_tmv = self.add_constant_component(128, 0x0001000100010001)
            # confirm if this << or <<<
            tmv = self.add_rotate_component(
                [base_tmv.id], [list(range(128))], 128, -i // 2
            )
            # Step 2: Rotate master key by 32 * i bits (4 * i bytes)
            rotated_key = self.add_rotate_component(
                [INPUT_KEY], [list(range(128))], 128, 32 * i
            )
            # Step 3: XOR TMV_i with rotated key → produces K'_i
            k_i_prime = self.add_XOR_component(
                [tmv.id, rotated_key.id],
                [[j for j in range(128)], [j for j in range(128)]],
                128,
            )
            # Step 4: Encrypt K'_i using K_sigma as key:
            k_i_prime_first = self.add_XOR_component(
                [k_i_prime.id, k_sigma_first.id],  # XOR with first half of K_sigma
                [[i for i in range(64)], [i for i in range(64)]],
                64,
            )
            k_i_prime_second = self.add_XOR_component(
                [k_i_prime.id, k_sigma_second.id],  # XOR with second half of K_sigma
                [[i for i in range(64, 128)], [i for i in range(64)]],
                64,
            )
            # - SubBytes (η)
            sboxes_components = []
            for j in range(8):
                sboxes_components.append(
                    self.add_SBOX_component(
                        [k_i_prime_first.id], [[j for j in range(8)]], 8, sboxes[j % 4]
                    )
                )
            for j in range(8, 16):
                sboxes_components.append(
                    self.add_SBOX_component(
                        [k_i_prime_second.id], [[j for j in range(8)]], 8, sboxes[j % 4]
                    )
                )

            # - ShiftRows (π′), as binary matrix M
            input_ids = [c.id for c in sboxes_components]
            input_positions = [list(range(8)) for _ in range(16)]
            shift = self.add_linear_layer_component(
                input_ids, input_positions, 128, M.tolist()
            )

            # - MixColumns (ψₗ): apply separately to 1st and 2nd halves
            even_first = self.add_mix_column_component(
                [shift.id], [[k for k in range(64)]], 64, self.kalyna_matrix_description
            )
            even_second = self.add_mix_column_component(
                [shift.id],
                [[k for k in range(64, 128)]],
                64,
                self.kalyna_matrix_description,
            )
            # Step 5: Store as round key K_i
            self.round_keys[i] = (even_first.id, even_second.id)
            print(
                f"this round {i} first half {even_first} and second half {even_second}"
            )
        ################### K_odd ########################
        # Generate odd round keys from the even ones (circular left shift)
        for i in range(1, 10, 2):
            print(f"this round {i}")
            # Unpack the two halves of the even round key
            even_first_id, even_second_id = self.round_keys[i - 1]
            # Perform circular left shift (Kalyna: 128/4 + 24 = 56 bits)
            left_shifted = self.add_rotate_component(
                [even_first_id, even_second_id],  # input IDs
                [[j for j in range(64)], [j for j in range(64)]],  # bit positions
                128,  # total size
                -128 // 4 + 24,  # shift amount in bits
            )
            print(left_shifted.id)

            # Store the odd round key as a single component (shifted result)
            self.round_keys[i] = left_shifted.id

        # print(f"this is the key {self.round_keys}")
        ##############################

        k0_first_id, k0_second_id = self.round_keys[0]

        # Get round key K₀ (even), tuple of halves
        first_half_modadd_key = self.add_MODADD_component(
            [k0_first_id, INPUT_PLAINTEXT],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )

        second_half_modadd_key = self.add_MODADD_component(
            [k0_second_id, INPUT_PLAINTEXT],
            [[i for i in range(64)], [i for i in range(64, 128)]],
            64,
        )

        current_first_half = first_half_modadd_key
        current_second_half = second_half_modadd_key

        # Step B: Middle Rounds (for r = 1 to NROUNDS - 1)
        for r in range(1, self.NROUNDS):
            self.add_round()
            sboxes_components = []
            for i in range(8):
                sbox_new = self.add_SBOX_component(
                    [current_first_half.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
                sboxes_components.append(sbox_new)

            for i in range(8, 16):
                sbox_new = self.add_SBOX_component(
                    [current_second_half.id], [[i for i in range(8)]], 8, sboxes[i % 4]
                )
                sboxes_components.append(sbox_new)

            """self.add_cipher_output_component(
                [sboxes_components],
                [[i for i in range(64)]],
                64,
            )
            self.add_cipher_output_component(
                [sboxes_components[i].id for i in range(16)],
                [[i for i in range(8)]] * 16,
                self.CIPHER_BLOCK_SIZE,
            )"""

            input_ids = [c.id for c in sboxes_components]
            input_bit_positions = [list(range(8)) for _ in range(16)]

            after_shift_row = self.add_linear_layer_component(
                input_ids, input_bit_positions, 128, M.tolist()
            )

            mix_column_1st_half = self.add_mix_column_component(
                [after_shift_row.id],
                [[i for i in range(64)]],
                64,
                self.kalyna_matrix_description,
            )
            mix_column_2nd_half = self.add_mix_column_component(
                [after_shift_row.id],
                [[i for i in range(64, 128)]],
                64,
                self.kalyna_matrix_description,
            )

            # Use round key K_r
            rk = self.round_keys[r]

            # Use round key K_r
            rk = self.round_keys[r]
            if isinstance(rk, tuple):
                # Even round key — tuple of (first_half, second_half), both 64-bit
                rk_first, rk_second = rk
                current_first_half = self.add_XOR_component(
                    [mix_column_1st_half.id, rk_first],
                    [[i for i in range(64)], [i for i in range(64)]],
                    64,
                )
                current_second_half = self.add_XOR_component(
                    [mix_column_2nd_half.id, rk_second],
                    [[i for i in range(64)], [i for i in range(64)]],
                    64,
                )
            else:
                # Odd round key — single 128-bit ID, must split into halves
                current_first_half = self.add_XOR_component(
                    [mix_column_1st_half.id, rk],
                    [[i for i in range(64)], [i for i in range(64)]],
                    64,
                )
                current_second_half = self.add_XOR_component(
                    [mix_column_2nd_half.id, rk],
                    [[i for i in range(64)], [i for i in range(64, 128)]],
                    64,
                )

        # Step C: Final Round (SubBytes + ShiftRows + MixColumn)
        self.add_round()
        sboxes_components = []
        for i in range(8):
            sbox_new = self.add_SBOX_component(
                [current_first_half.id], [[i for i in range(8)]], 8, sboxes[i % 4]
            )
            sboxes_components.append(sbox_new)

        for i in range(8, 16):
            sbox_new = self.add_SBOX_component(
                [current_second_half.id], [[i for i in range(8)]], 8, sboxes[i % 4]
            )
            sboxes_components.append(sbox_new)

        input_ids = [c.id for c in sboxes_components]
        input_bit_positions = [list(range(8)) for _ in range(16)]

        after_shift_row = self.add_linear_layer_component(
            input_ids, input_bit_positions, 128, M.tolist()
        )

        mix_column_1st_half = self.add_mix_column_component(
            [after_shift_row.id],
            [[i for i in range(64)]],
            64,
            self.kalyna_matrix_description,
        )
        mix_column_2nd_half = self.add_mix_column_component(
            [after_shift_row.id],
            [[i for i in range(64, 128)]],
            64,
            self.kalyna_matrix_description,
        )

        #  Step D: Final MODADD using K_N (last round key)
        kN_first_id, kN_second_id = self.round_keys[self.NROUNDS]  # Get K_N

        final_first_half = self.add_MODADD_component(
            [kN_first_id, mix_column_1st_half.id],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )
        final_second_half = self.add_MODADD_component(
            [kN_second_id, mix_column_2nd_half.id],
            [[i for i in range(64)], [i for i in range(64)]],
            64,
        )

        # Step E: Output
        """self.add_cipher_output_component(
            [final_first_half.id, final_second_half.id],
            [[i for i in range(64)], [i for i in range(64)]],
            self.CIPHER_BLOCK_SIZE,
        )
        '''
