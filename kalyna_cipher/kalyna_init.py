"""
@author: trident-10 (hassan_javaid)

Contains the class definition of KalynaObject.

Original paper: DSTU 7624:2014 "A New Encryption Standard of Ukraine: The Kalyna Block Cipher".

This implementation is the property of the author. All rights reserved.
"""

import numpy as np


def conv_hex(int_list):
    """
    Converts a list of integers into hex.
    :param int_list: (list) Input list of integers.
    :return : (list) Converted hex list.
    """
    return list(map(hex, int_list))


class KalynaObject(object):
    def __init__(self, blockSize: int, keyLength: int, numRounds: int, numStateMatrixRows: int, hexDigitBits: int = 4):
        self.BlockSize = blockSize
        self.KeyLength = keyLength
        self.NumRounds = numRounds
        self.NumStateMatrixRows = numStateMatrixRows
        self.HexDigitBits = hexDigitBits
        self.PadKeyLength = int(self.KeyLength / self.HexDigitBits)  # Length of hex word
        if self.KeyLength == self.BlockSize:
            self.HexKeyLength = self.PadKeyLength  # Length for MSB or LSB slice padding of hex word
        elif self.KeyLength == 2 * self.BlockSize:
            self.HexKeyLength = int(self.PadKeyLength / 2)  # Length for MSB or LSB slice padding of hex word
        self.numBytes = int(self.BlockSize / 8)
        self.state = np.zeros((self.NumStateMatrixRows, 8), int)
        self.word = self.to_words()

    def to_words(self, sep_byte: bool = False):
        """
        Converts a list of integers into hex.
        :param sep_byte:
        :return : (list) Converted hex list.
        """
        word = ''
        sep_word = ''
        x, y = self.state.shape[0], self.state.shape[1]
        for i in range(x):
            z = list(map(hex, self.state[i]))
            for j in range(len(z)):
                if int(z[j][2:], 16) < 16:
                    word = word + '0' + str(z[j][2:])
                    sep_word = sep_word + '0' + str(z[j][2:])
                else:
                    word += str(z[j][2:])
                    sep_word += str(z[j][2:])
            if (i + 1) % 2 == 0:
                sep_word += "\n"
        return sep_word.upper() if sep_byte else word.upper()

    def print_state(self):
        print(self.state)
        for i in range(self.state.shape[0]):
            print(conv_hex(self.state[i].tolist()))
        print(self.to_words(True))
