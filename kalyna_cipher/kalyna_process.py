"""
@author: trident-10 (hassan_javaid)

Contains the module for encryption, decryption and round key expansion used in Kalyna algorithm.

Implementation is according to the original paper DSTU 7624:2014 "A New Encryption Standard of Ukraine:
The Kalyna Block Cipher".

This implementation is the property of the author. All rights reserved.
"""

import math
import time
from operator import add, xor, mod, sub
from typing import Union
import numpy as np

from kalyna_init import KalynaObject
from sub_tables import (
    all_sub_tables,
    all_inv_tables,
    mds_vector,
    inverse_mds,
    mix_col1,
    mix_col4,
    mix_col5,
    mix_col6,
    mix_col7,
    mix_col8,
    mix_col173,
    mix_col149,
    mix_col118,
    mix_col168,
    mix_col47,
    mix_col73,
    mix_col215,
    mix_col202,
    rks_dec_128,
)

all_mix_cols = [0, mix_col1, 0, 0, mix_col4, mix_col5, mix_col6, mix_col7, mix_col8]
all_inv_mix_cols = [
    mix_col173,
    mix_col149,
    mix_col118,
    mix_col168,
    mix_col47,
    mix_col73,
    mix_col215,
    mix_col202,
]


def get_ascii(text: str):
    """
    Return ascii values of a text in the form of a list.
    :param text: (str) Input text.
    :return : (list) List of ascii-values.
    """
    return list(map(ord, text))


def conv_hex(int_list: list):
    """
    Converts a list of integers into hex.
    :param int_list: (list) Input list of integers.
    :return : (list) Converted hex list.
    """
    return list(map(hex, int_list))


def pad_the_key_hex(key: str, length_hex_key: int = 32):
    """
    Pads the key with itself till length of text becomes equal to numBytes.
    :param key: (str) Key whose length is less that numBytes and needs to be padded.
    :param length_hex_key: (int) Length of hex key.
    :return padded_key: (str) Padded Key of length equal to length_hex_key.
    """
    a1 = length_hex_key - len(key)
    padded_key = "0" * a1 + key
    return padded_key if len(padded_key) == length_hex_key else None


def key_to_bytes(hex_str: str, num_col: int = 8, c: int = 2, hex_key_length: int = 32):
    """

    :param hex_str:
    :param num_col:
    :param c:
    :param hex_key_length:
    :return:
    """
    # print("In key_to_bytes")
    # print(hex_key_length)
    if len(hex_str) < hex_key_length:
        pad_str = pad_the_key_hex(hex_str, hex_key_length)
    else:
        pad_str = hex_str
    # print(pad_str)
    pLen = len(pad_str)
    x = list()
    for i in range(0, pLen, 2):
        x.append(int(pad_str[i : i + 2], 16))
    x.reverse()
    return np.reshape(x, (c, num_col))


def to_bytes(
    input_list: Union[list, str],
    num_col: int = 8,
    c: int = 2,
    hex_key_length: int = 32,
    reverse: bool = False,
):
    """
    Takes a list of values and reshapes it in to a 2x8 numpy array
    of hex values in a format required for AES Kalyna Cipher. Returns the
    list of 8x2 byte-block as a numpy array.
    c=2 and num_col=8 for Kalyna Cipher-128 bit as specified in paper.
    :param input_list: (list) Integer list
    :param c: Number of rows in state matrix (c = 2 by default)
    :param num_col: Column length of state matrix (4 bytes * 2 = 8 bytes default)
    :param hex_key_length:
    :param reverse: Boolean for reversing parsed int list to maintain little endianness.
    :return d: (array) c x num_col numpy array.
    """
    parsed_int_key = input_list
    if type(parsed_int_key) == str:
        # If required => Padding key and state_0 for further processing
        if len(parsed_int_key) < hex_key_length:
            pad_str = pad_the_key_hex(parsed_int_key, hex_key_length)
        else:
            pad_str = parsed_int_key
        # Convert to 2 x num_col int bytes to make it subscriptable for further processing
        parsed_int_key = [
            int(pad_str[i : i + 2], 16) for i in range(0, len(pad_str), 2)
        ]
    if reverse:
        parsed_int_key.reverse()
    d = np.array(parsed_int_key).reshape((c, num_col))
    return d


def to_words(byte: np.array, wrapping: bool = False):
    """
    Converts a list of integers into hex.
    :param byte: A numpy array consisting of integers.
    :param wrapping: A boolean input to enable wrapped-hex-word output format.
    :return : Hex word unwrapped or wrapped.
    """
    word = ""
    sep_word = ""
    x, y = byte.shape[0], byte.shape[1]
    for i in range(x):
        z = list(map(hex, byte[i]))
        for j in range(len(z)):
            if int(z[j][2:], 16) < 16:
                word = word + "0" + str(z[j][2:])
                sep_word = sep_word + "0" + str(z[j][2:])
            else:
                word += str(z[j][2:])
                sep_word += str(z[j][2:])
        if (i + 1) % 2 == 0:
            sep_word += "\n"
    return sep_word.upper() if wrapping else word.upper()


def print_byte(byte: np.array):
    """
    Prints byte array in three formats: array, hex-array and word.
    :param byte: A numpy array consisting of integers
    :return: None
    """
    print(byte)
    for i in range(byte.shape[0]):
        print(conv_hex(byte[i].tolist()))
    print(to_words(byte, True))


def LsbReturn(x: int, r: int, x_len: int = 64):
    """
    A function that returns r least significant bits from the input sequence x
    of l-bit length.
    :param x: Input sequence of l-bit length.
    :param r: Index for input sequence slicing.
    :param x_len: Length of input sequence.
    :return : (np array) Sequence of r-bit length. Where out = x[r:end].
    """
    # Convert to hex for slicing
    hex_str = hex(x)[2:]
    if len(hex_str) < x_len:
        pad_str = pad_the_key_hex(hex_str, x_len)
        assert pad_str is not None, (
            "Output is None. Either hex key length for padding is greater than key_length or "
            "not a multiple of 32."
        )
    else:
        pad_str = hex_str
    return int(pad_str[r // 4 :], 16)


def MsbReturn(x: int, r: int, x_len: int = 64):
    """
    A function that returns r most significant bits from the input sequence x
    of l-bit length.
    :param x: Input sequence of l-bit length in array form.
    :param r: Index for input sequence slicing.
    :param x_len: Length of input sequence.
    :return : (array) Sequence of r-bit length. Where out = x[start:r].
    """
    # Convert to hex for slicing
    hex_str = hex(x)[2:]
    if len(hex_str) < x_len:
        pad_str = pad_the_key_hex(hex_str, x_len)
        assert pad_str is not None, (
            "Output is None. Either hex key length for padding is greater than key_length or "
            "not a multiple of 32."
        )
    else:
        pad_str = hex_str
    return int(pad_str[: r // 4], 16)


def circular_right_shift(value: int, n: int, num_bits_in_int: int = 128):
    """
    Circular right shift the input "value" by "n".
    :param value: Input to be shifted.
    :param n: Shift value.
    :param num_bits_in_int: The bit size of integer.
    :return: (int) Shifted value.
    """
    n = n % num_bits_in_int
    mask = (1 << num_bits_in_int) - 1
    result = (value >> n) | (value << (num_bits_in_int - n))
    result = result & mask
    return result


def circular_left_shift(value: int, n: int, num_bits_in_int: int = 128):
    """
    Circular left shift the input parameter "value" by "n".
    :param value: Input to be shifted.
    :param n: Shift value.
    :param num_bits_in_int: The bit size of integer.
    :return: (int) Shifted value.
    """
    n = n % num_bits_in_int
    mask = (1 << num_bits_in_int) - 1
    result = (value << n) | (value >> (num_bits_in_int - n))
    result = result & mask
    return result


def add_method_simple(
    byte1: np.array,
    byte2: np.array,
    c: int = 2,
    hex_key_length: int = 32,
    modulus: int = 2**64,
):
    """
    Returns sum of two bytes modulo some input. Modulus = 2**64 (default).
    :param byte1: 1st byte to be added.
    :param byte2: 2nd byte to be added.
    :param c: Number of rows of the two bytes.
    :param hex_key_length: Length of hex key to be used for padding. This makes length in hex format of both the bytes
    consistent.
    :param modulus: Default value used.
    :return: (np array) Sum of both bytes modulo "modulus".
    """
    assert byte1.shape == byte2.shape, "Bytes should be of the same shape."
    length, width = byte1.shape
    slc = 2 * width
    f_block = list()
    b1_w = to_words(np.fliplr(byte1))
    b2_w = to_words(np.fliplr(byte2))
    for i in range(length):
        b1 = int(b1_w[slc * i : slc * (i + 1)], 16)
        b2 = int(b2_w[slc * i : slc * (i + 1)], 16)
        d = (b1 + b2) % modulus
        v = hex(d)[2:]
        # for hex whose starting 0 is stripped off by python
        while len(v) < slc:
            v = "0" + v
        f_block.append(v)
    f_block = "".join(f_block)
    o_block = np.flipud(to_bytes(f_block, width, c, hex_key_length, True))
    return o_block


def add_method(k_obj: KalynaObject, byte2: np.array, modulus: int = 2**64):
    """
    Returns the sum of the internal state matrix and byte2 modulo some input. Modulus = 2**64 (default).
    :param k_obj: Kalyna object.
    :param byte2: 2nd byte to be added.
    :param modulus: Default value according to the paper.
    :return: (np array) Sum of both bytes modulo "modulus".
    """
    byte1 = k_obj.state
    assert byte1.shape == byte2.shape, "Bytes should be of the same shape."
    length, width = byte1.shape
    slc = 2 * width
    f_block = list()
    b1_w = to_words(np.fliplr(byte1))
    b2_w = to_words(np.fliplr(byte2))
    for i in range(length):
        b1 = int(b1_w[slc * i : slc * (i + 1)], 16)
        print(f"printing b1 {hex(b1)}")
        b2 = int(b2_w[slc * i : slc * (i + 1)], 16)
        print(f"printing b2 {hex(b2)}")
        d = (b1 + b2) % modulus
        v = hex(d)[2:]
        print(f"printing v {v}")
        # for hex whose starting 0 is stripped off by python
        while len(v) < slc:
            v = "0" + v
        f_block.append(v)
    f_block = "".join(f_block)
    o_block = np.flipud(
        to_bytes(f_block, width, k_obj.NumStateMatrixRows, k_obj.HexKeyLength, True)
    )
    k_obj.state = o_block


def xor_round_key(k_obj: KalynaObject, byte2: np.array):
    """
    Returns the XOR result of the internal state matrix of Kalyna object with byte2.
    :param k_obj: Kalyna object.
    :param byte2: 2nd byte.
    :return app_block: (array) XOR result.
    """
    byte_block = k_obj.state
    assert byte_block.shape == byte2.shape, "byte1 and byte2 are not of same shape."
    length, width = byte2.shape[0], byte2.shape[1]
    xor_block = [list(map(xor, byte_block[i], byte2[i])) for i in range(length)]
    k_obj.state = to_bytes(
        xor_block, width, k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    )


def sub_bytes(k_obj: KalynaObject, tables: list):
    """
    Implements the mapping step of the state matrix.
    :param k_obj: Kalyna object.
    :param tables: Forward substitution tables.
    :return: Mapped state matrix.
    """
    num_col, c, h = k_obj.state.shape[1], k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    print(f"number of columns: {num_col}")
    print(f"this is the state {k_obj.state}")
    for byte in k_obj.state:
        for j in range(len(byte)):
            print(f"printing byte: {byte}")
            print(f"index j {j}, {j%4}")
            print(f"byte[j] {byte[j]}")
            print("Table", tables[j % 4][byte[j]])
            print("Table", tables[j % 4])
    # print([tables[j % 4][byte[j]] for byte in k_obj.state for j in range(len(byte))])
    # import ipdb
    # ipdb.set_trace()
    sub_block = to_bytes(
        [tables[j % 4][byte[j]] for byte in k_obj.state for j in range(len(byte))],
        num_col,
        c,
        h,
    )
    k_obj.state = sub_block


import numpy as np


def list_to_hex(arr: np.ndarray) -> str:
    """
    Converts a 2D numpy array of integers (0-255) into a single hex string.

    Parameters:
        arr (np.ndarray): A 2D numpy array of uint8 integers.

    Returns:
        str: Hexadecimal string prefixed with '0x'.
    """
    if not isinstance(arr, np.ndarray):
        raise ValueError("Input must be a NumPy array.")

    if arr.dtype != np.uint8:
        arr = arr.astype(np.uint8)

    # Flatten the array row-wise and convert to hex
    flat = arr.flatten()
    hex_str = "".join(f"{byte:02X}" for byte in flat)

    return "0x" + hex_str


def rot_word(k_obj: KalynaObject, shift: list):
    """
    Implements the permutation step.
    :param k_obj: Kalyna object.
    :param shift: Permutation values. -ve for left shift and +ve for right shift.
    :return: Shifted state matrix.
    """
    vals = k_obj.state
    assert (
        len(shift) == vals.shape[1]
    ), "Length of shift list and state-matrix dim[1] must be same."
    items = vals.transpose()
    print(f"This is the state before the shift {k_obj.state}")
    for i in range(len(shift)):
        items[i] = np.roll(items[i], shift[i], axis=0)
    k_obj.state = items.transpose()
    # print(f"This is the state after the shift {k_obj.state}")


def mixColumns(k_obj: KalynaObject, tables: list, v: np.array):
    """
    Implements the Galois Field GF(2^8) transformation step.
    :param k_obj: Kalyna object.
    :param tables: Forward transformation tables.
    :param v: MDS vector matrix implemented as 8x8 numpy array
    :return: State matrix.
    """
    r_array = k_obj.state
    g = list()
    for byte in r_array:
        # Looping on mds_matrix
        for row_v in range(len(byte)):
            pr = 0
            for col_v in range(len(byte)):
                y = v[row_v][col_v]
                # import ipdb
                #
                # ipdb.set_trace()
                pr ^= tables[y][byte[col_v]]
            g.append(pr)
    k_obj.state = to_bytes(
        g, k_obj.state.shape[1], k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    )
    # print(f"This is the state after mix columns: {k_obj.state}")


def sub_method(k_obj: KalynaObject, byte2: np.array, modulus: int = 2**64):
    """
    Returns the difference of the internal state matrix and byte2 modulo some input.
    Modulus = 2**64 (default).
    :param k_obj: Kalyna object.
    :param byte2: 2nd byte to be subtracted.
    :param modulus: Default value according to the paper.
    :return: (np array) Difference of both bytes modulo "modulus".
    """
    byte1 = k_obj.state
    assert byte1.shape == byte2.shape, "Bytes should be of the same shape."
    length, width = byte1.shape
    slc = 2 * width
    f_block = list()
    b1_w = to_words(np.fliplr(byte1))
    b2_w = to_words(np.fliplr(byte2))
    for i in range(length):
        b1 = int(b1_w[slc * i : slc * (i + 1)], 16)
        b2 = int(b2_w[slc * i : slc * (i + 1)], 16)
        d = (b1 - b2) % modulus
        v = hex(d)[2:]
        # for hex whose starting 0 is stripped off by python
        while len(v) < slc:
            v = "0" + v
        f_block.append(v)
    f_block = "".join(f_block)
    o_block = np.flipud(
        to_bytes(f_block, width, k_obj.NumStateMatrixRows, k_obj.HexKeyLength, True)
    )
    k_obj.state = o_block


def inv_sub_bytes(k_obj: KalynaObject, inv_tables: list):
    """
    Implements the inverse mapping step of the state matrix.
    :param k_obj: Kalyna object.
    :param inv_tables: Forward substitution tables.
    :return: Mapped state matrix.
    """
    num_col, c, h = k_obj.state.shape[1], k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    inv_sub_block = to_bytes(
        [inv_tables[j % 4][byte[j]] for byte in k_obj.state for j in range(len(byte))],
        num_col,
        c,
        h,
    )
    k_obj.state = inv_sub_block


def inv_rot_word(k_obj: KalynaObject, inv_shift: list):
    """
    Implements the inverse permutation step.
    :param k_obj: Kalyna object.
    :param inv_shift: Permutation values. -ve for left shift and +ve for right shift.
    :return: Shifted state matrix.
    """
    vals = k_obj.state
    assert (
        len(inv_shift) == vals.shape[1]
    ), "Length of inv_shift list and state-matrix dim[1] must be same."
    items = vals.transpose()
    for i in range(len(inv_shift)):
        items[i] = np.roll(items[i], inv_shift[i], axis=0)
    k_obj.state = items.transpose()


def invMixColumns(k_obj: KalynaObject, inv_tables: list, c_mat_inv: np.array):
    """
    Implements the inverse Galois Field GF(2^8) transformation step.
    :param k_obj: Kalyna object.
    :param inv_tables: Forward transformation tables.
    :param c_mat_inv: MDS inverse vector matrix implemented as 8x8 numpy array
    :return: State matrix.
    """
    trans = {173: 0, 149: 1, 118: 2, 168: 3, 47: 4, 73: 5, 215: 6, 202: 7}
    r_array = k_obj.state
    g = list()
    for byte in r_array:
        # Looping on mds_matrix
        for row_v in range(len(byte)):
            pr = 0
            for col_v in range(len(byte)):
                y = c_mat_inv[row_v][col_v]
                ind = trans[y]
                pr ^= inv_tables[ind][byte[col_v]]
            g.append(pr)
    k_obj.state = to_bytes(
        g, k_obj.state.shape[1], k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    )


def little_to_big_endian(hex_str: str) -> str:
    """
    Convert a hex string from little endian to big endian notation.

    Parameters:
        hex_str (str): Hex string starting with '0x' or without it.

    Returns:
        str: Hex string in big endian notation with '0x' prefix.
    """
    # Remove '0x' prefix if present
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]

    # Check if length is even
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string length must be even (full bytes).")

    # Split hex string into bytes (2 chars each)
    bytes_list = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]

    # Reverse the bytes for big endian
    bytes_list.reverse()

    # Join back into string
    big_endian_hex = "".join(bytes_list)

    # Return with '0x' prefix and uppercase for consistency
    return "0x" + big_endian_hex.upper()


def EncryptRound(k_obj, sub_tables, mix_col_tab, c_mat, shift):
    sub_bytes(k_obj, sub_tables)
    # print(
    #     f"This is the state after s_box in hex: {little_to_big_endian(list_to_hex(k_obj.state))}"
    # )
    # print(f"This is the state after s_box in hex: {list_to_hex(k_obj.state)}")
    rot_word(k_obj, shift)
    print(f"This is the state after shift_row in hex: {list_to_hex(k_obj.state)}")
    mixColumns(k_obj, mix_col_tab, c_mat)


def KeyExpansionKT(
    k_obj: KalynaObject,
    main_key: int,
    k_alpha: np.array,
    k_omega: np.array,
    tables: list,
    mix_col_t: list,
    c_mat: np.array,
    state_0: int,
):

    l = k_obj.BlockSize

    # Pad state_0 word to appropriate length as keyLengthSize
    init_state = "0" * (k_obj.HexKeyLength - len(hex(state_0)[2:])) + hex(state_0)[2:]

    k_alpha_byte = k_alpha
    k_omega_byte = k_omega

    init_state_byte = to_bytes(
        init_state,
        k_obj.state.shape[1],
        k_obj.NumStateMatrixRows,
        k_obj.HexKeyLength,
        True,
    )
    k_obj.state = init_state_byte

    add_method(k_obj, k_alpha_byte)

    shift = [(i * l) // 512 for i in range(len(k_obj.state[0]))]
    print(f"this is the shift amount {shift}")

    EncryptRound(k_obj, tables, mix_col_t, c_mat, shift)

    xor_round_key(k_obj, k_omega_byte)

    EncryptRound(k_obj, tables, mix_col_t, c_mat, shift)
    # import ipdb
    #
    # ipdb.set_trace()
    add_method(k_obj, k_alpha_byte)

    EncryptRound(k_obj, tables, mix_col_t, c_mat, shift)

    K_sigma = k_obj.state
    return K_sigma


def KeyExpansionEven(
    k_obj: KalynaObject,
    k_sigma: np.array,
    main_key: int,
    tables: list,
    mix_col_t: list,
    c_mat: np.array,
):

    # Design tmv firstly
    tmv_0 = int("0001" * (k_obj.HexKeyLength // 4), 16)
    print(f"k_obj.HexKeyLength = {k_obj.HexKeyLength }")
    print(f"this is tmv_0 = {tmv_0}")
    import ipdb

    ipdb.set_trace()

    roundkeys = dict()
    l = k_obj.BlockSize
    k = k_obj.KeyLength

    for i in range(0, k_obj.NumRounds + 1, 2):
        # print("Round number: {}".format(i))

        # tmv left-shift and length check in case if MSB is added for shift >=8
        tmv = tmv_0 << (i // 2)
        tmv_byte = key_to_bytes(
            hex(tmv)[2:],
            k_obj.state.shape[1],
            k_obj.NumStateMatrixRows,
            k_obj.HexKeyLength,
        )

        # right shift the main_key acc to following conditions
        if k == l:
            cipher_key = circular_right_shift(main_key, 32 * i, k)
            ckb = key_to_bytes(
                hex(cipher_key)[2:],
                k_obj.state.shape[1],
                k_obj.NumStateMatrixRows,
                k_obj.PadKeyLength,
            )
            cipher_key_byte = np.array(ckb, int)
        elif k == 2 * l:
            # Number of State Matrix Rows i.e. k_obj.NumStateMatrixRows for key handling is different for k=2*l cases
            if i % 4 == 0:
                cipher_key = circular_right_shift(main_key, 16 * i, k)
                ckb = key_to_bytes(
                    hex(cipher_key)[2:],
                    k_obj.state.shape[1],
                    2 * k_obj.NumStateMatrixRows,
                    k_obj.PadKeyLength,
                )
                cipher_key_byte = np.array(ckb[: k_obj.NumStateMatrixRows], int)
            else:
                cipher_key = circular_right_shift(main_key, 64 * (i // 4), k)
                ckb = key_to_bytes(
                    hex(cipher_key)[2:],
                    k_obj.state.shape[1],
                    2 * k_obj.NumStateMatrixRows,
                    k_obj.PadKeyLength,
                )
                cipher_key_byte = np.array(ckb[k_obj.NumStateMatrixRows :], int)
        else:
            cipher_key = main_key
            raise ValueError(
                "Incorrect values of k:KeyLength = {} and l:BlockSize  = {} !".format(
                    k, l
                )
            )

        # Key expansion process
        kt_round = add_method_simple(
            k_sigma, tmv_byte, k_obj.NumStateMatrixRows, k_obj.HexKeyLength
        )
        k_obj.state = kt_round

        add_method(k_obj, cipher_key_byte)

        shift = [(i * l) // 512 for i in range(len(k_obj.state[0]))]

        EncryptRound(k_obj, tables, mix_col_t, c_mat, shift)

        xor_round_key(k_obj, kt_round)

        EncryptRound(k_obj, tables, mix_col_t, c_mat, shift)

        add_method(k_obj, kt_round)

        roundkeys[i] = k_obj.state

    return roundkeys


def KeyExpansionOdd(k_obj: KalynaObject, roundkeys: dict):

    l, k = k_obj.BlockSize, k_obj.KeyLength
    num_col, c, h = k_obj.state.shape[1], k_obj.NumStateMatrixRows, k_obj.HexKeyLength
    n = int(l / 4) + 24
    for i in range(1, k_obj.NumRounds, 2):
        rk = int(to_words(roundkeys[i - 1]), 16)
        roundkeys[i] = to_bytes(hex(circular_left_shift(rk, n, l))[2:], num_col, c, h)
    return roundkeys


def EncryptBlock(
    k_obj: KalynaObject,
    p_text: Union[str, int],
    roundkeys: dict,
    tables: list,
    mix_col_t: list,
    c_mat: np.array,
):

    k_0 = roundkeys[0]
    k_obj.state = to_bytes(
        hex(p_text)[2:],
        k_obj.state.shape[1],
        k_obj.NumStateMatrixRows,
        k_obj.HexKeyLength,
        True,
    )
    add_method(k_obj, k_0)

    for j in range(1, k_obj.NumRounds):
        sub_bytes(k_obj, tables)
        shift = [
            math.floor((i * k_obj.BlockSize) / 512) for i in range(len(k_obj.state[0]))
        ]
        rot_word(k_obj, shift)
        mixColumns(k_obj, mix_col_t, c_mat)
        k_v = roundkeys[j]
        xor_round_key(k_obj, k_v)

    sub_bytes(k_obj, tables)
    shift = [(i * k_obj.BlockSize) // 512 for i in range(len(k_obj.state[0]))]
    rot_word(k_obj, shift)
    mixColumns(k_obj, mix_col_t, c_mat)
    k_t = roundkeys[k_obj.NumRounds]
    add_method(k_obj, k_t)

    return k_obj.state


def DecryptBlock(
    k_obj: KalynaObject,
    c_text: Union[str, int],
    roundkeys: dict,
    inv_tables: list,
    inv_mix_col_t: list,
    inv_c_mat: np.array,
):

    l = k_obj.BlockSize
    t = k_obj.NumRounds
    k_t = roundkeys[t]
    k_obj.state = to_bytes(
        hex(c_text)[2:],
        k_obj.state.shape[1],
        k_obj.NumStateMatrixRows,
        k_obj.HexKeyLength,
        True,
    )

    sub_method(k_obj, k_t)

    invMixColumns(k_obj, inv_mix_col_t, inv_c_mat)
    inv_shift = [-((i * l) // 512) for i in range(len(k_obj.state[0]))]
    inv_rot_word(k_obj, inv_shift)
    inv_sub_bytes(k_obj, inv_tables)

    for i in range(t - 1, 0, -1):
        rk = roundkeys[i]

        xor_round_key(k_obj, rk)

        invMixColumns(k_obj, inv_mix_col_t, inv_c_mat)
        inv_rot_word(k_obj, inv_shift)
        inv_sub_bytes(k_obj, inv_tables)

    rk = roundkeys[0]

    sub_method(k_obj, rk)

    return k_obj.state


def KalynaKeyExpansion(parameters: tuple, main_key: int, state_0: int):

    l, k, t, c = parameters

    # Declare KalynaObject for round key generation
    k_c = KalynaObject(l, k, t, c)
    print(f"This is the main key: {main_key}")

    KT = 0
    if k == l:
        k0_b = key_to_bytes(
            hex(main_key)[2:], k_c.state.shape[1], c, k_c.PadKeyLength
        )  # k_alpha
        k1_b = key_to_bytes(
            hex(main_key)[2:], k_c.state.shape[1], c, k_c.PadKeyLength
        )  # k_omega
        KT = KeyExpansionKT(
            k_c, main_key, k0_b, k1_b, all_sub_tables, all_mix_cols, mds_matrix, state_0
        )
        k_c.state = KT
    elif k == 2 * l:
        # Number of State Matrix Rows i.e. k_obj.NumStateMatrixRows for key handling is different for k=2*l cases
        # k_alpha
        k0 = LsbReturn(main_key, l, k_c.PadKeyLength)
        k0_b = key_to_bytes(hex(k0)[2:], k_c.state.shape[1], c, k_c.HexKeyLength)
        # k_omega
        k1 = MsbReturn(main_key, l, k_c.PadKeyLength)
        k1_b = key_to_bytes(hex(k1)[2:], k_c.state.shape[1], c, k_c.HexKeyLength)
        KT = KeyExpansionKT(
            k_c, main_key, k0_b, k1_b, all_sub_tables, all_mix_cols, mds_matrix, state_0
        )
        k_c.state = KT

    roundkeys = KeyExpansionEven(
        k_c, KT, main_key, all_sub_tables, all_mix_cols, mds_matrix
    )
    roundkeys = KeyExpansionOdd(k_c, roundkeys)

    return roundkeys


def KalynaEncrypt(
    parameters: tuple, p_text: Union[str, int], main_key: int, state_0: int
):

    l, k, t, c = parameters
    rks = KalynaKeyExpansion(parameters, main_key, state_0)
    k_e = KalynaObject(l, k, t, c)
    return EncryptBlock(k_e, p_text, rks, all_sub_tables, all_mix_cols, mds_matrix)


def KalynaDecrypt(
    parameters: tuple, c_text: Union[str, int], main_key: int, state_0: int
):

    l, k, t, c = parameters
    rks = KalynaKeyExpansion(parameters, main_key, state_0)
    k_d = KalynaObject(l, k, t, c)
    return DecryptBlock(
        k_d, c_text, rks, all_inv_tables, all_inv_mix_cols, inverse_mds_matrix
    )


# Make MDS matrix
v = np.array(list(map(int, mds_vector)))
mds_matrix = np.vstack(
    [
        v,
        np.roll(v, 1),
        np.roll(v, 2),
        np.roll(v, 3),
        np.roll(v, 4),
        np.roll(v, 5),
        np.roll(v, 6),
        np.roll(v, 7),
    ]
)
v = np.array(list(map(int, inverse_mds)))

inverse_mds_matrix = np.vstack(
    [
        v,
        np.roll(v, 1),
        np.roll(v, 2),
        np.roll(v, 3),
        np.roll(v, 4),
        np.roll(v, 5),
        np.roll(v, 6),
        np.roll(v, 7),
    ]
)

if __name__ == "__main__":
    start_time = time.time()

    # -----------------------------------------------------------------
    # Parameters of Kalyna Object for encrypt/decrypt/key-expansion
    # l = Block size
    # k = Key Length
    # t = Num Rounds
    # c = Rows of state matrix
    # -----------------------------------------------------------------

    # orig_key = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    # orig_key = 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100
    orig_key = 0x3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100
    # orig_key = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
    # state_0 = 0x05000000000000000000000000000000
    # orig_key = 0x0F0E0D0C0B0A09080706050403020100
    # state_0 = 0x0D00000000000000000000000000000000000000000000000000000000000000
    # state_0 = 0x11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    # state_0 = "{0:#0{1}x}".format(11,130)
    # print(state_0)

    # # Parameters of Kalyna Object for encrypt/decrypt/key-expansion
    l = 512  # Block size = 512
    k = 512  # key_length = 512
    t = 18  # num_rounds = 18
    c = 8  # Rows of state matrix = 8
    params = (l, k, t, c)
    #
    # state_0 = 0x11
    # k_e = KalynaObject(l, k, t, c)
    # rks = KalynaKeyExpansion(params, orig_key, state_0)
    # for i in range(len(rks)):
    #     print("Round number {}".format(i))
    #     print_byte(rks[i])
    #
    # orig_key = 0x3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100
    # # # ptx = 0x101112131415161718191A1B1C1D1E1F
    # # # ptx = 0x1F1E1D1C1B1A19181716151413121110
    # ptx = 0x7F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A49484746454443424140
    # ctx = KalynaEncrypt(params, ptx, orig_key, state_0)
    # print("Ciphertext:")
    # print_byte(ctx)

    # k_d = KalynaObject(l, k, t, c)
    # orig_key = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
    # ctx = 0x1F1E1D1C1B1A19181716151413121110
    ctx = 0x404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
    # rks = rks_dec_128
    ptx = KalynaDecrypt(params, ctx, orig_key, state_0)
    # ptx = KalynaDecrypt(params, ctx, dec_key, state_0)
    print("Plaintext:")
    print_byte(ptx)
    # assert ptx ==

    print("--- %.6f seconds ---" % (time.time() - start_time))
