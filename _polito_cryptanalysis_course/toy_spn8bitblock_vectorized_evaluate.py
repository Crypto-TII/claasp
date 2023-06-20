# from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
# aes = AESBlockCipher()
# import numpy as np
# from os import urandom
# n = 2
# key = np.frombuffer(urandom(n*16), dtype = np.uint8).reshape((16, n)) # 2 random keys of 16 bytes
# plaintext = np.frombuffer(urandom(n*16), dtype = np.uint8).reshape((16, n)) # 2 random plaintexts of 16 bytes
# result = aes.evaluate_vectorized([key, plaintext])
# result
# [array([[154,  71, 162, 160,  77,  60, 124, 182, 104, 221, 192, 125, 181,
#           48, 240, 123],
#         [ 97, 182, 106,  49,  80, 201, 138,  55, 100, 216, 206,  65, 167,
#          205,   4, 151]], dtype=uint8)]
# [hex(int.from_bytes(result[0][i].tobytes(), byteorder='big')) for i in range(2)]
# ['0x9a47a2a04d3c7cb668ddc07db530f07b', '0x61b66a3150c98a3764d8ce41a7cd0497']


reset()
import numpy as np
from os import urandom
from claasp.ciphers.toys.toyspn1 import ToySPN1


def np_byte_array_to_hex_string_array(nparray, nparray_length, reversed=false):
    if reversed:
        return [hex(int.from_bytes(nparray[0][i].tobytes(), byteorder='big')) for i in range(nparray_length)]
    else:
        nparray_transposed = nparray.transpose()
        return [hex(int.from_bytes(nparray_transposed[i].tobytes(), byteorder='big')) for i in range(nparray_length)]


# def list_of_random_elements(number_of_bits_per_element, list_length):
#     number_of_bytes_per_element = ceil(number_of_bits_per_element / 8)
#     npbytearray = np.frombuffer(urandom(list_length * number_of_bytes_per_element), dtype=np.uint8)
#     reduced_npbytearray = np.mod(npbytearray, 2**number_of_bits_per_element)
#     return reduced_npbytearray.reshape((number_of_bytes_per_element, list_length)) # 2 random keys of 16 bytes
#
# def list_of_elements_from_fixed_uint8(fixed_values_uint8, number_of_bits_per_element, list_length):
#     number_of_bytes_per_element = ceil(number_of_bits_per_element / 8)
#     npbytearray = np.frombuffer(bytearray([fixed_values_uint8] * list_length * number_of_bytes_per_element), dtype=np.uint8)
#     reduced_npbytearray = np.mod(npbytearray, 2**number_of_bits_per_element)
#     return reduced_npbytearray.reshape((number_of_bytes_per_element, list_length))


def list_of_random_elements(number_of_bytes_per_element, list_length):
    return np.frombuffer(urandom(list_length*number_of_bytes_per_element), dtype = np.uint8).reshape((number_of_bytes_per_element, list_length)) # 2 random keys of 16 bytes


def list_of_elements_from_fixed_uint8(fixed_values_uint8, number_of_bytes_per_element, list_length):
    return np.frombuffer(bytearray([fixed_values_uint8] * list_length * number_of_bytes_per_element), dtype=np.uint8).reshape(
        (number_of_bytes_per_element, list_length))


block_bit_size = 8
key_bit_size = 8
toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, sbox=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0], number_of_rounds=10)

# block_bit_size = 6
# key_bit_size = 6
# toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=1)

number_of_oracle_calls = 1
plaintexts = list_of_elements_from_fixed_uint8(0x00, block_bit_size//8, number_of_oracle_calls)
keys = list_of_random_elements(key_bit_size//8, number_of_oracle_calls)
ciphertexts = toyspn1.evaluate_vectorized([keys, plaintexts])

plaintexts_hex = np_byte_array_to_hex_string_array(plaintexts, number_of_oracle_calls)
keys_hex = np_byte_array_to_hex_string_array(keys, number_of_oracle_calls)
ciphertexts_hex = np_byte_array_to_hex_string_array(ciphertexts, number_of_oracle_calls, reversed=true)

print(f'{plaintexts_hex = }')
print(f'{keys_hex = }')
print(f'{ciphertexts_hex = }')