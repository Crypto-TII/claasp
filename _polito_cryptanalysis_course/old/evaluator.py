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

# def define_list_of_random_values(list_length):
    # TODO
# def define_list_of_fixed_values(fixed_value, list_length):
    # TODO

block_bit_size = 16 
key_bit_size = 16
toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, sbox=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0])
number_of_oracle_calls = 3
number_of_bytes_per_plaintext = ceil(block_bit_size / 8)
plaintexts = np.frombuffer(bytearray([0] * number_of_oracle_calls*number_of_bytes_per_plaintext), dtype = np.uint8).reshape((number_of_bytes_per_plaintext, number_of_oracle_calls)) # 2 random keys of 16 bytes
number_of_bytes_per_key = ceil(key_bit_size / 8)
keys = np.frombuffer(urandom(number_of_oracle_calls*number_of_bytes_per_key), dtype = np.uint8).reshape((number_of_bytes_per_key, number_of_oracle_calls)) # 2 random keys of 16 bytes
ciphertexts = toyspn1.evaluate_vectorized([keys, plaintexts])

print(plaintexts)
print(type(plaintexts))

print(ciphertexts)
print(type(ciphertexts))
# np_byte_array_to_hex_string_array(plaintexts, number_of_oracle_calls)
# np_byte_array_to_hex_string_array(keys, number_of_oracle_calls)
# np_byte_array_to_hex_string_array(ciphertexts, number_of_oracle_calls)

