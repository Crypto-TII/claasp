# Exercise 1
reset()
import time
from claasp.ciphers.toys.toyspn1 import ToySPN1

toyspn1 = ToySPN1(block_bit_size=6, key_bit_size=6, number_of_rounds=10)

def brute_force_key_recovery(c0):
    for k in range(2**6):
        if toyspn1.evaluate([k,0x00]) == c0:
            return k
    return -1

c0 = 0x05 # known ciphertext corresponding to plaintext 0b000000 = 0x0
t0 = time.time()
found_key = brute_force_key_recovery(c0)
tf = time.time()
print(f'{hex(c0) = }')
print(f'{hex(found_key) = }')
print(f'total time = {tf-t0} ms')

# Exercise 2

reset()
import time
import numpy as np
from os import urandom
from claasp.ciphers.toys.toyspn1 import ToySPN1

def get_random_array(number_of_bytes_per_element):
    return np.frombuffer(urandom(number_of_bytes_per_element), dtype=np.uint8)

def hex_to_numpy_array(hex_value, number_of_bytes_per_element):
    return np.array([((hex_value >> 8*i) & 0xFF) for i in range(number_of_bytes_per_element)])

def list_of_random_elements(number_of_bytes_per_element, list_length):
    return np.frombuffer(urandom(list_length*number_of_bytes_per_element), dtype = np.uint8).reshape((number_of_bytes_per_element, list_length))

def list_of_all_elements(number_of_bytes_per_element, list_length):
    return  np.arange(list_length*number_of_bytes_per_element, dtype = np.uint8).reshape((number_of_bytes_per_element, list_length))

def list_of_elements_from_fixed_uint8(fixed_values_uint8, number_of_bytes_per_element, list_length):
    return np.frombuffer(bytearray([fixed_values_uint8] * list_length * number_of_bytes_per_element), dtype=np.uint8).reshape(
        (number_of_bytes_per_element, list_length))

block_bit_size = 24
key_bit_size = 24
toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, sbox=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0], number_of_rounds=10)

number_of_possible_keys = 2 # 2 ** key_bit_size
plaintexts = list_of_elements_from_fixed_uint8(0x00, block_bit_size // 8, number_of_possible_keys)
keys = list_of_all_elements(key_bit_size // 8, number_of_possible_keys)
ciphertexts = toyspn1.evaluate_vectorized([plaintexts, keys])

c0 = hex_to_numpy_array(0xFFFFFF, block_bit_size // 8)

is_in_list = np.any(np.all(c0 == ciphertexts, axis=1))

"""
def brute_force_key_recovery_vectorized(c0):
    number_of_possible_keys = 2 ** key_bit_size
    plaintexts = list_of_elements_from_fixed_uint8(0x00, block_bit_size // 8, number_of_possible_keys)
    keys = list_of_all_elements(key_bit_size // 8, number_of_possible_keys)
    ciphertexts = toyspn1.evaluate_vectorized([keys, plaintexts])
    i, j = np.where(ciphertexts[0] == c0)
    return keys[j[0],i[0]]

c0 = 0x75 # known ciphertext corresponding to plaintext 0b000000 = 0x0
t0 = time.time()
found_key = brute_force_key_recovery_vectorized(c0)
tf = time.time()
print(f'{hex(c0) = }')
print(f'{hex(found_key) = }')
print(f'total time = {tf-t0} ms')
"""