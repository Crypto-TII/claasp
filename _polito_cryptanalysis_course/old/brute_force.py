# Exercise 1: implement an exhaustive key search on the 6-bit ToySPN1 cipher, using a simple python evaluation function

import random
import time
from claasp.ciphers.toys.toyspn1 import ToySPN1


block_bit_size = 6
key_bit_size = 6
toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, number_of_rounds=10)


def random_permutation(plaintext, seed=0):
    random.seed(seed)
    random_permutation_list = [i for i in range(2 ** 6)]
    random.shuffle(random_permutation_list)
    return random_permutation_list[plaintext]


def oracle(oracle_input_query, control_bit=1, key=0x00, seed=0):
    if control_bit == 1:
        return toyspn1.evaluate([key, oracle_input_query])
    else:
        return random_permutation(oracle_input_query, seed)


def brute_force_key_recovery(unknown_key):
    c0 = oracle(0x00, control_bit=1, key=unknown_key)
    for k in range(2**6):
        if toyspn1.evaluate([k,0x00]) == c0:
            return k
    return -1

unknown_key = 0x11
t0 = time.time()
found_key = brute_force_key_recovery(unknown_key)
tf = time.time()
print(f'{hex(unknown_key) = }')
print(f'{hex(found_key) = }')
print(f'total time = {tf-t0} ms')

# Exercise 2: implement an exhaustive key search on the 8-bit ToySPN1 cipher, using a vectorized evaluation function

import numpy as np
from os import urandom

def list_of_random_elements(number_of_bytes_per_element, list_length):
    return np.frombuffer(urandom(list_length*number_of_bytes_per_element), dtype = np.uint8).reshape((number_of_bytes_per_element, list_length))


def list_of_all_elements(number_of_bytes_per_element, list_length):
    return  np.arange(2**8, dtype = np.uint8).reshape((number_of_bytes_per_element, list_length))


def list_of_elements_from_fixed_uint8(fixed_values_uint8, number_of_bytes_per_element, list_length):
    return np.frombuffer(bytearray([fixed_values_uint8] * list_length * number_of_bytes_per_element), dtype=np.uint8).reshape(
        (number_of_bytes_per_element, list_length))

block_bit_size = 8
key_bit_size = 8
toyspn1 = ToySPN1(block_bit_size=block_bit_size, key_bit_size=key_bit_size, sbox=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0], number_of_rounds=10)


def brute_force_key_recovery_vectorized(unknown_key):
    c0 = oracle(0x00, control_bit=1, key=unknown_key)
    number_of_possible_keys = 2 ** 8
    plaintexts = list_of_elements_from_fixed_uint8(0x00, block_bit_size // 8, number_of_possible_keys)
    keys = list_of_all_elements(key_bit_size // 8, number_of_possible_keys)
    ciphertexts = toyspn1.evaluate_vectorized([keys, plaintexts])
    i, j = np.where(ciphertexts[0] == c0)
    return keys[j[0],i[0]]

unknown_key = random.randint(0,2**8)
t0 = time.time()
found_key = brute_force_key_recovery_vectorized(unknown_key)
tf = time.time()
print(f'{hex(unknown_key) = }')
print(f'{hex(found_key) = }')
print(f'total time = {tf-t0} ms')

t0 = time.time()
for unknown_key in range(2**8):
    found_key = brute_force_key_recovery_vectorized(unknown_key)
    if found_key != unknown_key:
        print(f'{hex(unknown_key) = }')
        print(f'{hex(found_key) = }')
tf = time.time()
print(f'total time = {tf-t0} ms')
