reset()

import math

# load("training/markov_cipher.py")

block_bit_size = 6
key_bit_size = 6
number_of_rounds = 3
sbox = [0, 5, 3, 2, 6, 1, 4, 7]
rotation_amount = 1

def xor(A, B):
    return A ^ B


def sbox_layer(X_, block_bit_size, sbox):
    """
    Example:
        sage: f'{sbox_layer(0b000001010011, 12, [0, 5, 3, 2, 6, 1, 4, 7]):012b}'
        '000101011010'
    """
    X = X_ & (2**block_bit_size-1)
    # sbox = [0, 5, 3, 2, 6, 1, 4, 7]
    sbox_bit_size = 3
    output_vector = []
    number_of_sboxes = block_bit_size // sbox_bit_size
    for i in range(number_of_sboxes):
        sbox_input = (X >> (sbox_bit_size*(number_of_sboxes - i - 1))) & 2**sbox_bit_size-1
        # print(f'{sbox_input = }')
        output_vector.append(sbox[sbox_input])
    # print(f'{output_vector = }')
    [output_vector[i] * (2 ** (number_of_sboxes - i - 1)) for i in range(number_of_sboxes)]
    return sum([output_vector[i] * (2**(sbox_bit_size*(number_of_sboxes - i - 1))) for i in range(number_of_sboxes)])


def rot_left(word, r, word_size):
    """
    r > 0 rotates left
    Example:
        sage: rot_left(4,1,3)
        1
        sage: rot_left(4,1,4)
        8
    """
    s = word_size
    return (word << r % s) & (2 ** s - 1) | ((word & (2 ** s - 1)) >> (s - (r % s)))


def toyspn2_cipher_gen(X, K, verb=False):
    round_key = K
    state = X
    if verb:
        print(f'input:      {state:0{block_bit_size}b}')
    word_bit_size = int(log(len(sbox),2))
    for i in range(number_of_rounds):
        round_key = rot_left(round_key, rotation_amount, key_bit_size)
        state = xor(state, round_key)
        if verb:
            print(f'round {i}:\nafter xor:  {state:0{block_bit_size}b}')
        state = sbox_layer(state, block_bit_size, sbox)
        if verb:
            print(f'after sbox: {state:0{block_bit_size}b}')
        state = rot_left(state, rotation_amount, block_bit_size)
        if verb:
            print(f'after rotl: {state:0{block_bit_size}b}')
    return state


def differential_probability(alpha, beta, k):
    count = 0
    for x in range(1<<block_bit_size):
        y0 = toyspn2_cipher_gen(x, k)
        y1 = toyspn2_cipher_gen(x ^ alpha, k)
        # print(f'{x}, {y0:06b}, {y1:06b}, {(y0^y1):06b}')
        if y0 ^ y1 == beta:
            count = count + 1
    return count / (1<<block_bit_size)


def partition_keys(alpha, beta, number_of_keys):
    expected_differential_probability = 0
    key_partition = {}
    for k in range(number_of_keys):
        dp = differential_probability(alpha, beta, k)
        if dp > 1:
            print(f'{k = } - ERROR!!!')
        expected_differential_probability = expected_differential_probability + dp
        if dp in key_partition.keys():
            key_partition[dp]["key_count"] = key_partition[dp]["key_count"] + 1
            key_partition[dp]["key_proportion"] = key_partition[dp]["key_count"] / number_of_keys
        else:
            key_partition[dp] = {"dp":  dp, "key_count": 1, "key_proportion": 1 / number_of_keys}
    expected_differential_probability = expected_differential_probability / number_of_keys
    return key_partition, expected_differential_probability

# # compare implementation with raghav's
# key = 0b000001
# plaintext = 0b000001
# print(f'toyspn2_cipher_gen:')
# print(f'{toyspn2_cipher_gen(plaintext, key, verb=True):06b}')
# print(f'toyspn2_cipher:')
# print(f'{toyspn2_cipher(plaintext, key, verb=True):06b}')

# # test differential probability
# alpha = 0b001001
# beta = 0b010010
# key = 0b000000
# dp = differential_probability(alpha, beta, key)
# print((f'{dp = }'))

# partition keys 6 bit case
alpha = 0b001001
beta  = 0b010010

# # partition keys 9 bit case
# alpha = 0b000001001
# beta  = 0b000010010

# # partition keys 12 bit case
# alpha = 0b001001001001
# beta  = 0b010010010010

key_partition, heuristic_expected_differential_probability = partition_keys(alpha, beta, 2 ** key_bit_size)

print(f'{heuristic_expected_differential_probability = }')
from sage.crypto.sbox import SBox
sbox_bit_size = int(log(len(sbox),2))
sbox_dp = SBox(sbox).differential_uniformity() / (2**sbox_bit_size)
number_of_sboxes_per_round = block_bit_size / sbox_bit_size
theoretical_expected_differential_probability = (sbox_dp * number_of_sboxes_per_round) ** number_of_rounds
print(f'{theoretical_expected_differential_probability = }')
for key in  key_partition.keys():
    print(f'{key_partition[key] = }')
