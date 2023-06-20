from math import log

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
    """
    Example:
        sage: from toyspn2 import toyspn2_cipher_gen
        sage: bin(toyspn2_cipher_gen(0b000000, 0b000001))
        '0b11001'
    """
    round_key = K
    state = X
    if verb:
        print(f'X:      {state:0{block_bit_size}b}')
        print(f'K:      {round_key:0{block_bit_size}b}')
    word_bit_size = int(log(len(sbox),2))
    for i in range(number_of_rounds):
        round_key = rot_left(round_key, rotation_amount, key_bit_size)
        state = xor(state, round_key)
        if verb:
            print(f'round {i}:\nafter xor(state):      {state:0{block_bit_size}b}')
            print(f'after xor(round key):  {round_key:0{block_bit_size}b}')
        state = sbox_layer(state, block_bit_size, sbox)
        if verb:
            print(f'after sbox(state):     {state:0{block_bit_size}b}')
        state = rot_left(state, rotation_amount, block_bit_size)
        if verb:
            print(f'after rotl(state):     {state:0{block_bit_size}b}')
    return state