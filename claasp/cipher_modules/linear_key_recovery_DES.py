from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from claasp.ciphers.block_ciphers.des_1round import DESBlockCipher_1round
from datetime import datetime
import random
import numpy as np
from os import urandom

nb_pairs = 5 #pow(2,16)
masterkey = 0x10316e028c8f3b4a

ROUND_PERMUTATION = [8, 16, 22, 30, 12, 27, 1, 17, 23, 15, 29, 5, 25, 19, 9, 0, 7, 13, 24, 2, 3, 28, 10, 18, 31, 11, 21, 6, 4, 26, 14, 20]

ROUND_PERMUTATION_BIN = \
[[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]

EXPANSION = [
                31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8,
                7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
]

def test_vector_vectorized(number_rounds=16):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_vector_vectorized()
    """
    # The following vector test is from "Validating the correctness of hardware implementations of DES".
    # For k = 0x10316e028c8f3b4a and p = 0, we should get c = 0x82dcbafbdeab6602
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)

    pairs = 3
    np_key = np.frombuffer(int(masterkey).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_key_repeated = np.repeat(np_key, pairs, axis=1)
    np_plaintext = np.frombuffer(int(0).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_plaintext_repeated = np.repeat(np_plaintext, pairs, axis=1)
    ciphertext = cipher.evaluate_vectorized([np_key_repeated, np_plaintext_repeated])
    ciphertext_list = [hex(int.from_bytes(ciphertext[0][i].tobytes(), byteorder='big')) for i in range(pairs)]
    print(ciphertext_list)

    end_time = datetime.now()
    print('Duration for evaluation: {}'.format(end_time - start_time))

def generate_npairs_vectorized(number_rounds):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    d = generate_npairs_vectorized(6)
    """
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)
    dictio = {}

    np_key = np.frombuffer(int(masterkey).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_key_repeated = np.repeat(np_key, nb_pairs, axis=1)
    plaintext = np.frombuffer(urandom(nb_pairs*8), dtype = np.uint8).reshape((-1, nb_pairs))
    plaintext_list = [hex(int.from_bytes(plaintext[:,i].tobytes(), byteorder='big')) for i in range(nb_pairs)]
    ciphertext = cipher.evaluate_vectorized([np_key_repeated, plaintext])
    ciphertext_list = [hex(int.from_bytes(ciphertext[0][i].tobytes(), byteorder='big')) for i in range(nb_pairs)]
    for i in range(nb_pairs):
        dictio[plaintext_list[i]] = ciphertext_list[i]

    end_time = datetime.now()
    print('Duration for evaluation: {}'.format(end_time - start_time))
    return dictio


def generate_npairs(number_rounds):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    d = generate_npairs(6)
    """
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)
    dictio = {}

    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        ciphertext = cipher.evaluate([masterkey, plaintext])
        dictio[plaintext] = ciphertext

    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    return dictio


def xor_bits(state32, position):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    s = 0xabcd0123
    xor_bits(s, [1,2])
    # position is a list of indexes that starts from 1 and from the left (msb)
    """
    res = 0
    for i in position:
        res ^= (state32 & (1 << (32 - i))) >> (32 - i)
        # res ^= (state32 & (1 << i)) >> i
    return res

def test_linear_approximation_on_a_pair(plaintext, ciphertext):
    # position_left = [15]
    # position_right = [7,18,24,27,28,29,30,31]
    position_left = [17]
    position_right = [1,2,3,4,5,8,14,25]
    plaintext_right = plaintext & 0xffffffff
    plaintext_left = (plaintext & 0xffffffff00000000) >> 32
    ciphertext_right = ciphertext & 0xffffffff
    ciphertext_left = (ciphertext & 0xffffffff00000000) >> 32
    if xor_bits(plaintext_right, position_right) ^ xor_bits(plaintext_left, position_left) ^ xor_bits(ciphertext_right, position_right) ^ xor_bits(ciphertext_left, position_left):
        return 0
    else:
        return 1

def test_linear_approx_on_multiple_pair():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair()
    """
    cipher = DESBlockCipher(number_of_rounds=5)
    start_time = datetime.now()
    count = 0
    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        ciphertext = cipher.evaluate([masterkey, plaintext])
        if test_linear_approximation_on_a_pair(plaintext, ciphertext):
            count += 1
    print("count = {}".format(count))
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))

def test_linear_approx_on_multiple_pair_backward():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair_backward()
    """
    cipher = DESBlockCipher(number_of_rounds=6)
    partial = cipher.cipher_partial_inverse(5, 5, True)
    start_time = datetime.now()
    count_forward = 0
    count_backward = 0
    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        result = cipher.evaluate([masterkey, plaintext], intermediate_output=True)
        ciphertext = result[0]
        state_round5 = result[1]["round_output"][-1]
        if test_linear_approximation_on_a_pair(plaintext, state_round5):
            count_forward += 1
        state64 = partial.evaluate([ciphertext, masterkey])
        if test_linear_approximation_on_a_pair(plaintext, state64):
            count_backward += 1
        if state64 != state_round5:
            print("error")
    print("count_forward = {}".format(count_forward))
    print("count_backward = {}".format(count_backward))
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))

def test_linear_approx_on_multiple_pair_vectorized():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair_vectorized()
    """
    start_time = datetime.now()
    count = 0
    dictio = generate_npairs_vectorized(5)
    for plaintext in list(dictio.keys()):
        if test_linear_approximation_on_a_pair(int(plaintext,16), int(dictio[plaintext], 16)):
            count += 1
    print("count = {}".format(count))
    end_time = datetime.now()
    print('Duration for testing linear approx: {}'.format(end_time - start_time))

def gen_partial_subkey(i):
    """
    The bits that need to be guessed for the subkey6 are those in position indicated by the 1s:
    000000111111000000111111111111111111000000111111
    This method generate a candidate of subkey6 with respect the above positions.

    from claasp.cipher_modules.linear_key_recovery_DES import *
    hex(gen_partial_subkey(44658535))
    """
    subkey48 = 0
    subkey48 ^= i & 0x3f
    i = i >> 6
    subkey48 ^= (i & 0x3f) << 12
    i = i >> 6
    subkey48 ^= (i & 0x3f) << 18
    i = i >> 6
    subkey48 ^= (i & 0x3f) << 24
    i = i >> 6
    subkey48 ^= (i & 0x3f) << 36
    return subkey48

def repeat_input_difference(input_difference_, number_of_samples_, number_of_bytes_):
    bytes_array = input_difference_.to_bytes(number_of_bytes_, 'big')
    np_array = np.array(list(bytes_array), dtype=np.uint8)
    column_array = np_array.reshape(-1, 1)
    return np.tile(column_array, (1, number_of_samples_))

def test_linear_approx_on_multiple_pair_vectorized_backward():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair_vectorized_backward()
    """
    cipher = DESBlockCipher(number_of_rounds=6)
    des_1round = DESBlockCipher_1round()
    partial = cipher.cipher_partial_inverse(5, 5, True)
    start_time = datetime.now()
    count = 0

    key_data = repeat_input_difference(masterkey, nb_pairs, 8)
    rng = np.random.default_rng()
    plaintext_data = rng.integers(low=0, high=256, size=(8, nb_pairs), dtype=np.uint8)
    plaintext_list = [hex(int.from_bytes(plaintext_data[:,i].tobytes(), byteorder='big')) for i in range(nb_pairs)] # works when reading columns
    ciphertext_data = cipher.evaluate_vectorized([key_data, plaintext_data])

    state64 = partial.evaluate_vectorized([ciphertext_data[0].T, key_data])[0] # carefull, order change with partial
    midpoint = state64.shape[1] // 2
    state64_swapped = np.hstack((state64[:, midpoint:], state64[:, :midpoint]))
    print(state64_swapped)
    state64_list = [hex(int.from_bytes(state64_swapped[i].tobytes(), byteorder='big')) for i in range(nb_pairs)] # works when reading rows

    subkey_data = repeat_input_difference(152108258343, nb_pairs, 8)
    state64_1round = des_1round.evaluate_vectorized([ciphertext_data[0].T, subkey_data])[0]
    print(state64_1round)

    for index, plaintext in enumerate(plaintext_list):
        if test_linear_approximation_on_a_pair(int(plaintext,16), int(state64_list[index],16)):
            count += 1
    print("count = {}".format(count))
    end_time = datetime.now()
    print('Duration for testing linear approx: {}'.format(end_time - start_time))

def invert_manually_vectorized(guess_subkey):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    invert_manually_vectorized(0xabcdef123456)
    """
    cipher = DESBlockCipher(number_of_rounds=2)
    rng = np.random.default_rng()
    plaintext = rng.integers(low=0, high=256, size=(8, nb_pairs), dtype=np.uint8)
    plaintext_list = [hex(int.from_bytes(plaintext[:,i].tobytes(), byteorder='big')) for i in range(nb_pairs)] # works when reading columns
    key = repeat_input_difference(masterkey, nb_pairs, 8)
    ciphertext = cipher.evaluate_vectorized([key, plaintext])[0]
    print(ciphertext)

    ciphertext_right = ciphertext[:, 4:]
    print(ciphertext_right)
    before_expansion_bin = np.unpackbits(ciphertext_right, axis=0)
    print(before_expansion_bin)
    after_expansion_bin = before_expansion_bin.transpose().dot(ROUND_PERMUTATION_BIN).transpose() % 2
    print(after_expansion_bin)

    subkey = repeat_input_difference(guess_subkey, nb_pairs, 6)
    print(subkey)
    subkey_bin = np.unpackbits(subkey, axis=0)
    print(subkey_bin)
    xor = np.bitwise_xor(after_expansion_bin, subkey)
    print(xor)



def partial_subkey_recovery_vectorized():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    true_partial_subkey, Juan = partial_subkey_recovery_vectorized()
    """
    cipher = DESBlockCipher(number_of_rounds=6)
    partial = cipher.cipher_partial_inverse(5, 5, True)
    des_1round = DESBlockCipher_1round()

    start_time = datetime.now()
    count = 0
    rng = np.random.default_rng()
    plaintext_data = rng.integers(low=0, high=256, size=(8, nb_pairs), dtype=np.uint8)
    plaintext_list = [hex(int.from_bytes(plaintext_data[:,i].tobytes(), byteorder='big')) for i in range(nb_pairs)] # works when reading columns
    key_data = repeat_input_difference(masterkey, nb_pairs, 8)
    ciphertext_data = cipher.evaluate_vectorized([key_data, plaintext_data])

    max_bias = 0
    true_partial_subkey = 0
    print("Desired partial subkey6 = {}".format(hex(138149613607)))
    print("Partial subkey6 recovery ...")
    # full_subkey6 = 152108258343 <=> partial_subkey6 (30 bits that influences the l.a) = 138149613607 <=> i = 44658535
    # Reduction of the research area:
    Juan = {} # keys of this dict are the 30 guessed bits of subkey6, the values are the corresponding counters
    for i in [6478, 44658535, 44658000]: #range(44658500, 44658600): # range(pow(2,30)) for the full research
        partial_subkey = gen_partial_subkey(i)
        print(f"--------> sk = {hex(partial_subkey)}")
        subkey_data = repeat_input_difference(partial_subkey, nb_pairs, 8)
        state64 = des_1round.evaluate_vectorized([ciphertext_data[0].T, subkey_data])[0]
        # midpoint = state64.shape[1] // 2
        # state64_swapped = np.hstack((state64[:, midpoint:], state64[:, :midpoint]))
        state64_list = [hex(int.from_bytes(state64[i].tobytes(), byteorder='big')) for i in range(nb_pairs)]
        for index, plaintext in enumerate(plaintext_list):
            if test_linear_approximation_on_a_pair(int(plaintext, 16), int(state64_list[index], 16)):
                count += 1
        bias = abs(float(count)/nb_pairs - 1/2)
        if bias > max_bias:
            max_bias = bias
            true_partial_subkey = partial_subkey
        Juan[partial_subkey] = count
        count = 0
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    print("Partial subkey6 = {}".format(hex(true_partial_subkey)))
    print("-------------")

    return true_partial_subkey, Juan


def partial_subkey_recovery():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    partial_subkey_recovery()
    """
    cipher = DESBlockCipher(number_of_rounds=6)
    partial = cipher.cipher_partial_inverse(5, 5, True)
    dictio_using_key = generate_npairs(6)

    start_time = datetime.now()
    max_bias = 0
    true_partial_subkey = 0
    count = 0
    print("Desired partial subkey6 = {}".format(hex(138149613607)))
    print("Partial subkey6 recovery ...")
    # full_subkey6 = 152108258343 <=> partial_subkey6 (30 bits that influences the l.a) = 138149613607 <=> i = 44658535
    # Reduction of the research area:
    for i in [6478, 44658535, 44658000]: #range(44658534, 44658537): # range(pow(2,34)) for the full research
        partial_subkey = gen_partial_subkey(i)
        # print(f"partial_subkey = {hex(partial_subkey)}")
        for plaintext, ciphertext in dictio_using_key.items():
            # print("ciphertext")
            # print(hex(ciphertext))
            state64 = partial.evaluate([ciphertext, partial_subkey]) # TODO: check if order is correct
            # print("state64")
            # print(hex(state64))
            if test_linear_approximation_on_a_pair(plaintext, state64):
                count += 1
        bias = abs(float(count)/nb_pairs - 1/2)
        print(f"bias = {bias}")
        if bias > max_bias:
            max_bias = bias
            true_partial_subkey = partial_subkey
        print(f"count = {count}")
        count = 0
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    print("Partial subkey6 = {}".format(hex(true_partial_subkey)))
    print("-------------")

    return true_partial_subkey


# Symbolic master key
symbolic_master_key = ["k" + str(i) for i in range(64)]
symbolic_key = symbolic_master_key
subkey6 = ['k2', 'k43', 'k26', 'k16', 'k41', 'k9', 'k25', 'k49', 'k59', 'k1', 'k40', 'k34', 'k24', 'k56', 'k18', 'k17', 'k0',
      'k50', 'k51', 'k58', 'k57', 'k48', 'k10', 'k33', 'k12', 'k22', 'k29', 'k44', 'k62', 'k61', 'k37', 'k20', 'k30',
      'k11', 'k13', 'k54', 'k19', 'k46', 'k28', 'k53', 'k5', 'k14', 'k3', 'k4', 'k38', 'k52', 'k45', 'k21']
# Subkeys in function of the bits of the masterkey:
Cs = {
1 : ['k9', 'k50', 'k33', 'k59', 'k48', 'k16', 'k32', 'k56', 'k1', 'k8', 'k18', 'k41', 'k2', 'k34', 'k25', 'k24', 'k43', 'k57', 'k58', 'k0', 'k35', 'k26', 'k17', 'k40', 'k21', 'k27', 'k38', 'k53', 'k36', 'k3', 'k46', 'k29', 'k4', 'k52', 'k22', 'k28', 'k60', 'k20', 'k37', 'k62', 'k14', 'k19', 'k44', 'k13', 'k12', 'k61', 'k54', 'k30'],
2 : ['k1', 'k42', 'k25', 'k51', 'k40', 'k8', 'k24', 'k48', 'k58', 'k0', 'k10', 'k33', 'k59', 'k26', 'k17', 'k16', 'k35', 'k49', 'k50', 'k57', 'k56', 'k18', 'k9', 'k32', 'k13', 'k19', 'k30', 'k45', 'k28', 'k62', 'k38', 'k21', 'k27', 'k44', 'k14', 'k20', 'k52', 'k12', 'k29', 'k54', 'k6', 'k11', 'k36', 'k5', 'k4', 'k53', 'k46', 'k22'],
3 : ['k50', 'k26', 'k9', 'k35', 'k24', 'k57', 'k8', 'k32', 'k42', 'k49', 'k59', 'k17', 'k43', 'k10', 'k1', 'k0', 'k48', 'k33', 'k34', 'k41', 'k40', 'k2', 'k58', 'k16', 'k60', 'k3', 'k14', 'k29', 'k12', 'k46', 'k22', 'k5', 'k11', 'k28', 'k61', 'k4', 'k36', 'k27', 'k13', 'k38', 'k53', 'k62', 'k20', 'k52', 'k19', 'k37', 'k30', 'k6'],
4 : ['k34', 'k10', 'k58', 'k48', 'k8', 'k41', 'k57', 'k16', 'k26', 'k33', 'k43', 'k1', 'k56', 'k59', 'k50', 'k49', 'k32', 'k17', 'k18', 'k25', 'k24', 'k51', 'k42', 'k0', 'k44', 'k54', 'k61', 'k13', 'k27', 'k30', 'k6', 'k52', 'k62', 'k12', 'k45', 'k19', 'k20', 'k11', 'k60', 'k22', 'k37', 'k46', 'k4', 'k36', 'k3', 'k21', 'k14', 'k53'],
5 : ['k18', 'k59', 'k42', 'k32', 'k57', 'k25', 'k41', 'k0', 'k10', 'k17', 'k56', 'k50', 'k40', 'k43', 'k34', 'k33', 'k16', 'k1', 'k2', 'k9', 'k8', 'k35', 'k26', 'k49', 'k28', 'k38', 'k45', 'k60', 'k11', 'k14', 'k53', 'k36', 'k46', 'k27', 'k29', 'k3', 'k4', 'k62', 'k44', 'k6', 'k21', 'k30', 'k19', 'k20', 'k54', 'k5', 'k61', 'k37'],
6 : ['k2', 'k43', 'k26', 'k16', 'k41', 'k9', 'k25', 'k49', 'k59', 'k1', 'k40', 'k34', 'k24', 'k56', 'k18', 'k17', 'k0', 'k50', 'k51', 'k58', 'k57', 'k48', 'k10', 'k33', 'k12', 'k22', 'k29', 'k44', 'k62', 'k61', 'k37', 'k20', 'k30', 'k11', 'k13', 'k54', 'k19', 'k46', 'k28', 'k53', 'k5', 'k14', 'k3', 'k4', 'k38', 'k52', 'k45', 'k21'],
}

def partial_master_key_recovery(val_int, symbolic_key, subkey6):
    """
    # partial_subkey6 = 0b000000000010000000101010010110111101000000100111 = 138149613607 (30 bits correctly guessed of subkey6)
    from claasp.cipher_modules.linear_key_recovery_DES import *
    partial_master_key_recovery(138149613607, symbolic_key, subkey6)
    """
    val = (bin(val_int)[2:]).zfill(48)
    pos = '000000111111000000111111111111111111000000111111' # pos of the bits that we guessed for subkey6
    master_key_pos = [0] * 64
    master_key_val = [0] * 64

    for i in range(len(pos)):
        if pos[i] == '1':
            for j in range(64):
                if subkey6[i] == symbolic_key[j]:
                    symbolic_key[j] = val[i]
                    master_key_pos[j] = 1
                    master_key_val[j] = int(val[i])
                    break

    master_key_pos_str = ''.join(map(str, master_key_pos))
    master_key_val_str = ''.join(map(str, master_key_val))
    # print("updated key:")
    # print(symbolic_key)
    # print("master_key_pos:", master_key_pos_str)
    # print("master_key_val:", master_key_val_str)
    return int(master_key_val_str,2), int(master_key_pos_str,2)

def gen_rest_of_masterkey(i, unknown_bits_position):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    bin(gen_rest_of_masterkey(15, [1,2,3,6]))
    """
    partial_key = 0
    for index, pos in enumerate(unknown_bits_position):
        if i & (1 << index):
            partial_key ^= 1 << pos
    # print(bin(partial_key))
    return partial_key

def master_key_recovery():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    guessed_master_key, Paul = master_key_recovery()
    """
    # partial_subkey = partial_subkey_recovery_vectorized()
    partial_subkey = 138149613607 # to be removed
    partial_masterkey, known_bits_position = partial_master_key_recovery(partial_subkey, symbolic_key, subkey6)
    print("Exhaustive research of the 34 remaining bits of the master key ...")
    unknown_bits_position = []
    for i in range(64):
        if known_bits_position & (1 << i) == 0:
            unknown_bits_position.append(i)

    # just to checked, cannot be used in real attack, we don't know masterkey
    # unknown = known_bits_position ^ 0xffffffffffffffff
    # masterkey = 0x10316e028c8f3b4a
    # partial_masterkey = masterkey & unknown
    # #printBin(partial_masterkey)
    # #print(0x2c050ea) # 46158058

    cipher = DESBlockCipher(number_of_rounds=6)
    plaintext = random.getrandbits(64)
    ciphertext = cipher.evaluate([masterkey, plaintext])

    start_time = datetime.now()
    # full_masterkey = 1166834735692856138 <=> partial_masterkey (34 remaining bits) = 387030374883592 <=> i = 46158058
    # Reduction of the research area:
    all_guessed_master_key = {}
    flag_masterkey_found = 0
    for i in range(46158055, 46158060): # range(pow(2,34)) for the full research
        guess_rest_of_partial_masterkey = gen_rest_of_masterkey(i, unknown_bits_position)
        guessed_master_key = guess_rest_of_partial_masterkey ^ partial_masterkey
        ciphertext_from_guessed_master_key = cipher.evaluate([guessed_master_key, plaintext])
        if ciphertext == ciphertext_from_guessed_master_key:
            end_time = datetime.now()
            print('Duration: {}'.format(end_time - start_time))
            all_guessed_master_key[guessed_master_key] = True
            # return guessed_master_key
            flag_masterkey_found = 1
            break
        all_guessed_master_key[guessed_master_key] = False
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    if not flag_masterkey_found:
        print("Master key not found")
    else:
        print("Master key found !!!")
    Paul = [all_guessed_master_key, partial_masterkey, unknown_bits_position]
    return guessed_master_key, Paul
