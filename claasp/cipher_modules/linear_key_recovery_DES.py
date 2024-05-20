from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from claasp.ciphers.block_ciphers.des_block_cipher_key_recovery import DESBlockCipherWithout_IP_FP
from claasp.ciphers.block_ciphers.des_1round import DESBlockCipher_1round
from datetime import datetime
import random
import numpy as np
from os import urandom

nb_pairs = 10000 #pow(2,16)
masterkey = 0x10316e028c8f3b4a


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
    cipher = DESBlockCipherWithout_IP_FP(number_of_rounds=number_rounds)
    dictio = {}

    np_key = np.frombuffer(int(masterkey).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_key_repeated = np.repeat(np_key, nb_pairs, axis=1)
    plaintext = np.frombuffer(urandom(nb_pairs*8), dtype = np.uint8).reshape((-1, nb_pairs))
    plaintext_list = [hex(int.from_bytes(plaintext[:,i].tobytes(), byteorder='big')) for i in range(nb_pairs)]
    ciphertext = cipher.evaluate_vectorized([np_key_repeated, plaintext])[0]
    # midpoint = ciphertext.shape[1] // 2
    # # Swap halves
    # ciphertext_swapped = np.hstack((ciphertext[:, midpoint:], ciphertext[:, :midpoint]))
    ciphertext_list = [hex(int.from_bytes(ciphertext[i].tobytes(), byteorder='big')) for i in range(nb_pairs)]
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
    cipher = DESBlockCipherWithout_IP_FP(number_of_rounds=number_rounds)
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
    cipher = DESBlockCipherWithout_IP_FP(number_of_rounds=5)
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
    cipher = DESBlockCipherWithout_IP_FP(number_of_rounds=6)
    partial = cipher.cipher_partial_inverse(5, 5, True)
    start_time = datetime.now()
    count_forward = 0
    count_backward = 0
    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        result = cipher.evaluate([masterkey, plaintext], intermediate_output=True)
        ciphertext = result[0]
        state_round5 = result[1]["round_output"][-1]
        tmp = state_round5 & 0xffffffff
        state_round5_swapped = (tmp << 32) ^ (state_round5 >> 32)
        if test_linear_approximation_on_a_pair(plaintext, state_round5_swapped):
            count_forward += 1
        state64 = partial.evaluate([ciphertext, masterkey])
        tmp = state64 & 0xffffffff
        state64_swapped = (tmp << 32) ^ (state_round5 >> 32)
        if test_linear_approximation_on_a_pair(plaintext, state64_swapped):
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

def generate_pairs(number_of_samples = 2 ** 13):
    des = DESBlockCipherWithout_IP_FP(number_of_rounds=6)
    rng = np.random.default_rng()

    key_data = repeat_input_difference(0x10316e028c8f3b4a, number_of_samples, 8)

    plaintext_data = rng.integers(low=0, high=256, size=(8, number_of_samples), dtype=np.uint8)
    bit_positions = [7,18,24,27,28,29,30,31,47]
    ciphertext_data = des.evaluate_vectorized([key_data, plaintext_data])
    pp = extract_bits(plaintext_data, bit_positions)
    pc = extract_bits(ciphertext_data[0].T, bit_positions)

    count = 0
    for i in range(number_of_samples):
        p_xor = np.bitwise_xor.reduce(pp[i])
        c_xor = np.bitwise_xor.reduce(pc[i])
        if p_xor ^ c_xor == 1:
            count += 1
    #print(count/number_of_samples*1.0)
    return plaintext_data, ciphertext_data[0].T

def extract_bits(columns, positions):
    results = []
    for col in columns.T:
        num = 0
        for i, byte in enumerate(col):
            num = (num << 8) | byte
        column_result = []
        for pos in positions:
            bit = (num >> pos) & 1
            column_result.append(bit)
        results.append(column_result)

    return np.array(results, dtype=np.uint8)

def partial_subkey_recovery_vectorized():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    true_partial_subkey = partial_subkey_recovery_vectorized()
    """
    start_time = datetime.now()
    number_of_samples = 5000
    cipher = DESBlockCipherWithout_IP_FP(number_of_rounds=6)
    plaintext_data_6, ciphertext_data6 = generate_pairs(number_of_samples)
    partial = cipher.cipher_partial_inverse(5, 5, False)
    partial.set_inputs(['cipher_output_5_14', 'linear_layer_5_2'], [64, 48])
    bit_positions = [7, 18, 24, 27, 28, 29, 30, 31, 47]
    python_dict = {}
    max_bias = 0
    true_partial_subkey = 0
    print("Desired partial subkey6 = {}".format(hex(138149613607)))
    print("Partial subkey6 recovery ...")
    # full_subkey6 = 152108258343 <=> partial_subkey6 (30 bits that influences the l.a) = 138149613607 <=> i = 44658535
    # Reduction of the research area:
    for i in range(44658535, 44658635): # range(pow(2,30)) for the full research
        partial_subkey_candidate = gen_partial_subkey(i)
        partial_subkey_candidate_n = repeat_input_difference(partial_subkey_candidate, number_of_samples, 6)
        ciphertext_data5_guess = partial.evaluate_vectorized([ciphertext_data6, partial_subkey_candidate_n])[0]
        midpoint = ciphertext_data5_guess.shape[1] // 2
        # Swap halves
        ciphertext_data5_guess = np.hstack((ciphertext_data5_guess[:, midpoint:], ciphertext_data5_guess[:, :midpoint]))
        pp = extract_bits(plaintext_data_6, bit_positions)
        pc = extract_bits(ciphertext_data5_guess.T, bit_positions)
        count = 0
        for i in range(number_of_samples):
            p_xor = np.bitwise_xor.reduce(pp[i])
            c_xor = np.bitwise_xor.reduce(pc[i])
            if p_xor ^ c_xor == 1:
                count += 1
        bias = abs(float(count)/number_of_samples - 1/2)
        if bias > max_bias:
            max_bias = bias
            true_partial_subkey = partial_subkey_candidate
        python_dict[partial_subkey_candidate] = count
        # print("partial_subkey_candidate, count, bias :", partial_subkey_candidate, count, bias)

    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    print("Partial subkey6 found = {}".format(hex(true_partial_subkey)))
    print("-------------")
    return true_partial_subkey

def get_partial_master_key_from_partial_subkey(partial_subkey_val_int):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    partial_subkey = 138149613607
    master_key_val_str, master_key_mask_str = get_partial_master_key_from_partial_subkey(partial_subkey)
    """
    partial_subkey_bits = (bin(partial_subkey_val_int)[2:]).zfill(48)
    partial_subkey_mask = '000000111111000000111111111111111111000000111111'

    partial_master_key_mask = [0] * 64
    partial_master_key_val = [0] * 64

    # Subkey K6 contains the positions of master key bits indexed from left to right
    K6 = [2, 43, 26, 16, 41, 9, 25, 49, 59, 1, 40, 34, 24, 56, 18, 17, 0,
          50, 51, 58, 57, 48, 10, 33, 12, 22, 29, 44, 62, 61, 37, 20, 30,
          11, 13, 54, 19, 46, 28, 53, 5, 14, 3, 4, 38, 52, 45, 21]

    for i in range(48):
        if partial_subkey_mask[i] == '1':
            for j in range(64):
                if K6[i] == j:
                    partial_master_key_mask[j] = 1
                    partial_master_key_val[j] = int(partial_subkey_bits[i])
                    break

    master_key_mask_str = ''.join(map(str, partial_master_key_mask))
    master_key_val_str = ''.join(map(str, partial_master_key_val))

    return master_key_val_str, master_key_mask_str

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

def get_full_masterkey_from_partial_masterkey(partial_masterkey, partial_masterkey_mask):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    masterkey = get_full_masterkey_from_partial_masterkey(master_key_val_str, master_key_mask_str)
    """
    # Need to take the parameters from get_partial_master_key_from_partial_subkey() method
    partial_masterkey = int(partial_masterkey, 2)
    known_bits_position = int(partial_masterkey_mask, 2)
    print("Exhaustive search of the 26 remaining bits of the master key ...")
    unknown_bits_position = []
    for i in range(64):
        if known_bits_position & (1 << i) == 0:
            unknown_bits_position.append(i)

    cipher = DESBlockCipher(number_of_rounds=6)
    plaintext = random.getrandbits(64)
    ciphertext = cipher.evaluate([masterkey, plaintext])

    start_time = datetime.now()
    # full_masterkey = 1166834735692856138 <=> partial_masterkey (34 remaining bits) = 387030374883592 <=> i = 46158058
    # Reduction of the research area:
    flag_masterkey_found = 0
    # Code can be improved by using vectorized evaluation here:
    for i in range(46158000, 46158100): # range(pow(2,26)) for the full research
        guess_rest_of_partial_masterkey = gen_rest_of_masterkey(i, unknown_bits_position)
        guessed_master_key = guess_rest_of_partial_masterkey ^ partial_masterkey
        ciphertext_from_guessed_master_key = cipher.evaluate([guessed_master_key, plaintext])
        if ciphertext == ciphertext_from_guessed_master_key:
            flag_masterkey_found = 1
            break
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    if not flag_masterkey_found:
        print("Master key not found")
    else:
        print("Master key found")
    return guessed_master_key

def master_key_recovery():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    master_key = master_key_recovery()
    """
    # the master_key found does not coincide entirely to the real master_key because of the 8 bits used for parity.
    true_partial_subkey = partial_subkey_recovery_vectorized()
    master_key_val_str, master_key_mask_str = get_partial_master_key_from_partial_subkey(true_partial_subkey)
    master_key_found = get_full_masterkey_from_partial_masterkey(master_key_val_str, master_key_mask_str)
    return master_key_found
