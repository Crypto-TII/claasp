from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from datetime import datetime
import random
import numpy as np
from os import urandom

nb_rounds = 5
nb_pairs = 10000 # pow(2,16)
key = 0x10316e028c8f3b4a

def test_vector_vectorized(number_rounds=16):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_vector_vectorized()
    """
    # For k = 0x10316e028c8f3b4a and p = 0, we should get c = 0x82dcbafbdeab6602
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)

    pairs = 3
    np_key = np.frombuffer(int(key).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_key_repeated = np.repeat(np_key, pairs, axis=1)
    np_plaintext = np.frombuffer(int(0).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
    np_plaintext_repeated = np.repeat(np_plaintext, pairs, axis=1)
    ciphertext = cipher.evaluate_vectorized([np_key_repeated, np_plaintext_repeated])
    ciphertext_list = [hex(int.from_bytes(ciphertext[0][i].tobytes(), byteorder='big')) for i in range(pairs)]
    print(ciphertext_list)

    end_time = datetime.now()
    print('Duration for evaluation: {}'.format(end_time - start_time))

def generate_npairs_vectorized(number_rounds=nb_rounds):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    d = generate_npairs_vectorized()
    """
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)
    dictio = {}

    np_key = np.frombuffer(int(key).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1,1)
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

def generate_npairs(number_rounds=nb_rounds):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    d = generate_npairs()
    """
    start_time = datetime.now()
    cipher = DESBlockCipher(number_of_rounds=number_rounds)
    dictio = {}

    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        ciphertext = cipher.evaluate([key, plaintext])
        dictio[plaintext] = ciphertext

    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    return dictio


def xor_bits(state32, position):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    s = 0xabcd0123
    xor_bits(s, [1,2])
    # position is a list of indexes that starts from 1 to the left (msb)
    """
    res = 0
    for i in position:
        res ^= (state32 & (1 << (32 - i))) >> (32 - i)
    return res

def test_linear_approximation_on_a_pair(plaintext, ciphertext):
    position_left = [17]
    position_right = [1,2,3,4,5,8,14,25]
    # position_left = [15]
    # position_right = [7,18,24,27,28,29,30,31]

    plaintext_right = plaintext & 0xffffffff
    plaintext_left = (plaintext & 0xffffffff00000000) >> 32
    ciphertext_right = ciphertext & 0xffffffff
    ciphertext_left = (ciphertext & 0xffffffff00000000) >> 32
    return xor_bits(plaintext_right, position_right) ^ xor_bits(plaintext_left, position_left) ^ xor_bits(ciphertext_right, position_right) ^ xor_bits(ciphertext_left, position_left)

def test_linear_approx_on_multiple_pair(number_rounds=nb_rounds):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair()
    """
    cipher = DESBlockCipher(number_of_rounds=number_rounds)
    start_time = datetime.now()
    count = 0
    for _ in range(nb_pairs):
        plaintext = random.getrandbits(64)
        ciphertext = cipher.evaluate([key, plaintext])
        if test_linear_approximation_on_a_pair(plaintext, ciphertext):
            count += 1
    print("count = {}".format(count))
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))

def test_linear_approx_on_multiple_pair_vectorized():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    test_linear_approx_on_multiple_pair_vectorized()
    """
    start_time = datetime.now()
    count = 0
    dictio = generate_npairs_vectorized()
    for plaintext in list(dictio.keys()):
        if test_linear_approximation_on_a_pair(int(plaintext,16), int(dictio[plaintext], 16)):
            count += 1
    print("count = {}".format(count))
    end_time = datetime.now()
    print('Duration for testing linear approx: {}'.format(end_time - start_time))

def gen_partial_subkey(i):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    gen_partial_subkey(44658535)
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

def partial_subkey_recovery():
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    partial_subkey_recovery()
    """
    cipher = DESBlockCipher(number_of_rounds=nb_rounds+1)
    partial = cipher.cipher_partial_inverse(nb_rounds, nb_rounds, True)

    dictio_using_key = generate_npairs_vectorized()
    ciphertext_list = [int(c, 16) for c in dictio_using_key.values()]
    np_ciphertexts = [
        np.frombuffer(int(ciphertext_list[i]).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1, 1) for i
        in range(nb_pairs)]
    np_ciphertexts_concat = np.dstack(np_ciphertexts).reshape(-1, nb_pairs)

    start_time = datetime.now()
    max_bias = 0
    true_partial_subkey = 0
    count = 0
    print("Desired partial subkey6 = {}".format(hex(138149613607)))
    print("Partial subkey6 recovery ...")
    # full_subkey6 = 152108258343 <=> partial_subkey6 (30 bits that influences the l.a) = 138149613607 <=> i = 44658535
    # Reduction of the research area:
    for i in range(44658533, 44658538): # range(pow(2,34)) for the full research
        partial_subkey = gen_partial_subkey(i)
        np_partial_subkey = np.frombuffer(int(partial_subkey).to_bytes(length=8, byteorder='big'), dtype=np.uint8).reshape(-1, 1)
        np_partial_subkey_repeated = np.repeat(np_partial_subkey, nb_pairs, axis=1)

        state64 = partial.evaluate_vectorized([np_partial_subkey_repeated, np_ciphertexts_concat]) # TODO: check if order is correct
        state64_list = [hex(int.from_bytes(state64[0][i].tobytes(), byteorder='big')) for i in range(nb_pairs)]

        for index, plaintext in enumerate(dictio_using_key.keys()):
            if test_linear_approximation_on_a_pair(int(plaintext,16), int(state64_list[index],16)):
                count += 1
        bias = abs(float(count) - nb_pairs/2)/nb_pairs
        if bias > max_bias:
            max_bias = bias
            true_partial_subkey = partial_subkey
        # max = bias
        count = 0
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    print("Partial subkey6 = {}".format(hex(true_partial_subkey)))
    print("-------------")

    return true_partial_subkey

# Symbolic master key
symbolic_master_key = ["k" + str(i) for i in range(64)]
# print("6th round subkey:")
subkey6 = ['k2', 'k43', 'k26', 'k16', 'k41', 'k9', 'k25', 'k49', 'k59', 'k1', 'k40', 'k34', 'k24', 'k56', 'k18', 'k17', 'k0',
      'k50', 'k51', 'k58', 'k57', 'k48', 'k10', 'k33', 'k12', 'k22', 'k29', 'k44', 'k62', 'k61', 'k37', 'k20', 'k30',
      'k11', 'k13', 'k54', 'k19', 'k46', 'k28', 'k53', 'k5', 'k14', 'k3', 'k4', 'k38', 'k52', 'k45', 'k21']
symbolic_key = symbolic_master_key

def partial_master_key_recovery(val_int, symbolic_key, subkey6):
    """
    # subkey6 = 0b000000000010000000101010010110111101000000100111 = 138149613607 (30 bits correctly guessed of subkey6)
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

def gen_partial_key(i, unknown_bits_position):
    """
    from claasp.cipher_modules.linear_key_recovery_DES import *
    bin(gen_partial_key(15, [1,2,3,6]))
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
    master_key_recovery()
    """
    # partial_subkey = partial_subkey_recovery()
    partial_subkey = 138149613607 # to be removed
    partial_key, known_bits_position = partial_master_key_recovery(partial_subkey, symbolic_key, subkey6)
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

    cipher = DESBlockCipher(number_of_rounds=nb_rounds)
    plaintext = random.getrandbits(64)
    ciphertext = cipher.evaluate([key, plaintext])

    start_time = datetime.now()
    # full_masterkey = 1166834735692856138 <=> partial_masterkey (34 remaining bits) = 387030374883592 <=> i = 46158058
    # Reduction of the research area:
    for i in range(46158055, 46158060): # range(pow(2,34)) for the full research
        guess_partial_key = gen_partial_key(i, unknown_bits_position)
        guessed_master_key = guess_partial_key ^ partial_key
        ciphertext_from_guessed_master_key = cipher.evaluate([guessed_master_key, plaintext])
        if ciphertext == ciphertext_from_guessed_master_key:
            end_time = datetime.now()
            print('Duration: {}'.format(end_time - start_time))
            return guessed_master_key
    end_time = datetime.now()
    print('Duration: {}'.format(end_time - start_time))
    print("Master key not found")



# pos: 000000 111111 000000 111111 111111 111111 000000 111111
# val: 000000 000010 000000 101010 010110 111101 000000 100111
# 0000 0011 1111 0000 0011 1111 1111 1111 1111 0000 0011 1111