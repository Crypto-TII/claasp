import math


def toyspn_chi(x0, x1, x2):
    y0 = x0 ^ (1 ^ x1) & x2
    y1 = x1 ^ (1 ^ x2) & x0
    y2 = x2 ^ (1 ^ x0) & x1
    return y0, y1, y2


def toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=False):
    x0 = x0 ^ k0
    x1 = x1 ^ k1
    x2 = x2 ^ k2
    x3 = x3 ^ k3
    x4 = x4 ^ k4
    x5 = x5 ^ k5
    if verb:
        print(f'after xor: {x0}{x1}{x2}{x3}{x4}{x5}')
    y0, y1, y2 = toyspn_chi(x0, x1, x2)
    y3, y4, y5 = toyspn_chi(x3, x4, x5)
    if verb:
        print(f'after sbox: {y0}{y1}{y2}{y3}{y4}{y5}')
        print(f'after rotl: {y5}{y0}{y1}{y2}{y3}{y4}')
    return y5, y0, y1, y2, y3, y4


def toyspn_update_key(k0, k1, k2, k3, k4, k5):
    return k5, k0, k1, k2, k3, k4


def toyspn2_cipher(X, K, verb=False):
    x0 = (X >> 5) & 1
    x1 = (X >> 4) & 1
    x2 = (X >> 3) & 1
    x3 = (X >> 2) & 1
    x4 = (X >> 1) & 1
    x5 = (X >> 0) & 1
    k0 = (K >> 5) & 1
    k1 = (K >> 4) & 1
    k2 = (K >> 3) & 1
    k3 = (K >> 2) & 1
    k4 = (K >> 1) & 1
    k5 = (K >> 0) & 1
    if verb:
        print(f'input:      {x0}{x1}{x2}{x3}{x4}{x5}')
        print(f'key:        {k0}{k1}{k2}{k3}{k4}{k5}')
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)
    k0, k1, k2, k3, k4, k5 = toyspn_update_key(k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5, verb=verb)
    # x0 = x0 ^ k0
    # x1 = x1 ^ k1
    # x2 = x2 ^ k2
    # x3 = x3 ^ k3
    # x4 = x4 ^ k4
    # x5 = x5 ^ k5
    return x5 | (x4 << 1) | (x3 << 2) | (x2<<3) | (x1<<4) | (x0<<5)


def toyspn3_cipher(X, K):
    """
    Takes independent random round keys, with no key schedule
    """
    x0 = (X>>5) & 1
    x1 = (X>>4) & 1
    x2 = (X>>3) & 1
    x3 = (X>>2) & 1
    x4 = (X>>1) & 1
    x5 = (X>>0) & 1
    k0 = (K >> 5) & 1
    k1 = (K >> 4) & 1
    k2 = (K >> 3) & 1
    k3 = (K >> 2) & 1
    k4 = (K >> 1) & 1
    k5 = (K >> 0) & 1
    k6 = (K >> 11) & 1
    k7 = (K >> 10) & 1
    k8 = (K >> 9) & 1
    k9 = (K >> 8) & 1
    k10 = (K >> 7) & 1
    k11 = (K >> 6) & 1
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k0, k1, k2, k3, k4, k5)
    x0, x1, x2, x3, x4, x5 = toyspn_round(x0, x1, x2, x3, x4, x5, k6, k7, k8, k9, k10, k11)
    # x0 = x0 ^ k0
    # x1 = x1 ^ k1
    # x2 = x2 ^ k2
    # x3 = x3 ^ k3
    # x4 = x4 ^ k4
    # x5 = x5 ^ k5
    return x5 | (x4 << 1) | (x3 << 2) | (x2 << 3) | (x1 << 4) | (x0 << 5)


def diff_prob(alpha, beta, k, cipher):
    count = 0
    for x in range(1<<6):
        if cipher(x, k) ^ cipher(x ^ alpha, k) == beta:
            count = count + 1
    return count / (1<<6)


def partition_keys(cipher, alpha, beta, number_of_keys):
    expected_differential_probability = 0
    key_partition = {}
    for k in range(number_of_keys):
        differential_probability = diff_prob(alpha, beta, k, cipher)
        if differential_probability > 1:
            print(f'{k = } - ERROR!!!')
        expected_differential_probability = expected_differential_probability + differential_probability
        if differential_probability in key_partition.keys():
            key_partition[differential_probability]["key_count"] = key_partition[differential_probability]["key_count"] + 1
            key_partition[differential_probability]["key_proportion"] = key_partition[differential_probability]["key_count"] / number_of_keys
        else:
            key_partition[differential_probability] = {"dp":  differential_probability, "key_count": 1, "key_proportion": 1 / number_of_keys}
    expected_differential_probability = expected_differential_probability / number_of_keys
    return key_partition, expected_differential_probability

"""
alpha = 9 # 001001
beta = 18 # 010010
key_partition_toyspn2, expected_differential_probability_toyspn2 = partition_keys(toyspn2_cipher, alpha, beta, 64)

print(f'{expected_differential_probability_toyspn2 = }')
for key in  key_partition_toyspn2.keys():
    print(f'{key_partition_toyspn2[key] = }')

key_partition_toyspn3, expected_differential_probability_toyspn3 = partition_keys(toyspn3_cipher, alpha, beta, 2**12)
print(f'{expected_differential_probability_toyspn3 = }')
for key in  key_partition_toyspn3.keys():
    print(f'{key_partition_toyspn3[key] = }')
"""

"""
key_partition_toyspn2 = {}
for K in range(2**6):
    alpha = 9 # 001001
    beta = 18 # 010010
    sol = diff_prob(alpha, beta, K, toyspn2_cipher)
    if sol in key_partition_toyspn2.keys():
        key_partition_toyspn2[sol] = key_partition_toyspn2[sol] + 1
    else:
        key_partition_toyspn2[sol] = 1
    # if sol == 0:
    #     print("{}\t{}\t{}".format(K, sol, 0))
    # else:
    #     print("{}\t{}\t{:.2f}".format(K, sol, math.log(sol/(1.0*64), 2)))


# print("Key\tSol.\tDP (log_2)")

key_partition_toyspn3 = {}
for K in range(2**(6*2)):
    alpha = 9 # 001001
    beta = 18 # 010010
    sol = diff_prob(alpha, beta, K, toyspn3_cipher)
    if sol in key_partition_toyspn3.keys():
        key_partition_toyspn3[sol] = key_partition_toyspn3[sol] + 1
    else:
        key_partition_toyspn3[sol] = 1
    # if sol == 0:
    #     print("{}\t{}\t{}".format(K, sol, 0))
    # else:
    #     print("{}\t{}\t{:.2f}".format(K, sol, math.log(sol/(1.0*64), 2)))
"""