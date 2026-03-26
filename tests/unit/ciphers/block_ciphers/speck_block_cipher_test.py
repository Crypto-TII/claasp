from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_speck_block_cipher():
    speck = SpeckBlockCipher()
    assert speck.type == 'block_cipher'
    assert speck.family_name == 'speck'
    assert speck.number_of_rounds == 22
    assert speck.id == 'speck_p32_k64_o32_r22'
    assert speck.component_from(0, 0).id == 'rot_0_0'

    speck = SpeckBlockCipher(number_of_rounds=4)
    assert speck.number_of_rounds == 4
    assert speck.id == 'speck_p32_k64_o32_r4'
    assert speck.component_from(3, 0).id == 'constant_3_0'

    speck = SpeckBlockCipher()
    plaintext = 0x6574694c
    key = 0x1918111009080100
    ciphertext = 0xa86842f2
    assert speck.evaluate([plaintext, key]) == ciphertext
    assert speck.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    assert speck.evaluate_vectorized_gpu([plaintext, key], evaluate_api=True) == ciphertext

    speck = SpeckBlockCipher(block_bit_size=64, key_bit_size=96)
    plaintext = 0x74614620736e6165
    key = 0x131211100b0a090803020100
    ciphertext = 0x9f7952ec4175946c
    assert speck.evaluate([plaintext, key]) == ciphertext
    assert speck.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext
    assert speck.evaluate_vectorized_gpu([plaintext, key], evaluate_api=True) == ciphertext

def test_differential_checker_speck32_gpu_scalability():
    """
    Experimental verification of differential characteristics for Speck32/64
    from Table 4 of [FWGSH2016]_ using GPU acceleration only.

    Shows how GPU enables verification of higher-round distinguishers
    by processing larger sample sizes in feasible time.

    Input difference: (Delta_L=0x0211, Delta_R=0x0A04)
    Theoretical probability for 9 rounds: 2^-30.
    """
    import time
    import math
    import numpy as np
    try:
        import cupy as cp
    except ImportError:
        return  # Skip if CuPy not available

    from claasp.cipher_modules.models.utils import differential_checker_for_block_cipher_single_key

    input_difference = (0x0211 << 16) | 0x0A04
    fixed_key = 0x0000000000000000
    seed = 42

    rounds_data = {
        1: {'out_diff': (0x2800, 0x0010), 'log2_prob': -4},
        3: {'out_diff': (0x8000, 0x8000), 'log2_prob': -6},
        5: {'out_diff': (0x8004, 0x840E), 'log2_prob': -10},
        7: {'out_diff': (0x5002, 0x0420), 'log2_prob': -25},
        9: {'out_diff': (0x1001, 0x5001), 'log2_prob': -30},
    }

    print("\n")
    print("=" * 70)
    print("  Speck32/64 - GPU Differential Verification (Table 4 [FWGSH2016])")
    print(f"  Input difference: {hex(input_difference)}")
    print("=" * 70)
    print(f"  {'rounds':>6} | {'samples':>8} | {'GPU log2p':>10} | {'theo':>6} | {'time':>8}")
    print("-" * 70)

    for number_of_rounds, data in rounds_data.items():
        speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64,
                                 number_of_rounds=number_of_rounds)
        block_size = speck.inputs_bit_size[0]
        key_size = speck.inputs_bit_size[1]

        out_L, out_R = data['out_diff']
        output_difference = (out_L << 16) | out_R
        number_of_samples = min(1 << (-data['log2_prob'] + 4), 1 << 25)
        samples_exp = int(math.log2(number_of_samples))

        start = time.time()
        log2p_gpu = differential_checker_for_block_cipher_single_key(
            speck, input_difference, output_difference,
            number_of_samples, block_size, key_size, fixed_key, seed,
            use_gpu=True
        )
        t_gpu = time.time() - start

        print(f"  {number_of_rounds:>6} | {'2^'+str(samples_exp):>8} | {log2p_gpu:>10.2f} | {data['log2_prob']:>6} | {t_gpu:>7.2f}s")

    print("=" * 70)