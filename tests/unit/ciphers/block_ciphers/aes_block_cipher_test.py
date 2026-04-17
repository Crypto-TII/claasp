from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.cipher_modules.code_generator import generate_numba_cipher_evaluation_kernel
from numba import cuda, uint8, uint16, uint32, uint64
import numpy as np
import pytest

def test_aes128_block_cipher():
    """Test AES-128 with test vectors from NIST SP 800-38A."""
    aes128 = AESBlockCipher(key_bit_size=128)
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    
    # Test vectors extracted from NIST SP 800-38A Appendix F.1.1
    test_vectors = [
        (0x6bc1bee22e409f96e93d7e117393172a, 0x3ad77bb40d7a3660a89ecaf32466ef97),
        (0xae2d8a571e03ac9c9eb76fac45af8e51, 0xf5d3d58503b9699de785895a96fdbaaf),
        (0x30c81c46a35ce411e5fbc1191a0a52ef, 0x43b1cd7f598ece23881b00e3ed030688),
        (0xf69f2445df4f9b17ad2b417be66c3710, 0x7b0c785e27e8ad3f8223207104725dd4),
    ]
    
    for plaintext, expected_ciphertext in test_vectors:
        result = aes128.evaluate([key, plaintext])
        assert result == expected_ciphertext, \
            f"AES-128 encryption failed: plaintext={plaintext:032x}, expected={expected_ciphertext:032x}, got={result:032x}"
    
    # Verify cipher structure
    assert aes128.inputs_bit_size[0] == 128  # key size
    assert aes128.output_bit_size == 128  # block size
    assert aes128.number_of_rounds == 10
    assert aes128.Nk == 4  # 4 words in key
    assert aes128.Nr == 10  # 10 rounds


def test_aes192_block_cipher():
    """Test AES-192 with test vectors from NIST SP 800-38A."""
    aes192 = AESBlockCipher(key_bit_size=192)
    key = 0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    
    # Test vectors extracted from NIST SP 800-38A Appendix F.1.3
    test_vectors = [
        (0x6bc1bee22e409f96e93d7e117393172a, 0xbd334f1d6e45f25ff712a214571fa5cc),
        (0xae2d8a571e03ac9c9eb76fac45af8e51, 0x974104846d0ad3ad7734ecb3ecee4eef),
        (0x30c81c46a35ce411e5fbc1191a0a52ef, 0xef7afd2270e2e60adce0ba2face6444e),
        (0xf69f2445df4f9b17ad2b417be66c3710, 0x9a4b41ba738d6c72fb16691603c18e0e),
    ]
    
    for plaintext, expected_ciphertext in test_vectors:
        result = aes192.evaluate([key, plaintext])
        assert result == expected_ciphertext, \
            f"AES-192 encryption failed: plaintext={plaintext:032x}, expected={expected_ciphertext:032x}, got={result:032x}"
    
    # Verify cipher structure
    assert aes192.inputs_bit_size[0] == 192  # key size
    assert aes192.output_bit_size == 128  # block size
    assert aes192.number_of_rounds == 12
    assert aes192.Nk == 6  # 6 words in key
    assert aes192.Nr == 12  # 12 rounds


def test_aes256_block_cipher():
    """Test AES-256 with test vectors from NIST SP 800-38A."""
    aes256 = AESBlockCipher(key_bit_size=256)
    key = 0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    
    # Test vectors extracted from NIST SP 800-38A Appendix F.1.5
    test_vectors = [
        (0x6bc1bee22e409f96e93d7e117393172a, 0xf3eed1bdb5d2a03c064b5a7e3db181f8),
        (0xae2d8a571e03ac9c9eb76fac45af8e51, 0x591ccb10d410ed26dc5ba74a31362870),
        (0x30c81c46a35ce411e5fbc1191a0a52ef, 0xb6ed21b99ca6f4f9f153e7b1beafed1d),
        (0xf69f2445df4f9b17ad2b417be66c3710, 0x23304b7a39f9f3ff067d8d8f9e24ecc7),
    ]
    
    for plaintext, expected_ciphertext in test_vectors:
        result = aes256.evaluate([key, plaintext])
        assert result == expected_ciphertext, \
            f"AES-256 encryption failed: plaintext={plaintext:032x}, expected={expected_ciphertext:032x}, got={result:032x}"
    
    # Verify cipher structure
    assert aes256.inputs_bit_size[0] == 256  # key size
    assert aes256.output_bit_size == 128  # block size
    assert aes256.number_of_rounds == 14
    assert aes256.Nk == 8  # 8 words in key
    assert aes256.Nr == 14  # 14 rounds


def test_aes_parameters_configuration_list():
    """Verify PARAMETERS_CONFIGURATION_LIST contains all three AES variants."""
    from claasp.ciphers.block_ciphers.aes_block_cipher import PARAMETERS_CONFIGURATION_LIST
    
    assert len(PARAMETERS_CONFIGURATION_LIST) == 3
    
    # Check AES-128 configuration
    aes128_config = PARAMETERS_CONFIGURATION_LIST[0]
    assert aes128_config['key_bit_size'] == 128
    assert aes128_config['number_of_rounds'] == 10
    
    # Check AES-192 configuration
    aes192_config = PARAMETERS_CONFIGURATION_LIST[1]
    assert aes192_config['key_bit_size'] == 192
    assert aes192_config['number_of_rounds'] == 12
    
    # Check AES-256 configuration
    aes256_config = PARAMETERS_CONFIGURATION_LIST[2]
    assert aes256_config['key_bit_size'] == 256
    assert aes256_config['number_of_rounds'] == 14


def test_aes_invalid_key_size():
    """Test that invalid key sizes raise ValueError."""
    try:
        aes = AESBlockCipher(key_bit_size=512)
        assert False, "Expected ValueError for invalid key_bit_size"
    except ValueError as e:
        assert "Invalid key_bit_size" in str(e)





def test_aes_numba_batch_efficiency_against_evaluate_vectorized_r2():
    import time

    aes = AESBlockCipher(key_bit_size=128, number_of_rounds=2)
    timeout_seconds = 30.0
    sample_exponents = [12, 14, 16, 18, 20]
    rng = np.random.default_rng(12)

    key_n = aes.inputs_bit_size[aes.inputs.index('key')] // 8
    pt_n = aes.inputs_bit_size[aes.inputs.index('plaintext')] // 8

    _, code = generate_numba_cipher_evaluation_kernel(aes, mode='differential')
    device_code = code.split('@cuda.jit\ndef differential_kernel')[0]

    eg = {
        'cuda': cuda,
        'uint8': uint8,
        'uint16': uint16,
        'uint32': uint32,
        'uint64': uint64,
        'np': np,
    }
    exec(device_code, eg)
    batch_kernel_code = """@cuda.jit
def test_kernel_aes_batch(key, pt, out):
    i = cuda.grid(1)
    if i < pt.shape[1]:
        evaluate_cipher(pt[:, i], key[:, i], out[:, i])
"""
    exec(batch_kernel_code, eg)

    warm_key = np.zeros((key_n, 1), dtype=np.uint8)
    warm_pt = np.zeros((pt_n, 1), dtype=np.uint8)
    warm_out = np.zeros((pt_n, 1), dtype=np.uint8)
    d_warm_key = cuda.to_device(warm_key)
    d_warm_pt = cuda.to_device(warm_pt)
    d_warm_out = cuda.to_device(warm_out)
    eg['test_kernel_aes_batch'][1, 1](d_warm_key, d_warm_pt, d_warm_out)
    cuda.synchronize()

    print("\n")
    print("=" * 92)
    print("  AES-128 r2 - Batch Efficiency: evaluate_vectorized vs Numba")
    print(f"  timeout per backend: {timeout_seconds:.0f}s")
    print("=" * 92)
    print(f"  {'samples':>10} | {'CPU time':>12} | {'Numba time':>12} | {'speedup':>10}")
    print("-" * 92)

    for exp in sample_exponents:
        num_samples = 1 << exp
        key_arr = rng.integers(0, 256, size=(key_n, num_samples), dtype=np.uint8)
        pt_arr = rng.integers(0, 256, size=(pt_n, num_samples), dtype=np.uint8)
        input_list = [key_arr if name == 'key' else pt_arr for name in aes.inputs]

        cpu_status = None
        expected = None
        cpu_start = time.perf_counter()
        expected = aes.evaluate_vectorized(input_list)[0].T
        cpu_time = time.perf_counter() - cpu_start
        if cpu_time > timeout_seconds:
            cpu_status = 'TIMEOUT'
            expected = None

        out = np.zeros((pt_n, num_samples), dtype=np.uint8)
        d_key = cuda.to_device(np.ascontiguousarray(key_arr))
        d_pt = cuda.to_device(np.ascontiguousarray(pt_arr))
        d_out = cuda.to_device(out)

        threads_per_block = 128
        blocks = (num_samples + threads_per_block - 1) // threads_per_block

        numba_status = None
        numba_start = time.perf_counter()
        eg['test_kernel_aes_batch'][blocks, threads_per_block](d_key, d_pt, d_out)
        cuda.synchronize()
        got = d_out.copy_to_host()
        numba_time = time.perf_counter() - numba_start
        if numba_time > timeout_seconds:
            numba_status = 'TIMEOUT'

        if expected is not None:
            assert np.array_equal(got, expected)

        cpu_display = cpu_status if cpu_status else f'{cpu_time:.4f}s'
        numba_display = numba_status if numba_status else f'{numba_time:.4f}s'
        if cpu_status or numba_status:
            speedup_display = '-'
        else:
            speedup = cpu_time / numba_time if numba_time > 0 else float('inf')
            speedup_display = f'{speedup:.2f}x'

        print(f"  {'2^'+str(exp):>10} | {cpu_display:>12} | {numba_display:>12} | {speedup_display:>10}")

    print("=" * 92)
