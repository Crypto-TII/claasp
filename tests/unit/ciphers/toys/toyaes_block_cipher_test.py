from claasp.ciphers.toys.toyaes_block_cipher import ToyAESBlockCipher
from claasp.cipher_modules.code_generator import generate_numba_cipher_evaluation_kernel
from numba import cuda, uint8, uint16, uint32, uint64
import numpy as np
import pytest
import time


def test_aes_block_cipher():
    aes = ToyAESBlockCipher()
    assert aes.type == 'block_cipher'
    assert aes.family_name == 'aes_block_cipher'
    assert aes.number_of_rounds == 10
    assert aes.id == 'aes_block_cipher_k128_p128_o128_r10'
    assert aes.component_from(0, 0).id == 'xor_0_0'
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes128_block_cipher():
    aes = ToyAESBlockCipher()
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    plaintext = 0x6bc1bee22e409f96e93d7e117393172a
    ciphertext = 0x3ad77bb40d7a3660a89ecaf32466ef97
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_8_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=8, state_size=3)
    key = 0x2b7e151628aed2a6ab
    plaintext = 0x6bc1bee22e409f96e9
    ciphertext = 0xf8666f8d0ba0dcfced
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_8_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=8, state_size=2)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0xdbbdd038
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_4_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=4)
    key = 0x2b7e151628aed2a6
    plaintext = 0x6bc1bee22e409f96
    ciphertext = 0x0e51ff61dac37a78
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_4_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=3)
    key = 0b100111100101111110011110010111110000
    plaintext = 0b100111100101111110011110010111110000
    ciphertext = 0x3a54a9d02
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext


def test_aes_4_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=4, state_size=2)
    key = 0x2b7e
    plaintext = 0x6bc1
    ciphertext = 0xa1fe
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=4)
    key = 0x2b7e151628ae
    plaintext = 0x6bc1bee22e40
    ciphertext = 0x33d9c96fe11c
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=3)
    key = 0b101101101101101101100011011
    plaintext = 0b100001111011110101101100010
    ciphertext = 0x0595c25b
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_3_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=3, state_size=2)
    key = 0x2b7
    plaintext = 0x6bc
    ciphertext = 0x2c8
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_4_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=4, number_of_rounds=1)
    key = 0x2b7e1516
    plaintext = 0x6bc1bee2
    ciphertext = 0x5B1536C8
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_3_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=3)
    key = 0b101101101100011011
    plaintext = 0b011110101101100010
    ciphertext = 0x00de3c
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_aes_2_2_block_cipher():
    aes = ToyAESBlockCipher(word_size=2, state_size=2)
    key = 0x2b
    plaintext = 0x6b
    ciphertext = 0x1f
    assert aes.evaluate([key, plaintext]) == ciphertext
    assert aes.evaluate_vectorized([key, plaintext], evaluate_api=True) == ciphertext
    assert aes.evaluate_vectorized_gpu([key, plaintext], evaluate_api=True) == ciphertext

def test_numba_matches_evaluate_vectorized_toyaes_rounds_1_2():
    pt_hex = "6bc1bee22e409f96e93d7e117393172a"
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"

    for rounds in (1, 2):
        cipher = ToyAESBlockCipher(number_of_rounds=rounds)

        pt_n = cipher.inputs_bit_size[cipher.inputs.index("plaintext")] // 8
        key_n = cipher.inputs_bit_size[cipher.inputs.index("key")] // 8
        pt_arr = np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8).reshape(pt_n, 1)
        key_arr = np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8).reshape(key_n, 1)

        input_list = []
        for name in cipher.inputs:
            input_list.append(key_arr if name == "key" else pt_arr)
        expected = cipher.evaluate_vectorized(input_list)[0][0, :].tobytes().hex()

        _, code = generate_numba_cipher_evaluation_kernel(cipher, mode="differential")
        device_code = code.split("@cuda.jit\ndef differential_kernel")[0]

        eg = {
            "cuda": cuda,
            "uint8": uint8,
            "uint16": uint16,
            "uint32": uint32,
            "uint64": uint64,
            "np": np,
        }
        exec(device_code, eg)

        kernel_name = f"test_kernel_toyaes_r{rounds}"
        exec(
            f"@cuda.jit\ndef {kernel_name}(pt, key, out):\n    evaluate_cipher(pt, key, out)",
            eg,
        )

        pt = np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8).copy()
        key = np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8).copy()
        out = np.zeros(pt_n, dtype=np.uint8)

        d_pt = cuda.to_device(pt)
        d_key = cuda.to_device(key)
        d_out = cuda.to_device(out)
        eg[kernel_name][1, 1](d_pt, d_key, d_out)
        cuda.synchronize()

        got = d_out.copy_to_host().tobytes().hex()
        print(f"ToyAES rounds={rounds}")
        print(f"  exp: {expected}")
        print(f"  got: {got}")

        assert got == expected


def test_numba_toyaes_10_rounds_diagnostic_prints_output():
    pt_hex = "6bc1bee22e409f96e93d7e117393172a"
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    rounds = 1
    cipher = ToyAESBlockCipher(number_of_rounds=rounds)

    pt_n = cipher.inputs_bit_size[cipher.inputs.index("plaintext")] // 8

    t0 = time.perf_counter()
    _, code = generate_numba_cipher_evaluation_kernel(cipher, mode="differential")
    t_codegen = time.perf_counter()
    device_code = code.split("@cuda.jit\ndef differential_kernel")[0]

    eg = {
        "cuda": cuda,
        "uint8": uint8,
        "uint16": uint16,
        "uint32": uint32,
        "uint64": uint64,
        "np": np,
    }
    exec(device_code, eg)
    t_exec_device = time.perf_counter()

    kernel_name = f"test_kernel_toyaes_r{rounds}_diagnostic"
    exec(
        f"@cuda.jit\ndef {kernel_name}(pt, key, out):\n    evaluate_cipher(pt, key, out)",
        eg,
    )
    t_exec_kernel = time.perf_counter()

    pt = np.frombuffer(bytes.fromhex(pt_hex), dtype=np.uint8).copy()
    key = np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8).copy()
    out = np.zeros(pt_n, dtype=np.uint8)

    d_pt = cuda.to_device(pt)
    d_key = cuda.to_device(key)
    d_out = cuda.to_device(out)
    t_h2d = time.perf_counter()

    eg[kernel_name][1, 1](d_pt, d_key, d_out)
    cuda.synchronize()
    t_first_launch = time.perf_counter()

    first_got = d_out.copy_to_host().tobytes().hex()
    t_first_copy = time.perf_counter()

    eg[kernel_name][1, 1](d_pt, d_key, d_out)
    cuda.synchronize()
    t_second_launch = time.perf_counter()

    got = d_out.copy_to_host().tobytes().hex()
    t_second_copy = time.perf_counter()

    print(f"ToyAES numba diagnostic rounds={rounds}")
    print(f"  got: {got}")
    print(f"  first_got: {first_got}")
    print(f"  code_len: {len(code)}")
    print(f"  components: {len(cipher.get_all_components())}")
    print(f"  codegen_s: {t_codegen - t0:.6f}")
    print(f"  exec_device_s: {t_exec_device - t_codegen:.6f}")
    print(f"  exec_kernel_wrapper_s: {t_exec_kernel - t_exec_device:.6f}")
    print(f"  host_to_device_s: {t_h2d - t_exec_kernel:.6f}")
    print(f"  first_launch_s: {t_first_launch - t_h2d:.6f}")
    print(f"  first_copy_s: {t_first_copy - t_first_launch:.6f}")
    print(f"  second_launch_s: {t_second_launch - t_first_copy:.6f}")
    print(f"  second_copy_s: {t_second_copy - t_second_launch:.6f}")
    print(f"  total_s: {t_second_copy - t0:.6f}")
