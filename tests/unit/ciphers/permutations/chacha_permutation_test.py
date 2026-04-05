from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF, ROUND_MODE_SINGLE
from claasp.cipher_modules.code_generator import generate_numba_cipher_evaluation_kernel
from claasp.cipher_modules.generic_functions_vectorized_byte_numba import supports_word_fast_path
from numba import cuda, uint8, uint16, uint32, uint64
import numpy as np


def test_chacha_permutation():
    chacha = ChachaPermutation()
    assert chacha.family_name == 'chacha_permutation'
    assert chacha.type == 'permutation'
    assert chacha.number_of_rounds == 40
    assert chacha.id == 'chacha_permutation_p512_o512_r40'

    chacha = ChachaPermutation(number_of_rounds=2, round_mode=ROUND_MODE_HALF)
    assert chacha.number_of_rounds == 2

    chacha = ChachaPermutation(number_of_rounds=20, round_mode='single')
    assert chacha.number_of_rounds == 40
    assert chacha.id == 'chacha_permutation_p512_o512_r40'

    chacha = ChachaPermutation(number_of_rounds=20, round_mode=ROUND_MODE_SINGLE)
    state = ["61707865", "3320646e", "79622d32", "6b206574",
             "03020100", "07060504", "0b0a0908", "0f0e0d0c",
             "13121110", "17161514", "1b1a1918", "1f1e1d1c",
             "00000001", "09000000", "4a000000", "00000000"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x837778abe238d763a67ae21e5950bb2fc4f2d0c7fc62bb2f8fa018fc3f5ec7b7335271c2f29489f3eabda8fc82e46ebdd'
                 '19c12b4b04e16de9e83d0cb4e3c50a2', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output

    chacha_full = ChachaPermutation(number_of_rounds=20, round_mode='single')
    assert chacha_full.evaluate([plaintext], verbosity=False) == output

    chacha_single_mode = ChachaPermutation(number_of_rounds=20, round_mode=ROUND_MODE_SINGLE)
    assert chacha_single_mode.evaluate([plaintext], verbosity=False) == output

    chacha = ChachaPermutation(number_of_rounds=1, round_mode=ROUND_MODE_HALF)
    assert chacha.get_component_from_id("rot_0_2").description[1] == -16

    chacha = ChachaPermutation(number_of_rounds=1, start_round=('odd', 'bottom'), round_mode=ROUND_MODE_HALF)
    assert chacha.get_component_from_id("rot_0_2").description[1] == -8


def test_toy_chacha_permutation():
    """
    The test vectors below were taken from the source code available in the URL specified in [DEY2023]_.
    """

    chacha = ChachaPermutation(number_of_rounds=2, rotations=[2, 1, 4, 3], word_size=8, round_mode=ROUND_MODE_HALF)
    state = ["01", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0x81000000ad0000005600000046000000', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output

    chacha = ChachaPermutation(number_of_rounds=8, rotations=[2, 1, 4, 3], word_size=8, round_mode=ROUND_MODE_HALF)
    state = ["01", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00"]
    plaintext = int("0x" + "".join(state), 16)
    output = int('0xe023858e713feb86a730656ac909f76a', 16)
    assert chacha.evaluate([plaintext], verbosity=False) == output
    assert chacha.evaluate_vectorized([plaintext], evaluate_api=True) == output
    assert chacha.evaluate_vectorized_gpu([plaintext], evaluate_api=True) == output

def test_numba_matches_evaluate_vectorized_toy_chacha_fallback():
    """
    The test vectors below were taken from the source code available in the URL specified in [DEY2023]_.
    """
    chacha = ChachaPermutation(
        number_of_rounds=2,
        rotations=[2, 1, 4, 3],
        word_size=8,
        round_mode=ROUND_MODE_HALF,
    )
    state = ["01", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00",
             "00", "00", "00", "00"]
    plaintext = int("0x" + "".join(state), 16)

    pt_n = chacha.inputs_bit_size[chacha.inputs.index("plaintext")] // 8
    expected = chacha.evaluate_vectorized([plaintext], evaluate_api=True)
    expected_hex = expected.to_bytes(pt_n, byteorder="big").hex()

    _, code = generate_numba_cipher_evaluation_kernel(chacha, mode="differential")
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

    kernel_name = "test_kernel_toy_chacha_fallback"
    exec(
        f"@cuda.jit\ndef {kernel_name}(pt, key, out):\n    evaluate_cipher(pt, key, out)",
        eg,
    )

    pt = np.frombuffer(plaintext.to_bytes(pt_n, byteorder="big"), dtype=np.uint8).copy()
    key = np.zeros(0, dtype=np.uint8)
    out = np.zeros(pt_n, dtype=np.uint8)

    d_pt = cuda.to_device(pt)
    d_key = cuda.to_device(key)
    d_out = cuda.to_device(out)
    eg[kernel_name][1, 1](d_pt, d_key, d_out)
    cuda.synchronize()

    got = d_out.copy_to_host().tobytes().hex()
    print("Expected:", expected_hex)
    print("Got     :", got)
    assert got == expected_hex
    assert got == "81000000ad0000005600000046000000"

