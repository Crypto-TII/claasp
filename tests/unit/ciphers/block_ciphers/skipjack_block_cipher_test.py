from claasp.ciphers.block_ciphers.skipjack_block_cipher import SkipjackBlockCipher


def test_skipjack_block_cipher():
    """
    Test vectors from [NIST1998]
    https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/skipjack/skipjack.pdf

    This test verifies the SKIPJACK implementation using the official NSA test vector
    for 32 rounds, as well as intermediate round outputs for 8 and 16 rounds.

    The test checks both the Python evaluation and the vectorized evaluation
    to ensure consistency with the expected outputs.
    """
    # Test cipher properties
    skipjack = SkipjackBlockCipher()
    assert skipjack.type == 'block_cipher'
    assert skipjack.family_name == 'skipjack'
    assert skipjack.number_of_rounds == 32
    assert skipjack.id == 'skipjack_p64_k80_o64_r32'
    assert skipjack.output_bit_size == 64
    
    # Test component structure
    components = skipjack.get_all_components()
    assert len(components) == 576
    first_comp = skipjack.component_from(0, 0)
    assert first_comp is not None
    assert hasattr(first_comp, 'id')
    
    # Test official vectors Key and Plaintext
    key = 0x00998877665544332211
    plaintext = 0x33221100ddccbbaa
    
    # Test intermediate output at 8 rounds to verify Rule A phase correctness
    skipjack_8 = SkipjackBlockCipher(number_of_rounds=8)
    ciphertext_8 = 0xd79b5599be50dd90
    assert skipjack_8.evaluate([plaintext, key]) == ciphertext_8
    assert skipjack_8.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext_8
    
    # Test intermediate output at 16 rounds to verify Rule A and Rule B phases together
    skipjack_16 = SkipjackBlockCipher(number_of_rounds=16)
    ciphertext_16 = 0xd7f8899053979883
    assert skipjack_16.number_of_rounds == 16
    assert skipjack_16.id == 'skipjack_p64_k80_o64_r16'
    assert skipjack_16.evaluate([plaintext, key]) == ciphertext_16
    assert skipjack_16.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext_16
    
    # Test final output after full 32 rounds to verify second Rule B phase completion
    skipjack_32 = SkipjackBlockCipher()
    ciphertext_32 = 0x2587cae27a12d300
    assert skipjack_32.evaluate([plaintext, key]) == ciphertext_32
    assert skipjack_32.evaluate_vectorized([plaintext, key], evaluate_api=True) == ciphertext_32


def test_skipjack_all_rounds():
    """
    Test each individual round output from 1 to 32 using intermediate values from [NIST1998]
    
    This test verifies the correctness of each round output to ensure
    proper implementation of both Rule A and Rule B operations.
    """
    key = 0x00998877665544332211
    plaintext = 0x33221100ddccbbaa
    
    # Expected output after each round from [NIST1998]
    expected_outputs = [
        0xb0040baf1100ddcc,   # round 1
        0xe6883b460baf1100,   # round 2
        0x3c762d753b460baf,   # round 3
        0x4c4547ee2d753b46,   # round 4
        0xb949820a47ee2d75,   # round 5
        0xf0e3dd90820a47ee,   # round 6
        0xf9b9be50dd90820a,   # round 7
        0xd79b5599be50dd90,   # round 8
        0xdd901e0b820bbe50,   # round 9
        0xbe504c52c391820b,   # round 10
        0x820b7f51f209c391,   # round 11
        0xc391f9c2fd56f209,   # round 12
        0xf20925ff3a5efd56,   # round 13
        0xfd5665dad7f83a5e,   # round 14
        0x3a5e69d99883d7f8,   # round 15
        0xd7f8899053979883,   # round 16
        0x9c00049289905397,   # round 17
        0x9fdccc5904928990,   # round 18
        0x3731beb2cc590492,   # round 19
        0x7afb7e7dbeb2cc59,   # round 20
        0x7759bb157e7dbeb2,   # round 21
        0xfb6445c0bb157e7d,   # round 22
        0x6f7f111545c0bb15,   # round 23
        0x65a7deaa111545c0,   # round 24
        0x45c0e0f9bb141115,   # round 25
        0x11153913a523bb14,   # round 26
        0xbb148ee6281da523,   # round 27
        0xa523bfe235ee281d,   # round 28
        0x281d0d841adc35ee,   # round 29
        0x35eee6f125871adc,   # round 30
        0x1adc60eed3002587,   # round 31
        0x2587cae27a12d300,   # round 32
    ]
    
    # Test each round output
    for rounds in range(1, 33):
        skipjack = SkipjackBlockCipher(number_of_rounds=rounds)
        result = skipjack.evaluate([plaintext, key])
        assert result == expected_outputs[rounds - 1], \
            f"Round {rounds} failed: expected {hex(expected_outputs[rounds - 1])}, got {hex(result)}"
        