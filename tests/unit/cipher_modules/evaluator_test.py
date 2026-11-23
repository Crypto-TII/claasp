import numpy as np

from claasp.cipher_modules import evaluator
from claasp.ciphers.single_component_ciphers.identity_cipher import IdentityCipher


def test_create_vectorized_evaluator_can_be_reused():
    identity = IdentityCipher(block_bit_size=16)
    compiled_evaluator = evaluator.create_vectorized_evaluator(identity)
    first_inputs = [np.array([[0x12], [0x34]], dtype=np.uint8)]
    second_inputs = [np.array([[0xab], [0xcd]], dtype=np.uint8)]

    first_output = compiled_evaluator(first_inputs)
    second_output = compiled_evaluator(second_inputs)

    assert first_output[-1].tolist() == [[0x12, 0x34]]
    assert second_output[-1].tolist() == [[0xab, 0xcd]]
