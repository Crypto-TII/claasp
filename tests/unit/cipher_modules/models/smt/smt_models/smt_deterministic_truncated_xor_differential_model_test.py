import pytest

from claasp.cipher_modules.models.smt.smt_models.smt_deterministic_truncated_xor_differential_model import (
    SmtDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def test_smt_deterministic_truncated_xor_differential_model():
    speck = SpeckBlockCipher(number_of_rounds=2)

    with pytest.raises(NotImplementedError, match="there is no SMT implementation"):
        SmtDeterministicTruncatedXorDifferentialModel(speck)
