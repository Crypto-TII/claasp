"""Known-input recovery verifies the concrete primitive, including field layers."""

import pytest

from claasp.drivers.solvers import Z3Solver
from claasp.primitives import AES, ToySpeck

pytestmark = pytest.mark.external


def test_native_aes_plaintext_recovery_crosses_lookup_mixcolumns_and_key_schedule():
    primitive = AES(number_of_rounds=2)
    plaintext, key = 0x123456789ABCDEF, 0xFEDCBA987654321
    output = primitive.evaluate(plaintext, key)
    result = primitive.analysis.recover_input(
        "plaintext", known_inputs={"key": key}, output=output, solver=Z3Solver(timeout_seconds=30)
    )
    assert result.is_satisfiable
    assert result.value("plaintext") == plaintext
    assert primitive.evaluate(result.value("plaintext"), key) == output


def test_underdetermined_key_recovery_returns_a_valid_key_without_claiming_uniqueness():
    primitive = ToySpeck(1)
    plaintext, key = 0x12, 0xABCD
    output = primitive.evaluate(plaintext, key)
    result = primitive.analysis.recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=output,
        solver=Z3Solver(timeout_seconds=30),
    )
    assert result.is_satisfiable
    assert primitive.evaluate(plaintext, result.value("key")) == output
    # A one-round ToySpeck experiment only observes the last key word.
    recovered = result.value("key")
    assert isinstance(recovered, int)
    alternative = recovered ^ 0x1000
    assert primitive.evaluate(plaintext, alternative) == output
