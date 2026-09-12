import shutil

import pytest

from claasp_next.boolean.solvers import SatStatus
from claasp_next.analysis import AnalysisProblem, FixedValue
from claasp_next.ciphers import SpeckBlockCipher
from claasp_next.smt.solvers import Z3Solver


pytestmark = pytest.mark.external


def test_z3_recovers_and_independently_verifies_reduced_speck_key():
    assert shutil.which("z3") is not None, "the external test job must install Z3"
    cipher = SpeckBlockCipher(number_of_rounds=1)
    plaintext = 0x6574694C
    ciphertext = cipher.evaluate(plaintext, 0x1918111009080100)

    result = cipher.analyze().recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=ciphertext,
        solver=Z3Solver(timeout_seconds=30),
    )

    assert result.status is SatStatus.SATISFIABLE
    assert cipher.evaluate(plaintext, result.value("key")) == ciphertext


def test_z3_reproduces_legacy_full_speck_missing_bits_result():
    cipher = SpeckBlockCipher(number_of_rounds=22)
    problem = AnalysisProblem(
        cipher,
        (
            FixedValue(cipher.input("plaintext"), 0x6574694C),
            FixedValue(cipher.input("key"), 0x1918111009080100),
        ),
        {"ciphertext": cipher.output},
    )

    result = cipher.analyze().solve(problem, Z3Solver(timeout_seconds=30))

    assert result.is_satisfiable
    assert result.value("ciphertext") == 0xA86842F2
    assert cipher.evaluate(0x6574694C, 0x1918111009080100) == result.value("ciphertext")
