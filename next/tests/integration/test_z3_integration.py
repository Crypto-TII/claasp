import shutil

import pytest

from claasp_next.drivers.solvers import SatStatus
from claasp_next.analysis import AnalysisProblem, FixedValue
from claasp_next.ciphers import PresentBlockCipher, SpeckBlockCipher
from claasp_next.smt.solvers import Z3Solver
from claasp_next.smt import (
    PresentDifferentialSMTModel,
    PresentLinearSMTModel,
    ModularAddLinearSMTModel,
    SBoxTransitionSMTModel,
)
from claasp_next.smt.trails import check_present_linear_smt_trail, check_present_smt_trail
from claasp_next.analysis import TrailKind
from claasp_next.ciphers.block_ciphers.present import PRESENT_SBOX


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


def test_z3_proves_present_sbox_transition_feasibility_and_impossibility():
    model = SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_DIFFERENTIAL)
    solver = Z3Solver(timeout_seconds=10)

    possible = solver.solve(model.smt_formula(input_pattern=1, output_pattern=3))
    impossible = solver.solve(model.smt_formula(input_pattern=1, output_pattern=1))

    assert possible.status is SatStatus.SATISFIABLE
    assert model.decode_transition(possible.assignment).weight == 2.0
    assert impossible.status is SatStatus.UNSATISFIABLE


def test_z3_proves_and_extracts_present_two_round_optimum():
    cipher = PresentBlockCipher(number_of_rounds=2)
    solver = Z3Solver(timeout_seconds=30)
    below_optimum = PresentDifferentialSMTModel(cipher, maximum_weight=3)
    optimum = PresentDifferentialSMTModel(cipher, maximum_weight=4)

    assert solver.solve(below_optimum.smt_formula()).status is SatStatus.UNSATISFIABLE
    solved = solver.solve(optimum.smt_formula())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is SatStatus.SATISFIABLE
    assert trail.total_weight == 4.0
    assert check_present_smt_trail(cipher, trail)


def test_z3_proves_and_extracts_present_three_round_linear_optimum():
    cipher = PresentBlockCipher(number_of_rounds=3)
    solver = Z3Solver(timeout_seconds=30)
    below_optimum = PresentLinearSMTModel(cipher, maximum_weight=3)
    optimum = PresentLinearSMTModel(cipher, maximum_weight=4)

    assert solver.solve(below_optimum.smt_formula()).status is SatStatus.UNSATISFIABLE
    solved = solver.solve(optimum.smt_formula())
    trail = optimum.decode_trail(solved.assignment)

    assert solved.status is SatStatus.SATISFIABLE
    assert trail.total_weight == 4.0
    assert check_present_linear_smt_trail(cipher, trail)


def test_z3_restores_speck_linear_modular_add_reference_transitions():
    solver = Z3Solver(timeout_seconds=10)
    model = ModularAddLinearSMTModel(16)
    reference = (
        (0x6081, 0x40C1, 0x4081),
        (0x0001, 0x0001, 0x0001),
        (0x0000, 0x0000, 0x0000),
        (0x0800, 0x0800, 0x0C00),
    )
    transitions = []
    for left, right, output in reference:
        solved = solver.solve(model.smt_formula(
            left_mask=left, right_mask=right, output_mask=output
        ))
        assert solved.status is SatStatus.SATISFIABLE
        transitions.append(model.decode_transition(solved.assignment))

    assert [transition.weight for transition in transitions] == [2.0, 0.0, 0.0, 1.0]
    assert [transition.sign for transition in transitions] == [1, 1, 1, -1]
    assert sum(transition.weight for transition in transitions) == 3.0
