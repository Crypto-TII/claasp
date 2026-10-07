import shutil

import pytest

from claasp import Bit, Primitive, ValueType
from claasp.components import Add
from claasp.drivers.solvers import MinisatSolver, SatStatus
from claasp.primitives import Present80, Simon, Speck
from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.constraints.sat import (
    BooleanCNFModel,
    ModularAddDifferentialSATModel,
    ModularAddLinearSATModel,
    SBoxXorDifferentialSATModel,
)

pytestmark = pytest.mark.external


def test_minisat_solves_and_refutes_named_present_constraints():
    assert shutil.which("minisat") is not None, "the external test job must install MiniSat"
    primitive = Present80(number_of_rounds=1)
    formula = BooleanCNFModel(primitive).cnf_formula()
    fixed_inputs = {
        **{f"plaintext_{position}": 0 for position in range(64)},
        **{f"key_{position}": 0 for position in range(80)},
    }
    solver = MinisatSolver(timeout_seconds=30)
    result = solver.solve(formula, fixed_inputs)
    assert result.status is SatStatus.SATISFIABLE
    assert formula.is_satisfied(result.assignment)

    contradictory = {**fixed_inputs, "add_round_key_1_0": 1}
    result = solver.solve(formula, contradictory)
    assert result.status is SatStatus.UNSATISFIABLE
    assert result.assignment is None


def test_high_level_analysis_recovers_an_unknown_input():
    primitive = Primitive(
        "xor", {"plaintext": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))}
    )
    primitive.add_round()
    output = primitive.add_component(Add((primitive.input("plaintext"), primitive.input("key"))))
    primitive.set_output(output)

    result = primitive.analyze().recover_input(
        "key",
        known_inputs={"plaintext": 1},
        output=0,
        solver=MinisatSolver(timeout_seconds=10),
    )
    assert result.is_satisfiable
    assert result.value("key") == 1
    assert result.backend == "MinisatSolver"
    assert result.statistics == {"variables": 3, "clauses": 6}
    assert len(result.reproducibility["formula_sha256"]) == 64


def test_word_level_sat_recovers_a_reduced_speck_key():
    primitive = Speck(number_of_rounds=1)
    plaintext = 0x6574694C
    expected = primitive.evaluate(plaintext, 0x1918111009080100)

    result = primitive.analyze().recover_input(
        "key",
        known_inputs={"plaintext": plaintext},
        output=expected,
        solver=MinisatSolver(timeout_seconds=30),
    )

    assert result.is_satisfiable
    assert primitive.evaluate(plaintext, result.value("key")) == expected
    assert result.statistics["variables"] > 64


def test_and_word_graph_recovers_a_simon_plaintext():
    primitive = Simon(number_of_rounds=3)
    plaintext, key = 0x65656877, 0x1918111009080100
    ciphertext = primitive.evaluate(plaintext, key)
    result = primitive.analyze().recover_input(
        "plaintext",
        known_inputs={"key": key},
        output=ciphertext,
        solver=MinisatSolver(timeout_seconds=10),
    )
    assert result.is_satisfiable
    assert result.value("plaintext") == plaintext
    assert primitive.evaluate(result.value("plaintext"), key) == ciphertext


def test_minisat_solves_and_refutes_sbox_differential_transitions():
    relation = SBoxXorDifferentialSATModel(PRESENT_SBOX)
    result = MinisatSolver(timeout_seconds=10).solve(
        relation.cnf_formula(input_pattern=1, output_pattern=3)
    )
    assert result.status is SatStatus.SATISFIABLE
    assert relation.decode_transition(result.assignment).weight == 2

    impossible = MinisatSolver(timeout_seconds=10).solve(
        relation.cnf_formula(input_pattern=1, output_pattern=1)
    )
    assert impossible.status is SatStatus.UNSATISFIABLE


@pytest.mark.parametrize(
    "relation,masks,weight,sign",
    (
        (ModularAddDifferentialSATModel(4), (1, 1, 2), 2, 1),
        (ModularAddLinearSATModel(4), (2, 2, 2), 1, 1),
    ),
)
def test_minisat_solves_modular_add_transition_models(relation, masks, weight, sign):
    names = (
        ("left_mask", "right_mask", "output_mask")
        if isinstance(relation, ModularAddLinearSATModel)
        else ()
    )
    formula = relation.cnf_formula(**dict(zip(names, masks))) if names else relation.cnf_formula()
    assumptions = {
        f"{prefix}_{bit}": (value >> (relation.width - 1 - bit)) & 1
        for prefix, value in zip(("left", "right", "output"), masks)
        for bit in range(relation.width)
    }
    result = MinisatSolver(timeout_seconds=10).solve(formula, assumptions)
    assert result.status is SatStatus.SATISFIABLE
    transition = relation.decode_transition(result.assignment)
    assert (transition.weight, transition.sign) == (weight, sign)
