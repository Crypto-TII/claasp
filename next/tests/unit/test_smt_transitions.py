from itertools import product

from claasp_next.primitives.block_ciphers.present import PRESENT_SBOX
from claasp_next.representations.constraints.smt import (
    ModularAddLinearSMTModel,
    SBoxTransitionSMTModel,
)
from claasp_next.semantics.cryptanalysis import TrailKind


def _solutions(formula):
    for values in product((0, 1), repeat=len(formula.variables)):
        assignment = dict(zip(formula.variables, values))
        if all(
            any(assignment[formula.variables[abs(item) - 1]] == (item > 0) for item in clause)
            for clause in formula.assertions
        ):
            yield assignment


def test_differential_smt_relation_matches_all_present_ddt_entries():
    model = SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_DIFFERENTIAL)
    formula = model.smt_formula()
    decoded = {
        (
            model.decode_transition(assignment).input_pattern.value,
            model.decode_transition(assignment).output_pattern.value,
        )
        for assignment in _solutions(formula)
    }
    expected = {
        (source, target)
        for source in range(16)
        for target in range(16)
        if model.semantics.xor_differential(source, target).is_possible
    }
    assert decoded == expected


def test_linear_smt_relation_projects_exact_weight_and_sign():
    model = SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_LINEAR)
    formula = model.smt_formula(input_pattern=1, output_pattern=5)
    transition = model.decode_transition(next(_solutions(formula)))

    assert transition.weight == 1.0
    assert transition.sign == -1


def test_modular_add_linear_smt_matches_every_four_bit_mask_triple():
    model = ModularAddLinearSMTModel(4)
    formula = model.smt_formula()
    solutions = list(_solutions(formula))
    decoded = {
        (
            transition.input_pattern.value,
            transition.output_pattern.value,
            transition.weight,
            transition.sign,
        )
        for assignment in solutions
        for transition in (model.decode_transition(assignment),)
    }
    expected = {
        (
            transition.input_pattern.value,
            transition.output_pattern.value,
            transition.weight,
            transition.sign,
        )
        for left in range(16)
        for right in range(16)
        for output in range(16)
        for transition in (model.semantics.xor_linear(left, right, output),)
        if transition.is_possible
    }
    assert decoded == expected
