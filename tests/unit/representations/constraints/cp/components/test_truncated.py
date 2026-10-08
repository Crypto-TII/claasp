"""Deterministic-truncated CP component construction."""

import pytest

from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.cp import (
    ModularAddBoomerangCPModel,
    ModularAddDeterministicTruncatedCPModel,
)
from claasp.semantics.cryptanalysis import ModularAddBoomerangSemantics


def test_modadd_boomerang_automaton_feasibility_matches_exhaustive_oracle():
    transitions = {}
    for (
        delta_left,
        delta_right,
        nabla_output,
        nabla_right,
        source,
        target,
    ) in ModularAddBoomerangCPModel._transition_rows():
        transitions.setdefault(
            (delta_left, delta_right, nabla_output, nabla_right, source), set()
        ).add(target)
    exhaustive = ModularAddBoomerangSemantics(3)
    for delta_left in range(8):
        for delta_right in range(8):
            for nabla_output in range(8):
                for nabla_right in range(8):
                    states = {0}
                    for bit in range(3):
                        key_bits = (
                            (delta_left >> bit) & 1,
                            (delta_right >> bit) & 1,
                            (nabla_output >> bit) & 1,
                            (nabla_right >> bit) & 1,
                        )
                        states = {
                            target
                            for source in states
                            for target in transitions.get((*key_bits, source), ())
                        }
                    assert (
                        bool(states)
                        == exhaustive.connectivity(
                            delta_left, delta_right, nabla_output, nabla_right
                        ).is_possible
                    )


def test_deterministic_truncated_cp_preserves_paired_carry_formula():
    model = ModularAddDeterministicTruncatedCPModel(4)
    query = model.cp_model(left_pattern="0001", right_pattern="0001", output_pattern="???0")
    assert len(query.declarations) == 32
    assert len(query.constraints) == 71
    assert query.constraint_models[0].model.backend is ConstraintBackend.CP


def test_deterministic_truncated_cp_validates_boundaries():
    with pytest.raises(ValueError, match="contain 4 bits"):
        ModularAddDeterministicTruncatedCPModel(4).cp_model(left_pattern="0")
    with pytest.raises(ValueError, match="build"):
        ModularAddDeterministicTruncatedCPModel(2).decode_transition({})
