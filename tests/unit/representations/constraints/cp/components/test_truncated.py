"""Deterministic-truncated CP component construction."""

import pytest

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.cp import (
    HybridImpossibleBoundaryCPModel,
    HybridSBoxCPModel,
    HybridXorCPModel,
    ModularAddBoomerangCPModel,
    ModularAddDeterministicTruncatedCPModel,
)
from claasp.semantics.cryptanalysis import (
    ModularAddBoomerangSemantics,
    TruncatedXorDifference,
)


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


def test_hybrid_boundary_keeps_bitwise_and_tagged_incompatibilities_distinct():
    model = HybridImpossibleBoundaryCPModel(4, ((0, 1, 2, 3),))
    query = model.cp_model(forward=(10, 10, 10, 10), backward=(0, 0, 0, 0))
    assert "forward_group_tag[0] > 2" in query.constraints[-2]
    result = model.decode_boundary(
        {
            "forward": (10, 10, 10, 10),
            "backward": (0, 0, 0, 0),
            "contradiction": (False, False, False, False, True),
        }
    )
    assert result.bitwise_positions == () and result.tagged_groups == (0,)


def test_hybrid_boundary_rejects_unverified_assignment():
    model = HybridImpossibleBoundaryCPModel(2, ((0, 1),))
    model.cp_model(forward=(10, 10), backward=(10, 10))
    with pytest.raises(ValueError, match="no independently verified"):
        model.decode_boundary({"forward": (10, 10), "backward": (10, 10)})


def test_hybrid_xor_preserves_only_zero_passthrough_and_concrete_parity():
    domain = (0, 1, 2, 10, 20)
    for left in domain:
        for right in domain:
            expected = (
                (left + right) % 2
                if left < 2 and right < 2
                else left
                if right == 0
                else right
                if left == 0
                else 2
            )
            assert HybridXorCPModel.propagate(left, right) == expected


def test_hybrid_sbox_decoder_accepts_tag_and_exact_branches():
    model = HybridSBoxCPModel(PRESENT_SBOX, output_tag=10)
    model.cp_model(input_pattern=(1, 0, 0, 0))
    assert model.decode_transition({"input": (1, 0, 0, 0), "result": (10, 10, 10, 10)}) == (
        (1, 0, 0, 0),
        (10, 10, 10, 10),
    )
    target = tuple(
        bit.encoded
        for bit in model.semantics.truncated_xor_differential(
            TruncatedXorDifference.parse("1000")
        ).bits
    )
    if target != (2, 2, 2, 2):
        assert model.decode_transition({"input": (1, 0, 0, 0), "result": target})[1] == target
