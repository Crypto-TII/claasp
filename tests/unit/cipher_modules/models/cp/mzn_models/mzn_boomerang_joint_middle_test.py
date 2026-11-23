"""Joint middle regressions checked against exhaustive permutation evaluation."""

import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher


def fixed(name, value, size):
    return set_fixed_variables(
        name, "equal", list(range(size)), integer_to_bit_list(value, size, "big")
    )


def cancellation_cipher():
    cipher = Cipher("quadratic_cancellation", "permutation", ["plaintext"], [5], 5)
    cipher.add_round()
    ab = cipher.add_and_component(["plaintext", "plaintext"], [[0], [1]], 1)
    cd = cipher.add_and_component(["plaintext", "plaintext"], [[2], [3]], 1)
    tail = cipher.add_xor_component(["plaintext", ab.id, cd.id], [[4], [0], [0]], 1)
    cipher.add_cipher_output_component(["plaintext", tail.id], [[0, 1, 2, 3], [0]], 5)
    return cipher


def structure(rounds=1, top=0, bottom=0):
    return dict(
        top_part_number_of_rounds=top,
        middle_part_number_of_rounds=rounds - top - bottom,
        bottom_part_number_of_rounds=bottom,
    )


def test_joint_middle_recovers_cancellation_excluded_by_local_tables():
    cipher = cancellation_cipher()
    delta, nabla = 20, 10
    # This involution has an external quartet for every one of its 32 inputs.
    for x in range(32):
        y, yp = cipher.evaluate([x]), cipher.evaluate([x ^ delta])
        assert cipher.evaluate([y ^ nabla]) ^ cipher.evaluate([yp ^ nabla]) == delta
    external = [
        fixed("upper_plaintext", delta, 5),
        fixed("lower_" + cipher.all_components()[-1].id, nabla, 5),
    ]
    local = MznHadipourBoomerangModel(
        cipher, structure(), enforce_value_compatibility=True
    )
    assert (
        local.find_one_boomerang_trail(fixed_values=external, timeout_in_seconds=10)[
            "status"
        ]
        == "UNSATISFIABLE"
    )
    joint = MznHadipourBoomerangModel(
        cipher, structure(), middle_model="exact", exclude_returning_quartets=True
    )
    result = joint.find_lowest_weight_boomerang_trail(
        fixed_values=external, timeout_in_seconds=10
    )
    assert result["status"] == "SATISFIABLE"
    assert result["score_type"] == "outer_characteristic_score"
    assert result["middle_weight"] is None
    assert float(result["total_weight"]) == 0
    assert set(result["components_values"]) == {
        "upper_plaintext",
        "lower_" + cipher.all_components()[-1].id,
    }
    values = result["quartet_values"]
    output = cipher.all_components()[-1].id
    xs = [int(values[f"quartet_{j}_plaintext"]["value"], 16) for j in range(4)]
    ys = [int(values[f"quartet_{j}_{output}"]["value"], 16) for j in range(4)]
    assert len(set(xs)) == 4
    assert result["exclude_returning_quartets"] is True
    assert [cipher.evaluate([x]) for x in xs] == ys
    assert xs[0] ^ xs[1] == xs[2] ^ xs[3] == delta
    assert ys[0] ^ ys[2] == ys[1] ^ ys[3] == nabla


def test_joint_middle_supports_sbox_values_without_local_switch_encoder():
    cipher = Cipher("sbox_middle", "permutation", ["plaintext"], [3], 3)
    cipher.add_round()
    box = cipher.add_sbox_component(
        ["plaintext"], [[0, 1, 2]], 3, [0, 1, 3, 2, 5, 7, 4, 6]
    )
    output = cipher.add_cipher_output_component([box.id], [[0, 1, 2]], 3)
    model = MznHadipourBoomerangModel(cipher, structure(), middle_model="exact")
    controls = [
        fixed(f"quartet_{j}_plaintext", x, 3) for j, x in enumerate([0, 3, 3, 0])
    ]
    result = model.find_one_boomerang_trail(
        fixed_values=controls, timeout_in_seconds=10
    )
    assert result["status"] == "SATISFIABLE"
    assert int(result["quartet_values"]["quartet_1_" + output.id]["value"], 16) == 2
    fixed_values = [fixed("upper_" + box.id, 0, 3)]
    with pytest.raises(ValueError, match="unretained"):
        model.build_hadipour_boomerang_model(fixed_variables=fixed_values)


def test_joint_modular_middle_uses_integer_backend_and_preserves_outer_scores():
    model = MznHadipourBoomerangModel(
        SpeckBlockCipher(number_of_rounds=3), structure(3, 1, 1), middle_model="exact"
    )
    model.build_hadipour_boomerang_model(weight=None)
    assert model._middle_keys() == []
    assert model.c_upper > 0
    assert model.c_lower > 0
    assert model._default_solver(None) != "gecode"
    controls = [
        fixed(f"quartet_{j}_plaintext", x, 32) for j, x in enumerate([2, 3, 3, 2])
    ]
    controls.append(fixed("quartet_0_key", 0, 64))
    result = model.find_one_boomerang_trail(
        fixed_values=controls, timeout_in_seconds=10
    )
    assert result["status"] == "SATISFIABLE"
    assert float(result["total_weight"]) == 2 * (
        result["upper_weight"] + result["lower_weight"]
    )
    assert result["middle_weight"] is None


def test_middle_mode_is_validated():
    cipher = cancellation_cipher()
    split = structure()
    with pytest.raises(ValueError, match="middle_model"):
        MznHadipourBoomerangModel(cipher, split, middle_model="invalid")


@pytest.mark.parametrize("middle_model", ["local", "exact"])
@pytest.mark.parametrize("exclude", [False, True])
def test_returning_only_identity_pair_is_optional(middle_model, exclude):
    cipher = Cipher("identity_returning", "permutation", ["state"], [4], 4)
    cipher.add_round()
    output = cipher.add_cipher_output_component(["state"], [[0, 1, 2, 3]], 4)
    model = MznHadipourBoomerangModel(
        cipher,
        structure(),
        middle_model=middle_model,
        enforce_value_compatibility=not exclude,
        exclude_returning_quartets=exclude,
    )
    assert model.enforce_value_compatibility
    result = model.find_one_boomerang_trail(
        fixed_values=[fixed("upper_state", 1, 4), fixed("lower_" + output.id, 1, 4)],
        solver_name="gecode",
        timeout_in_seconds=5,
    )
    assert result["status"] == ("UNSATISFIABLE" if exclude else "SATISFIABLE")
    if not exclude:
        assert result["exclude_returning_quartets"] is False
        xs = [
            int(result["quartet_values"][f"quartet_{i}_state"]["value"], 16)
            for i in range(4)
        ]
        assert len(set(xs)) == 2


@pytest.mark.parametrize("value", [1, None, "yes"])
def test_nondegenerate_option_requires_boolean(value):
    cipher = cancellation_cipher()
    split = structure()
    with pytest.raises(ValueError, match="exclude_returning_quartets"):
        MznHadipourBoomerangModel(cipher, split, exclude_returning_quartets=value)
