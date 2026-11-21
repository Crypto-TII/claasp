"""Independent replay and endpoint-semantics tests for exact quartet searches."""

from copy import deepcopy

import pytest

from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import (
    MznHadipourBoomerangModel,
)
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.katan_block_cipher import KatanBlockCipher
from claasp.ciphers.block_ciphers.lea_block_cipher import LeaBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.simeck_block_cipher import SimeckBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation
from claasp.ciphers.permutations.chaskeypi_permutation import ChaskeyPiPermutation
from claasp.name_mappings import CIPHER_OUTPUT


def fixed_value(name, value, size):
    return set_fixed_variables(
        name, "equal", list(range(size)), integer_to_bit_list(value, size, "big")
    )


def replay(cipher, result):
    """Use the original evaluator, independently of MiniZinc's value encoding."""
    values = result["quartet_values"]
    output = next(c.id for c in cipher.all_components() if c.type == CIPHER_OUTPUT)
    inputs = []
    outputs = []
    for execution in range(4):
        point = [
            int(values[f"quartet_{execution}_{name}"]["value"], 16)
            for name in cipher.inputs
        ]
        result_value = int(values[f"quartet_{execution}_{output}"]["value"], 16)
        assert cipher.evaluate(point) == result_value
        inputs.append(point)
        outputs.append(result_value)
    assert inputs[0][0] ^ inputs[1][0] == inputs[2][0] ^ inputs[3][0]
    assert outputs[0] ^ outputs[2] == outputs[1] ^ outputs[3]
    assert inputs[0][0] != inputs[1][0]
    assert outputs[0] != outputs[2]
    assert all(point[1:] == inputs[0][1:] for point in inputs)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SimonBlockCipher(number_of_rounds=3),
        lambda: SimeckBlockCipher(number_of_rounds=5),
        lambda: SpeckBlockCipher(number_of_rounds=3),
        lambda: LeaBlockCipher(number_of_rounds=3),
        lambda: KatanBlockCipher(number_of_rounds=3),
        lambda: ChaskeyPiPermutation(number_of_rounds=3),
        lambda: ChachaPermutation(number_of_rounds=3, round_mode="half_half"),
    ],
)
def test_exact_graph_replays_on_seven_primitive_families(factory):
    cipher = factory()
    before = deepcopy(cipher.as_python_dictionary())
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=cipher.number_of_rounds - 2,
        ),
        enforce_value_compatibility=True,
    )
    # A returning pair is an intentional positive control, not a distinguisher.
    fixed = [
        fixed_value(
            f"quartet_{execution}_{cipher.inputs[0]}", point, cipher.inputs_bit_size[0]
        )
        for execution, point in enumerate([2, 3, 3, 2])
    ]
    fixed += [
        fixed_value(
            "quartet_0_" + name,
            0x1918111009080100 if isinstance(cipher, SimeckBlockCipher) else 0,
            size,
        )
        for name, size in zip(cipher.inputs[1:], cipher.inputs_bit_size[1:])
    ]
    result = model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=20)
    assert result["status"] == "SATISFIABLE"
    assert result["value_compatibility"] == "full_cipher"
    replay(cipher, result)
    assert cipher.as_python_dictionary() == before
    assert not any(name.startswith("quartet_") for name in result["components_values"])


def test_exact_graph_search_produces_an_independently_replayable_witness():
    cipher = SimonBlockCipher(number_of_rounds=3)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    result = model.find_one_boomerang_trail(timeout_in_seconds=10)
    assert result["status"] == "SATISFIABLE"
    replay(cipher, result)


def test_exact_value_flag_requires_bool():
    with pytest.raises(ValueError, match="must be a boolean"):
        MznHadipourBoomerangModel(
            SimonBlockCipher(number_of_rounds=3), {}, enforce_value_compatibility=1
        )


@pytest.mark.parametrize("middle", [2, 3])
def test_extended_switch_values_leave_unretained_endpoints_free(middle):
    cipher = SimonBlockCipher(number_of_rounds=middle + 2)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=middle,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    fixed = [
        fixed_value(f"quartet_{execution}_plaintext", point, 32)
        for execution, point in enumerate([2, 3, 3, 2])
    ]
    fixed.append(fixed_value("quartet_0_key", 0, 64))
    result = model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=10)
    assert result["status"] == "SATISFIABLE"
    replay(cipher, result)


def test_exact_graph_rejects_different_master_keys_and_wrong_values():
    cipher = SimonBlockCipher(number_of_rounds=3)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    fixed = [fixed_value("quartet_0_key", 0, 64), fixed_value("quartet_1_key", 1, 64)]
    assert (
        model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=5)[
            "status"
        ]
        == "UNSATISFIABLE"
    )
    output = next(c.id for c in cipher.all_components() if c.type == CIPHER_OUTPUT)
    fixed = [
        fixed_value("quartet_0_key", 0, 64),
        fixed_value("quartet_0_plaintext", 0, 32),
        fixed_value("quartet_0_" + output, cipher.evaluate([0, 0]) ^ 1, 32),
    ]
    assert (
        model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=5)[
            "status"
        ]
        == "UNSATISFIABLE"
    )


def test_exact_graph_build_is_repeatable_and_enum_rejects_witness_duplicates():
    model = MznHadipourBoomerangModel(
        SimonBlockCipher(number_of_rounds=3),
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    model.build_hadipour_boomerang_model(weight=None)
    first = model.assemble_model()
    model.build_hadipour_boomerang_model(weight=None)
    assert model.assemble_model() == first
    with pytest.raises(NotImplementedError, match="enumeration would enumerate"):
        model.solve(all_solutions_=True)


def test_exact_modsub_uses_native_value_semantics():
    from claasp.cipher import Cipher

    cipher = Cipher("value_subtraction", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    component = cipher.add_modsub_component(
        ["plaintext", "plaintext"], [[0, 1], [2, 3]], 2
    )
    cipher.add_cipher_output_component([component.id, "plaintext"], [[0, 1], [2, 3]], 4)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=0,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=0,
        ),
        enforce_value_compatibility=True,
    )
    fixed = [
        fixed_value(f"quartet_{execution}_plaintext", point, 4)
        for execution, point in enumerate([2, 3, 3, 2])
    ]
    result = model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=5)
    assert result["status"] == "SATISFIABLE"
    replay(cipher, result)


def test_exact_values_fail_explicitly_for_missing_component_encoder(monkeypatch):
    from claasp.components.and_component import And

    monkeypatch.setattr(And, "cp_constraints", None)
    model = MznHadipourBoomerangModel(
        SimonBlockCipher(number_of_rounds=3),
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    with pytest.raises(NotImplementedError, match="No exact CP value model"):
        model.build_hadipour_boomerang_model(weight=None)


def test_exact_values_reject_mismatched_state_sizes():
    from claasp.cipher import Cipher

    cipher = Cipher("not_a_permutation", "permutation", ["plaintext"], [4], 2)
    cipher.add_round()
    component = cipher.add_and_component(
        ["plaintext", "plaintext"], [[0, 1], [2, 3]], 2
    )
    cipher.add_cipher_output_component([component.id], [[0, 1]], 2)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=0,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=0,
        ),
        enforce_value_compatibility=True,
    )
    with pytest.raises(ValueError, match="one output matching the first input size"):
        model.build_hadipour_boomerang_model(weight=None)


def test_extended_modular_switch_values_preserve_endpoint_semantics():
    cipher = SpeckBlockCipher(number_of_rounds=4)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=1,
            middle_part_number_of_rounds=2,
            bottom_part_number_of_rounds=1,
        ),
        enforce_value_compatibility=True,
    )
    fixed = [
        fixed_value(f"quartet_{j}_plaintext", point, 32)
        for j, point in enumerate([2, 3, 3, 2])
    ]
    fixed.append(fixed_value("quartet_0_key", 0, 64))
    result = model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=10)
    assert result["status"] == "SATISFIABLE"
    replay(cipher, result)


def test_exact_graph_includes_a_nonlinear_master_key_schedule():
    from claasp.cipher import Cipher

    cipher = Cipher(
        "sbox_key_schedule", "block_cipher", ["plaintext", "key"], [3, 3], 3
    )
    cipher.add_round()
    table = [0, 1, 3, 2, 5, 7, 4, 6]
    assert table[2] ^ table[4] ^ table[6] ^ table[0] != 0
    round_key = cipher.add_sbox_component(["key"], [[0, 1, 2]], 3, table)
    value = cipher.add_xor_component(
        ["plaintext", round_key.id], [[0, 1, 2], [0, 1, 2]], 3
    )
    cipher.add_cipher_output_component([value.id], [[0, 1, 2]], 3)
    model = MznHadipourBoomerangModel(
        cipher,
        dict(
            top_part_number_of_rounds=0,
            middle_part_number_of_rounds=1,
            bottom_part_number_of_rounds=0,
        ),
        enforce_value_compatibility=True,
    )
    fixed = [
        fixed_value(f"quartet_{j}_plaintext", point, 3)
        for j, point in enumerate([0, 1, 1, 0])
    ]
    fixed.append(fixed_value("quartet_0_key", 6, 3))
    result = model.find_one_boomerang_trail(fixed_values=fixed, timeout_in_seconds=5)
    assert result["status"] == "SATISFIABLE"
    replay(cipher, result)
