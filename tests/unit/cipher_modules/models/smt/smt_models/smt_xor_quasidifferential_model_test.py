
import pytest

from claasp.cipher_modules.models.smt.smt_models.smt_xor_quasidifferential_model import (
    SmtXorQuasidifferentialModel,
)
from claasp.cipher_modules.models.smt.solvers import Z3_EXT
from claasp.cipher_modules.models.smt.utils import constants
from claasp.cipher_modules.models.utils import integer_to_bit_list, set_fixed_variables
from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from claasp.ciphers.block_ciphers.rectangle_block_cipher import RectangleBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.toys.heys_block_cipher import HeysBlockCipher
from claasp.ciphers.toys.toyspn1 import ToySPN1
from claasp.name_mappings import INPUT_KEY, INPUT_PLAINTEXT, XOR_QUASIDIFFERENTIAL


def test_find_lowest_weight_xor_quasidifferential_trail_on_rectangle():
    rectangle = RectangleBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(rectangle)
    plaintext = set_fixed_variables(INPUT_PLAINTEXT, "not_equal", range(64), (0,) * 64)
    trail = smt.find_lowest_weight_xor_quasidifferential_trail(fixed_values=[plaintext])
    assert trail["total_weight"] == 0.0


def test_find_one_xor_quasidifferential_trail_on_simon():
    simon = SimonBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(simon)
    solution = smt.find_one_xor_quasidifferential_trail()
    assert str(solution["cipher"]) == "simon_p32_k64_o32_r1"
    assert solution["solver_name"] == Z3_EXT
    assert solution["components_values"]["and_0_4"]["weight"] == solution["total_weight"]


def test_compute_trail_sign():
    speck = SpeckBlockCipher(number_of_rounds=6)
    smt = SmtXorQuasidifferentialModel(speck)
    fixed_values = _speck_six_round_characteristic()
    trail = smt.find_one_xor_quasidifferential_trail_with_fixed_weight(13, fixed_values=fixed_values)
    assert trail["total_weight"] == 13.0
    assert smt.compute_trail_sign(trail) == 1


def test_estimate_fixed_key_probability():
    speck = SpeckBlockCipher(number_of_rounds=6)
    smt = SmtXorQuasidifferentialModel(speck)
    fixed_masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(32), "bit_values": [0] * 32},
        {"component_id": INPUT_KEY, "bit_positions": range(64), "bit_values": [0] * 64},
        {"component_id": "cipher_output_5_12", "bit_positions": range(32), "bit_values": [0] * 32},
    ]
    result = smt.estimate_fixed_key_probability(
        max_weight=13,
        min_weight=13,
        fixed_values=_speck_six_round_characteristic(),
        fixed_masks=fixed_masks,
    )
    assert result["num_trails"] == 1
    assert result["trails"][0]["sign"] == 1
    assert result["estimated_probability"] == 2.0**-13


def test_fork_constraints_tie_branch_masks_by_xor():
    # At a fork the source mask is the XOR of the branch masks, not their
    # equality. Checked against Equation (4) on the copy map F(x) = (x, x):
    # of the 512 three-bit transitions with a non-zero coefficient, all
    # satisfy u = v1 xor v2 and only 8 satisfy u = v1 = v2, so sharing one
    # variable among consumers is a constraint 64 times too strong.
    speck = SpeckBlockCipher(number_of_rounds=2)
    smt = SmtXorQuasidifferentialModel(speck)
    variables, constraints = smt._fork_constraints()

    forks = [wire for wire, consumers in smt._wire_consumers.items() if len(consumers) > 1]

    assert len(forks) == 96
    assert len(constraints) == 96
    assert len(variables) == 256
    assert constraints[0].startswith("(assert (= qdt_")
    assert " (xor " in constraints[0]


def test_forked_wires_use_one_mask_variable_per_consumer():
    speck = SpeckBlockCipher(number_of_rounds=2)
    smt = SmtXorQuasidifferentialModel(speck)

    modadd = speck.component_from_id("modadd_0_1")
    mask_ids = smt._qdt_input_bit_ids(modadd)

    assert any(mask_id.endswith("_to_modadd_0_1") for mask_id in mask_ids)
    assert all("_to_" not in mask_id or "_to_modadd_0_1" in mask_id for mask_id in mask_ids)


def test_each_read_of_a_wire_gets_its_own_branch():
    # DES's expansion feeds 16 bits of permutation_0_0 into BOTH halves of
    # xor_0_7. Keying a branch by consumer id alone would give the two reads
    # one name, and the fork assertion would then XOR it with itself, where
    # it cancels -- the branch would drop out of the source relation.
    des = DESBlockCipher(number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(des)

    xor = des.component_from_id("xor_0_7")
    mask_ids = smt._qdt_input_bit_ids(xor)

    assert len(mask_ids) == len(set(mask_ids))

    doubly_read = [
        wire
        for wire, consumers in smt._wire_consumers.items()
        if [consumer for consumer, _ in consumers].count("xor_0_7") > 1
    ]
    assert doubly_read

    source_id, position = doubly_read[0]
    _, constraints = smt._fork_constraints()
    assertion = next(c for c in constraints if c.startswith(f"(assert (= qdt_{source_id}_{position} "))
    branches = [token for token in assertion.split() if "_to_" in token]

    assert len(branches) == len(set(branches))


def test_masks_of_unread_cipher_input_bits_are_zero():
    # Half of Speck's key is never read at two rounds. Those mask variables
    # are otherwise free, yet _qdt_get_operands puts them in every blocking
    # clause, so each assignment would count as a distinct trail.
    speck = SpeckBlockCipher(number_of_rounds=2)
    smt = SmtXorQuasidifferentialModel(speck)

    constraints = smt._unread_input_mask_constraints()

    assert len(constraints) == 32
    assert all(c.startswith("(assert (not qdt_key_") for c in constraints)


def test_masks_of_terminal_output_taps_are_zero():
    # A round-output tap exposes a wire without consuming it, so it is not a
    # coordinate of the function the trail describes. Left free, its fork
    # branch lets the solver dump mask into the tap and decouple the rounds.
    # The cipher output is excluded: its bits ARE output coordinates.
    speck = SpeckBlockCipher(number_of_rounds=2)
    smt = SmtXorQuasidifferentialModel(speck)

    constraints = smt._terminal_tap_mask_constraints()
    tapped = {c.split("qdt_")[1].rsplit("_", 1)[0] for c in constraints}

    assert "intermediate_output_0_6" in tapped
    assert not any("cipher_output" in c for c in constraints)


def test_sbox_with_a_non_power_of_two_qdt_is_refused():
    # The weight of a transition is -log2|coefficient| and the model encodes
    # it as an integer, so a coefficient of 3/8 would be silently recorded as
    # weight 1. The differential models already refuse such an S-box through
    # check_table_feasibility; this is the QDT-side counterpart.
    smt = SmtXorQuasidifferentialModel(HeysBlockCipher(number_of_rounds=1))

    with pytest.raises(ValueError, match="not a power of two"):
        smt.build_xor_quasidifferential_trail_model(weight=2)


def test_model_admits_the_masks_of_equation_4():
    admissible = [
        (0x00, 0x00, 1),   # coefficient +0.5000
        (0x40, 0x42, 2),   # coefficient -0.2500
        (0x40, 0x53, 2),   # coefficient +0.2500
        (0x80, 0x0F, 3),   # coefficient +0.1250
        (0x80, 0x1E, 3),   # coefficient -0.1250
    ]

    for input_mask, output_mask, weight in admissible:
        result = _solve_speck8_with_masks(input_mask, output_mask, weight)
        assert result["status"] == "SATISFIABLE", (
            f"an admissible mask was rejected: u={input_mask:#04x} "
            f"v={output_mask:#04x} weight {weight}"
        )


def test_model_rejects_the_masks_outside_equation_4():
    # The direction that matters whenever a constraint is relaxed: the risk
    # then is over-permissiveness, which no SATISFIABLE assertion can catch.
    inadmissible = [(0x00, 0x01), (0x00, 0x02), (0x00, 0x03)]

    for input_mask, output_mask in inadmissible:
        for weight in (1, 2, 3):
            result = _solve_speck8_with_masks(input_mask, output_mask, weight)
            assert result["status"] == "UNSATISFIABLE", (
                f"an impossible mask was accepted: u={input_mask:#04x} "
                f"v={output_mask:#04x} weight {weight}"
            )


def _solve_speck8_with_masks(input_mask, output_mask, weight):
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(speck)

    fixed_values = [
        set_fixed_variables(INPUT_KEY, "equal", range(16), (0,) * 16),
        set_fixed_variables(INPUT_PLAINTEXT, "equal", range(8), integer_to_bit_list(0x01, 8, "big")),
        set_fixed_variables("cipher_output_0_6", "equal", range(8), integer_to_bit_list(0x19, 8, "big")),
    ]

    smt.build_xor_quasidifferential_trail_model(weight=weight, fixed_variables=fixed_values)
    if smt._counter == smt._sequential_counter:
        smt._sequential_counter_greater_or_equal(weight, "dummy_hw_1")

    masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(8),
         "bit_values": integer_to_bit_list(input_mask, 8, "big")},
        {"component_id": "cipher_output_0_6", "bit_positions": range(8),
         "bit_values": integer_to_bit_list(output_mask, 8, "big")},
    ]
    extra = smt._build_fixed_mask_constraints(masks)
    smt._model_constraints = (
        smt._model_constraints[: -len(constants.MODEL_SUFFIX)] + extra + constants.MODEL_SUFFIX
    )

    return smt.solve(XOR_QUASIDIFFERENTIAL, solver_name=Z3_EXT)


def _simon_six_round_characteristic():
    cipher = SimonBlockCipher(number_of_rounds=6)
    differences = [0x00400110, 0x00100040, 0x00000010, 0x00100000, 0x00400010, 0x01100040, 0x01100040]
    taps = [c.id for c in cipher.get_all_components()
            if c.description[0] in ("round_output", "cipher_output")]

    fixed_values = [
        set_fixed_variables(INPUT_KEY, "equal", range(64), (0,) * 64),
        set_fixed_variables(INPUT_PLAINTEXT, "equal", range(32),
                            integer_to_bit_list(0x01100400, 32, "big")),
    ]
    for component_id, difference in zip(taps, differences):
        fixed_values.append(
            set_fixed_variables(component_id, "equal", range(32),
                                integer_to_bit_list(difference, 32, "big"))
        )

    boundary_masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(32), "bit_values": [0] * 32},
        {"component_id": "cipher_output_5_13", "bit_positions": range(32), "bit_values": [0] * 32},
    ]

    return cipher, fixed_values, boundary_masks


def test_estimate_fixed_key_probability_applies_the_key_factor():
    # This weight-12 Simon characteristic has four trails with zero boundary
    # masks: the characteristic itself, two weight-14 corrections of opposite
    # sign carrying disjoint key masks A and B, and a weight-16 trail carrying
    # A xor B. The probability therefore depends on the key only through
    # chi_A(k) and chi_B(k), and the average is NOT the fixed-key value.
    cipher, fixed_values, boundary_masks = _simon_six_round_characteristic()

    def probability(key):
        return SmtXorQuasidifferentialModel(cipher).estimate_fixed_key_probability(
            max_weight=16, min_weight=12,
            fixed_values=fixed_values, fixed_masks=boundary_masks, key=key,
        )

    average = probability(None)
    assert average["averaged_over_keys"] is True
    assert average["num_trails"] == 1           # only the zero-key-mask trail survives averaging
    assert average["num_trails_found"] == 4
    assert average["estimated_probability"] == 2.0**-12

    zero_key = probability(0)
    assert zero_key["averaged_over_keys"] is False
    assert zero_key["num_trails"] == 4
    assert zero_key["estimated_probability"] == 2.0**-12 - 2 * 2.0**-14 + 2.0**-16

    # 0x8000 is a single bit of A and lies outside B, so it flips chi_A only.
    flipped = probability(0x8000)
    assert flipped["estimated_probability"] == 2.0**-12 - 2.0**-16
    assert flipped["estimated_probability"] != zero_key["estimated_probability"]


def test_trail_sign_does_not_depend_on_solve_order():
    # compute_trail_sign reconstructs input masks from the solver assignment.
    # Held on the model, that assignment is overwritten by every later solve,
    # so a stored solution would be scored with the LAST trail's masks. Each
    # solution carries its own, so the order of the calls cannot matter.
    cipher, fixed_values, boundary_masks = _simon_six_round_characteristic()
    smt = SmtXorQuasidifferentialModel(cipher)

    solutions = [
        solution
        for weight in (12, 14)
        for solution in smt._solutions_at_weight(weight, fixed_values, boundary_masks, Z3_EXT, None, None)[0]
    ]
    assert len(solutions) == 3

    forwards = [smt.compute_trail_sign(solution) for solution in solutions]
    backwards = [smt.compute_trail_sign(solution) for solution in reversed(solutions)]

    assert forwards == list(reversed(backwards))
    assert len(set(forwards)) > 1        # otherwise the check proves nothing
    assert all(solution["qdt_variable_assignment"] for solution in solutions)


def test_weights_the_sequential_counter_cannot_express():
    # _sequential_counter_greater_or_equal rewrites "at least w" as "at most
    # n - w", so w == n collapses its inner dimension and it raises
    # IndexError. On 8-bit Speck at one round n is 4, so the crash sits right
    # inside the range a caller would naturally ask for.
    speck = SpeckBlockCipher(block_bit_size=8, key_bit_size=16, number_of_rounds=1)
    smt = SmtXorQuasidifferentialModel(speck)

    smt.build_xor_quasidifferential_trail_model(weight=1)
    indicators = len([v for v in smt._variables_list if v.startswith("hw_")])
    assert indicators == 4

    assert smt.find_one_xor_quasidifferential_trail_with_fixed_weight(indicators - 1)["total_weight"] == 3.0

    for weight in (indicators, indicators + 1, indicators + 3):
        assert smt.find_one_xor_quasidifferential_trail_with_fixed_weight(weight)["total_weight"] is None


def test_fixed_key_probability_matches_brute_force_on_an_spn():
    # The end-to-end reference so far was 8-bit Speck, an ARX: the S-box path
    # had never been compared with a measured probability. ToySPN1 is a 6-bit
    # SPN -- round-key XOR, two 3-bit S-boxes, a rotation -- so a
    # differential's exact probability can be counted over all 64 plaintexts,
    # for any key, and held against the signed sum of its trails.
    #
    # The comparison is made key by key, not only on the average: averaging
    # keeps only the zero-key-mask trails, so it would leave both the key
    # masks and the signs untested.
    toyspn = ToySPN1(number_of_rounds=2)
    delta_in, delta_out = 0x02, 0x20

    smt = SmtXorQuasidifferentialModel(toyspn)
    smt.build_xor_quasidifferential_trail_model()
    indicators = len([v for v in smt._variables_list if v.startswith("hw_")])
    assert indicators == 8          # no trail can weigh more, so the sum below is complete

    fixed_values = [
        set_fixed_variables(INPUT_KEY, "equal", range(6), (0,) * 6),
        set_fixed_variables(INPUT_PLAINTEXT, "equal", range(6), integer_to_bit_list(delta_in, 6, "big")),
        set_fixed_variables("cipher_output_1_6", "equal", range(6), integer_to_bit_list(delta_out, 6, "big")),
    ]
    boundary_masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(6), "bit_values": [0] * 6},
        {"component_id": "cipher_output_1_6", "bit_positions": range(6), "bit_values": [0] * 6},
    ]

    # key=0 keeps every trail in the list, each with its own key mask, so the
    # sum can be re-evaluated for the other keys without solving again.
    result = SmtXorQuasidifferentialModel(toyspn).estimate_fixed_key_probability(
        max_weight=indicators, min_weight=0,
        fixed_values=fixed_values, fixed_masks=boundary_masks, key=0,
    )
    trails = result["trails"]
    assert len(trails) == 4
    assert len([trail for trail in trails if trail["key_mask"]]) == 2

    def from_trails(key):
        return sum(
            (-1) ** bin(trail["key_mask"] & key).count("1") * trail["sign"] * 2.0 ** -trail["weight"]
            for trail in trails
        )

    def brute_force(key):
        outputs = [toyspn.evaluate([plaintext, key]) for plaintext in range(64)]
        hits = sum(1 for plaintext in range(64) if outputs[plaintext] ^ outputs[plaintext ^ delta_in] == delta_out)
        return hits / 64

    measured = {key: brute_force(key) for key in (0x00, 0x01, 0x02, 0x05, 0x0A, 0x3F)}

    assert set(measured.values()) == {0.0, 0.125, 0.25}      # otherwise the keys prove nothing
    for key, exact in measured.items():
        assert from_trails(key) == exact

    # The average is a different quantity, and the model says so itself.
    average = sum(trail["sign"] * 2.0 ** -trail["weight"] for trail in trails if trail["key_mask"] == 0)
    assert average == 0.125
    assert average != measured[0x00]


def test_enumeration_bounds_report_truncation():
    cipher, fixed_values, boundary_masks = _simon_six_round_characteristic()

    exact = 2.0**-12 - 2 * 2.0**-14 + 2.0**-16

    bounded = SmtXorQuasidifferentialModel(cipher).estimate_fixed_key_probability(
        max_weight=16, min_weight=12,
        fixed_values=fixed_values, fixed_masks=boundary_masks, key=0,
        max_trails_per_weight=1,
    )
    assert bounded["truncated"] is True
    assert bounded["truncated_weights"] == [12, 14, 16]
    assert bounded["num_trails"] == 3              # one of the two at weight 14 is missing
    assert bounded["estimated_probability"] != exact

    # timeout_per_weight=0 stops after the first trail of each weight too,
    # which makes the time-based bound checkable without a slow test.
    timed = SmtXorQuasidifferentialModel(cipher).estimate_fixed_key_probability(
        max_weight=16, min_weight=12,
        fixed_values=fixed_values, fixed_masks=boundary_masks, key=0,
        timeout_per_weight=0,
    )
    assert timed["truncated_weights"] == bounded["truncated_weights"]
    assert timed["estimated_probability"] == bounded["estimated_probability"]

    # Unbounded, the same call is exhaustive and says so.
    speck = SpeckBlockCipher(number_of_rounds=6)
    fixed_masks = [
        {"component_id": INPUT_PLAINTEXT, "bit_positions": range(32), "bit_values": [0] * 32},
        {"component_id": INPUT_KEY, "bit_positions": range(64), "bit_values": [0] * 64},
        {"component_id": "cipher_output_5_12", "bit_positions": range(32), "bit_values": [0] * 32},
    ]
    exhaustive = SmtXorQuasidifferentialModel(speck).estimate_fixed_key_probability(
        max_weight=13, min_weight=13,
        fixed_values=_speck_six_round_characteristic(), fixed_masks=fixed_masks,
    )
    assert exhaustive["truncated"] is False
    assert exhaustive["truncated_weights"] == []
    assert exhaustive["estimated_probability"] == 2.0**-13


def _speck_six_round_characteristic():
    differences = {
        INPUT_PLAINTEXT: 0x02110A04,
        "intermediate_output_0_6": 0x28000010,
        "intermediate_output_1_12": 0x00400000,
        "intermediate_output_2_12": 0x80008000,
        "intermediate_output_3_12": 0x81008102,
        "intermediate_output_4_12": 0x8000840A,
        "cipher_output_5_12": 0x850A9520,
    }
    fixed_values = [set_fixed_variables(INPUT_KEY, "equal", range(64), (0,) * 64)]
    for component_id, difference in differences.items():
        bit_values = [(difference >> (31 - i)) & 1 for i in range(32)]
        fixed_values.append(set_fixed_variables(component_id, "equal", range(32), bit_values))

    return fixed_values
