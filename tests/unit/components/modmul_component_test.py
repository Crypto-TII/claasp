import itertools

from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import (
    MilpBitwiseDeterministicTruncatedXorDifferentialModel,
)
from claasp.ciphers.single_component_ciphers.modmul_cipher import ModmulCipher
from claasp.components.modmul_component import ModMul


def test_modmul_component_creation():
    component = ModMul(
        current_round_number=1,
        current_round_number_of_components=0,
        input_id_links=["input1", "input2"],
        input_bit_positions=[[0, 1, 2, 3], [0, 1, 2, 3]],
        output_bit_size=4,
        modulus=16
    )
    
    assert component.id == "modmul_1_0"
    assert component.type == "word_operation"
    assert component.input_bit_size == 8
    assert component.output_bit_size == 4
    
    # Check evaluation string mapping based on the vector eval implementations
    bit_eval = component.get_bit_based_vectorized_python_code(["a", "b"], False)
    assert bit_eval == ["  modmul_1_0 = bit_vector_MODMUL([a,b ], 2, 4)"]
    
    byte_eval = component.get_byte_based_vectorized_python_code(["a", "b"])
    assert byte_eval == ["  modmul_1_0 = byte_vector_MODMUL(['a', 'b'])"]


# ---------------------------------------------------------------------------
# Deterministic truncated XOR differential model.
#
# The rule the two models below encode: a difference in either operand can only
# reach output bits at the position of the lowest active or unknown operand bit
# and above. Everything less significant than that stays 0, and nothing above it
# is ever a determined 1. Bit index 0 is the most significant, so "lowest" means
# the largest index carrying activity.
# ---------------------------------------------------------------------------

WORD = 3
UNKNOWN, ONE, ZERO = (1, 0), (0, 1), (0, 0)


def _component(word_bit_size=WORD):
    return ModMul(
        current_round_number=0,
        current_round_number_of_components=0,
        input_id_links=["plaintext", "key"],
        input_bit_positions=[list(range(word_bit_size))] * 2,
        output_bit_size=word_bit_size,
        modulus=2**word_bit_size,
    )


def _expected_output_classes(operand_a, operand_b):
    """The rule, written out independently of the model."""
    active = [j for j in range(len(operand_a)) if operand_a[j] != ZERO or operand_b[j] != ZERO]
    if not active:
        return [ZERO] * len(operand_a)
    lowest = max(active)
    return [UNKNOWN if j <= lowest else ZERO for j in range(len(operand_a))]


def _is_satisfied(clauses, assignment):
    for clause in clauses:
        literals = clause.split()
        if not any(
            (not assignment[lit[1:]]) if lit.startswith("-") else assignment[lit]
            for lit in literals
        ):
            return False
    return True


def test_sat_truncated_never_makes_an_output_bit_a_determined_one():
    _, constraints = _component().sat_bitwise_deterministic_truncated_xor_differential_constraints()

    for j in range(WORD):
        assert f"-modmul_0_0_{j}_1" in constraints


def test_sat_truncated_chains_activity_from_the_least_significant_bit_upwards():
    _, constraints = _component().sat_bitwise_deterministic_truncated_xor_differential_constraints()
    long_clause = {c.split()[0].lstrip("-"): c.split()[1:] for c in constraints if len(c.split()) > 2}

    # the least significant bit has nothing below it to chain
    assert f"modmul_0_0_{WORD - 1}_0" not in " ".join(long_clause[f"modmul_0_0_{WORD - 1}_0"])
    # every other bit carries the accumulated flag of the bit below it
    for j in range(WORD - 1):
        assert f"modmul_0_0_{j + 1}_0" in long_clause[f"modmul_0_0_{j}_0"]


def test_sat_truncated_clauses_admit_exactly_the_expected_output():
    """Brute force over every input class pattern, on a 3-bit word."""
    _, constraints = _component().sat_bitwise_deterministic_truncated_xor_differential_constraints()
    states = [ZERO, ONE, UNKNOWN]

    for pattern in itertools.product(states, repeat=2 * WORD):
        operand_a, operand_b = pattern[:WORD], pattern[WORD:]
        assignment = {}
        for j in range(WORD):
            assignment[f"plaintext_{j}_0"], assignment[f"plaintext_{j}_1"] = operand_a[j]
            assignment[f"key_{j}_0"], assignment[f"key_{j}_1"] = operand_b[j]

        satisfying = []
        for out in itertools.product(states + [(1, 1)], repeat=WORD):
            for j in range(WORD):
                assignment[f"modmul_0_0_{j}_0"], assignment[f"modmul_0_0_{j}_1"] = out[j]
            if _is_satisfied(constraints, assignment):
                satisfying.append(out)

        assert satisfying == [tuple(_expected_output_classes(operand_a, operand_b))]


def test_milp_truncated_sets_every_output_bit_to_twice_an_accumulator():
    cipher = ModmulCipher(word_bit_size=WORD, number_of_inputs=2)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
    milp.init_model_in_sage_milp_class()
    component = cipher.component_from_id("modmul_0_0")
    variables, constraints = component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    # two operands plus the output, one class variable per bit
    assert [str(name) for name, _ in variables] == (
        [f"x_class[plaintext_{j}]" for j in range(WORD)]
        + [f"x_class[key_{j}]" for j in range(WORD)]
        + [f"x_class[modmul_0_0_{j}]" for j in range(WORD)]
    )

    # every output bit is twice a binary flag, so it is 0 or 2 but never a determined 1
    output_terms = {str(var) for _, var in variables[2 * WORD :]}
    doubled = {str(c).split("==")[0].strip() for c in constraints if "== 2*" in str(c)}
    assert doubled == output_terms
