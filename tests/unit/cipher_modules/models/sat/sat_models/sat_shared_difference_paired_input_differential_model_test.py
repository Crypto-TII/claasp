from claasp.cipher_modules.models.sat.sat_models.sat_shared_difference_paired_input_differential_model import (
    SharedDifferencePairedInputDifferentialModel,
)
from claasp.cipher_modules.models.sat.solvers import CADICAL_EXT
from claasp.cipher_modules.models.utils import (
    set_fixed_variables,
    shared_difference_paired_input_differential_checker_permutation,
    integer_to_bit_list,
)
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation, ROUND_MODE_HALF
from claasp.name_mappings import INPUT_PLAINTEXT, SATISFIABLE


def test_sat_shared_difference_paired_input_differential_model_on_chacha_permutation():
    chacha1 = ChachaPermutation(number_of_rounds=1, round_mode=ROUND_MODE_HALF)
    sat_model = SharedDifferencePairedInputDifferentialModel(chacha1)

    fixed_variables = [
        set_fixed_variables(
            INPUT_PLAINTEXT,
            "equal",
            bit_positions=list(range(512)),
            bit_values=integer_to_bit_list(
                0x800000008000000080000000E0000000800000008000000080000000E00000008000000080000000800000008000400000008000000080000000800040008000,
                list_length=512,
                endianness="big",
            ),
        ),
        set_fixed_variables(
            "cipher_output_0_24",
            "equal",
            bit_positions=list(range(512)),
            bit_values=integer_to_bit_list(
                0x0000000000000000000000000000000000000800000008000000080000000E000000000000000000000000000000000080000000800000008000000080004000,
                list_length=512,
                endianness="big",
            ),
        ),
    ]
    trail = sat_model.find_one_shared_difference_paired_input_differential_trail_with_fixed_weight(
        8, fixed_variables, solver_name=CADICAL_EXT
    )

    assert trail["status"] == SATISFIABLE
    input_difference = int(trail["components_values"][INPUT_PLAINTEXT]["value"], 16)
    output_difference1 = int(trail["components_values"]["cipher_output_0_24"]["value"], 16)
    output_difference2 = int(trail["components_values"]["cipher1_cipher_output_0_24"]["value"], 16)
    prob = shared_difference_paired_input_differential_checker_permutation(
        chacha1, input_difference, output_difference1 ^ output_difference2, 1 << 13, 512, 16
    )
    assert prob <= 13
