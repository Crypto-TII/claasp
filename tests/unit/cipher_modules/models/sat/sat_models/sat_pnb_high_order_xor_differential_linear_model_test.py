from claasp.cipher_modules.models.sat.sat_models.sat_pnb_high_order_xor_differential_model import \
    SatPnbHighOrderXorDifferentialModel
from claasp.cipher_modules.models.utils import set_fixed_variables, pnb_high_order_xor_differential_checker_permutation, \
    integer_to_bit_list
from claasp.ciphers.permutations.chacha_permutation import ChachaPermutation


def test_sat_pnb_high_order_xor_on_chacha_permutation():
    chacha1 = ChachaPermutation(number_of_rounds=1)
    sat_model = SatPnbHighOrderXorDifferentialModel(chacha1)

    fixed_variables = [
        set_fixed_variables(
            'plaintext',
            'equal',
            bit_positions=list(range(512)),
            bit_values=integer_to_bit_list(
                0x40000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
                list_length=512,
                endianness='big'
            )
        ),
        set_fixed_variables(
            'cipher_output_0_24',
            'equal',
            bit_positions=list(range(512)),
            bit_values=integer_to_bit_list(
                0x00000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
                list_length=512,
                endianness='big'
            )
        )
    ]
    trail = sat_model.find_one_pnb_high_order_xor_differential_trail_with_fixed_weight(
        18,
        fixed_variables,
        solver_name="CADICAL_EXT"
    )
    assert trail['status'] == 'SATISFIABLE'
    input_difference = int(trail['components_values']['plaintext']['value'], 16)
    output_difference1 = int(trail['components_values']['cipher_output_0_24']['value'], 16)
    output_difference2 = int(trail['components_values']['cipher1_cipher_output_0_24']['value'], 16)
    prob = pnb_high_order_xor_differential_checker_permutation(
        chacha1,
        input_difference,
        output_difference1 ^ output_difference2,
        1 << 15,
        512,
        16
    )
    assert prob <= 16
