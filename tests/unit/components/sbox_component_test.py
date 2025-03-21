from claasp.cipher_modules.models.cp.mzn_model import MznModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
from claasp.cipher_modules.models.smt.smt_model import SmtModel
from claasp.cipher_modules.models.sat.sat_model import SatModel
from claasp.cipher_modules.models.milp.milp_model import MilpModel
from claasp.cipher_modules.models.utils import set_fixed_variables
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.toys.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import \
    MilpBitwiseDeterministicTruncatedXorDifferentialModel
from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import \
    MilpWordwiseDeterministicTruncatedXorDifferentialModel

X_0_X_8 = "x_0 <= x_8"
X_O = "('x[xor_0_0_0]', x_0)"
X_1 = "('x[xor_0_0_1]', x_1)"
I_X_0 = "('x[sbox_0_1_0_i]', x_0)"
I_X_1 = "('x[sbox_0_1_1_i]', x_1)"


def test_algebraic_polynomials():
    fancy = FancyBlockCipher(number_of_rounds=1)
    sbox_component = fancy.component_from(0, 0)
    algebraic = AlgebraicModel(fancy)
    algebraic_polynomials = sbox_component.algebraic_polynomials(algebraic)

    assert str(algebraic_polynomials[0]) == 'sbox_0_0_y2 + sbox_0_0_x1'
    assert str(algebraic_polynomials[1]) == 'sbox_0_0_x0*sbox_0_0_y0 + sbox_0_0_x0*sbox_0_0_x3'
    assert str(algebraic_polynomials[-2]) == 'sbox_0_0_y1*sbox_0_0_y3 + sbox_0_0_x0*sbox_0_0_x2'
    assert str(algebraic_polynomials[-1]) == 'sbox_0_0_y2*sbox_0_0_y3 + sbox_0_0_x1*sbox_0_0_x2'


def test_cms_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    output_bit_ids, constraints = sbox_component.cms_constraints()

    assert output_bit_ids == ['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3']

    assert constraints[0] == 'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0'
    assert constraints[1] == 'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1'
    assert constraints[-3] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1'
    assert constraints[-2] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2'
    assert constraints[-1] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'


def test_cp_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    sbox_component = midori.component_from(0, 5)
    declarations, constraints = sbox_component.cp_constraints([])

    assert declarations == ['array [1..16, 1..8] of int: table_sbox_0_5 = array2d(1..16, 1..8, [0,0,0,0,1,1,0,0,0,'
                            '0,0,1,1,0,1,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0,1,1,0,1,1,0,'
                            '1,1,1,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,1,0,1,0,'
                            '1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,1,1,1,1,0,1,1,0]);']

    assert constraints == ['constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++[sbox_0_5[0]]++'
                           '[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]], table_sbox_0_5);']


def test_cp_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    sbox_component = aes.component_from(0, 1)
    declarations, constraints, sbox_mant = sbox_component.cp_deterministic_truncated_xor_differential_constraints(sbox_mant = [])
    print(constraints)

    assert constraints == ['constraint table([xor_0_0[0]]++[xor_0_0[1]]++[xor_0_0[2]]++[xor_0_0[3]]++[xor_0_0[4]]++[xor_0_0[5]]++'
                                    '[xor_0_0[6]]++[xor_0_0[7]]++[sbox_0_1[0]]++[sbox_0_1[1]]++[sbox_0_1[2]]++[sbox_0_1[3]]++[sbox_0_1[4]]++'
                                    '[sbox_0_1[5]]++[sbox_0_1[6]]++[sbox_0_1[7]], table_sbox_0_1);']
                  

def test_cp_xor_differential_propagation_constraints():
    midori = MidoriBlockCipher(number_of_rounds=3)
    cp = MznModel(midori)
    sbox_component = midori.component_from(0, 5)
    declarations, constraints = sbox_component.cp_xor_differential_propagation_constraints(cp)

    assert declarations == ['array [1..97, 1..9] of int: DDT_sbox_0_5 = array2d(1..97, 1..9, '
                            '[0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,300,0,0,0,1,0,0,1,0,200,0,0,0,1,0,1,0,0,300,0,'
                            '0,0,1,0,1,0,1,300,0,0,0,1,0,1,1,0,300,0,0,0,1,1,0,0,0,300,0,0,0,1,1,1,1,0,300,0,0,'
                            '1,0,0,0,0,1,200,0,0,1,0,0,1,0,0,200,0,0,1,0,1,0,0,1,200,0,0,1,0,1,1,0,0,200,0,0,1,'
                            '1,0,1,0,0,300,0,0,1,1,0,1,1,0,200,0,0,1,1,0,1,1,1,300,0,0,1,1,1,0,0,0,300,0,0,1,1,'
                            '1,0,0,1,300,0,0,1,1,1,1,0,1,300,0,0,1,1,1,1,1,1,300,0,1,0,0,0,0,0,1,300,0,1,0,0,0,'
                            '0,1,0,200,0,1,0,0,0,0,1,1,300,0,1,0,0,0,1,0,0,300,0,1,0,0,0,1,0,1,300,0,1,0,0,1,0,'
                            '0,0,300,0,1,0,0,1,0,1,1,300,0,1,0,1,0,0,0,1,300,0,1,0,1,0,1,0,0,300,0,1,0,1,0,1,1,'
                            '1,200,0,1,0,1,1,0,0,1,300,0,1,0,1,1,0,1,0,200,0,1,0,1,1,1,0,0,300,0,1,1,0,0,0,0,1,'
                            '300,0,1,1,0,0,0,1,1,200,0,1,1,0,0,1,1,1,300,0,1,1,0,1,0,0,0,300,0,1,1,0,1,1,0,0,300,'
                            '0,1,1,0,1,1,0,1,300,0,1,1,0,1,1,1,1,300,0,1,1,1,0,0,1,1,300,0,1,1,1,0,1,0,1,200,0,'
                            '1,1,1,0,1,1,0,300,0,1,1,1,1,0,1,1,300,0,1,1,1,1,1,0,1,200,0,1,1,1,1,1,1,0,300,1,0,'
                            '0,0,0,0,0,1,300,1,0,0,0,0,0,1,1,300,1,0,0,0,0,1,0,0,300,1,0,0,0,0,1,1,0,300,1,0,0,'
                            '0,1,0,0,1,300,1,0,0,0,1,0,1,1,300,1,0,0,0,1,1,0,0,300,1,0,0,0,1,1,1,0,300,1,0,0,1,'
                            '0,0,1,0,200,1,0,0,1,0,0,1,1,300,1,0,0,1,0,1,0,1,300,1,0,0,1,1,0,0,0,300,1,0,0,1,1,'
                            '0,0,1,300,1,0,0,1,1,0,1,1,300,1,0,0,1,1,1,0,0,300,1,0,1,0,0,1,0,1,200,1,0,1,0,1,0,'
                            '1,0,200,1,0,1,0,1,1,0,1,200,1,0,1,0,1,1,1,1,200,1,0,1,1,0,1,0,0,300,1,0,1,1,0,1,1,'
                            '1,300,1,0,1,1,1,0,0,0,300,1,0,1,1,1,0,0,1,300,1,0,1,1,1,0,1,1,200,1,0,1,1,1,1,0,1,'
                            '300,1,0,1,1,1,1,1,1,300,1,1,0,0,0,0,1,0,200,1,1,0,0,0,1,0,1,300,1,1,0,0,0,1,1,0,300,'
                            '1,1,0,0,1,0,0,0,300,1,1,0,0,1,0,0,1,300,1,1,0,0,1,1,0,0,300,1,1,0,0,1,1,1,0,300,1,'
                            '1,0,1,0,0,1,1,300,1,1,0,1,0,1,1,0,300,1,1,0,1,0,1,1,1,200,1,1,0,1,1,0,1,0,200,1,1,'
                            '0,1,1,0,1,1,300,1,1,0,1,1,1,1,0,300,1,1,1,0,0,0,0,1,300,1,1,1,0,0,1,1,1,300,1,1,1,'
                            '0,1,0,0,0,300,1,1,1,0,1,1,0,0,300,1,1,1,0,1,1,0,1,300,1,1,1,0,1,1,1,0,200,1,1,1,0,'
                            '1,1,1,1,300,1,1,1,1,0,0,1,1,300,1,1,1,1,0,1,1,0,300,1,1,1,1,1,0,1,0,200,1,1,1,1,1,'
                            '0,1,1,300,1,1,1,1,1,1,1,0,300,1,1,1,1,1,1,1,1,200]);']

    assert constraints == ['constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++'
                           '[sbox_0_5[0]]++[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]]++[p[0]], DDT_sbox_0_5);']


def test_cp_xor_linear_mask_propagation_constraints():
    midori = MidoriBlockCipher()
    cp = MznModel(midori)
    sbox_component = midori.component_from(0, 5)
    result = sbox_component.cp_xor_linear_mask_propagation_constraints(cp)[1:]
    assert result == (['constraint table([sbox_0_5_i[0]]++[sbox_0_5_i[1]]++[sbox_0_5_i[2]]++[sbox_0_5_i[3]]++'
                       '[sbox_0_5_o[0]]++[sbox_0_5_o[1]]++[sbox_0_5_o[2]]++[sbox_0_5_o[3]]++[p[0]],LAT_sbox_0_5);'],)


def test_milp_large_xor_differential_probability_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    milp = MilpModel(aes)
    milp.init_model_in_sage_milp_class()
    sbox_component = aes.component_from(0, 1)
    variables, constraints = \
        sbox_component.milp_large_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable,
                                                                           milp._non_linear_component_id)

    assert str(variables[0]) == X_O
    assert str(variables[1]) == X_1
    assert str(variables[-2]) == "('x[sbox_0_1_6]', x_14)"
    assert str(variables[-1]) == "('x[sbox_0_1_7]', x_15)"

    assert str(constraints[0]) == "x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 <= 8*x_16"
    assert str(constraints[1]) == "1 - x_0 - x_1 - x_2 - x_3 - x_4 - x_5 - x_6 - x_7 <= 8 - 8*x_16"
    assert str(constraints[2]) == "x_8 <= x_16"


def test_milp_large_xor_linear_probability_constraints():
    aes = AESBlockCipher(number_of_rounds=3)
    milp = MilpModel(aes)
    milp.init_model_in_sage_milp_class()
    sbox_component = aes.component_from(0, 1)
    variables, constraints = \
        sbox_component.milp_large_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable,
                                                                     milp._non_linear_component_id)

    assert str(variables[0]) == I_X_0
    assert str(variables[1]) == I_X_1
    assert str(variables[-2]) == "('x[sbox_0_1_6_o]', x_14)"
    assert str(variables[-1]) == "('x[sbox_0_1_7_o]', x_15)"

    assert str(constraints[0]) == "x_0 + x_1 + x_2 + x_3 + x_4 + x_5 + x_6 + x_7 <= 8*x_16"
    assert str(constraints[1]) == "1 - x_0 - x_1 - x_2 - x_3 - x_4 - x_5 - x_6 - x_7 <= 8 - 8*x_16"
    assert str(constraints[-2]) == "x_17 + x_18 + x_19 + x_20 + x_21 + x_22 + x_23 + x_24 + x_25 + x_26 + x_27 + " \
                                   "x_28 + x_29 + x_30 + x_31 + x_32 == x_16"
    assert str(constraints[-1]) == "x_33 == 600*x_17 + 500*x_18 + 442*x_19 + 400*x_20 + 368*x_21 + 342*x_22 + " \
                                    "319*x_23 + 300*x_24 + 300*x_25 + 319*x_26 + 342*x_27 + 368*x_28 + 400*x_29 + " \
                                    "442*x_30 + 500*x_31 + 600*x_32"


def test_milp_small_xor_differential_probability_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0, 1)
    variables, constraints = \
        sbox_component.milp_small_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable,
                                                                           milp._non_linear_component_id)

    assert str(variables[0]) == X_O
    assert str(variables[1]) == X_1
    assert str(variables[-2]) == "('x[sbox_0_1_2]', x_6)"
    assert str(variables[-1]) == "('x[sbox_0_1_3]', x_7)"

    assert str(constraints[0]) == "x_8 <= x_0 + x_1 + x_2 + x_3"
    assert str(constraints[1]) == X_0_X_8
    assert str(constraints[-2]) == "x_9 + x_10 == x_8"
    assert str(constraints[-1]) == "x_11 == 300*x_9 + 200*x_10"


def test_milp_small_xor_linear_probability_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0, 1)
    variables, constraints = \
        sbox_component.milp_small_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable,
                                                                     milp._non_linear_component_id)

    assert str(variables[0]) == I_X_0
    assert str(variables[1]) == I_X_1
    assert str(variables[-2]) == "('x[sbox_0_1_2_o]', x_6)"
    assert str(variables[-1]) == "('x[sbox_0_1_3_o]', x_7)"

    assert str(constraints[0]) == "x_8 <= x_4 + x_5 + x_6 + x_7"
    assert str(constraints[1]) == X_0_X_8
    assert str(constraints[-2]) == "x_9 + x_10 + x_11 + x_12 == x_8"
    assert str(constraints[-1]) == "x_13 == 200*x_9 + 100*x_10 + 100*x_11 + 200*x_12"


def test_milp_xor_differential_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpXorDifferentialModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0, 1)
    variables, constraints = sbox_component.milp_xor_differential_propagation_constraints(milp)

    assert str(variables[0]) == X_O
    assert str(variables[1]) == X_1
    assert str(variables[-2]) == "('x[sbox_0_1_2]', x_6)"
    assert str(variables[-1]) == "('x[sbox_0_1_3]', x_7)"

    assert str(constraints[0]) == "x_0 + x_1 + x_2 + x_3 <= 4*x_8"
    assert str(constraints[1]) == "1 - x_0 - x_1 - x_2 - x_3 <= 4 - 4*x_8"
    assert str(constraints[-2]) == "x_9 + x_10 == x_8"
    assert str(constraints[-1]) == "x_11 == 300*x_9 + 200*x_10"


def test_milp_xor_linear_mask_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpXorLinearModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0, 1)
    variables, constraints = sbox_component.milp_xor_linear_mask_propagation_constraints(milp)

    assert str(variables[0]) == I_X_0
    assert str(variables[1]) == I_X_1
    assert str(variables[-2]) == "('x[sbox_0_1_2_o]', x_6)"
    assert str(variables[-1]) == "('x[sbox_0_1_3_o]', x_7)"

    assert str(constraints[0]) == "x_0 + x_1 + x_2 + x_3 <= 4*x_8"
    assert str(constraints[1]) == "1 - x_0 - x_1 - x_2 - x_3 <= 4 - 4*x_8"
    assert str(constraints[-2]) == "x_9 + x_10 + x_11 + x_12 == x_8"
    assert str(constraints[-1]) == "x_13 == 200*x_9 + 100*x_10 + 100*x_11 + 200*x_12"


def test_sat_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    output_bit_ids, constraints = sbox_component.sat_constraints()

    assert output_bit_ids == ['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3']

    assert constraints[0] == 'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0'
    assert constraints[1] == 'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1'
    assert constraints[-3] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1'
    assert constraints[-2] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2'
    assert constraints[-1] == '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'


def test_sat_bitwise_deterministic_truncated_xor_differential_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    output_bit_ids, constraints = sbox_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()

    assert output_bit_ids[0] == 'sbox_0_2_0_0'
    assert output_bit_ids[1] == 'sbox_0_2_1_0'
    assert output_bit_ids[2] == 'sbox_0_2_2_0'

    assert constraints[-3] == '-xor_0_0_6_0 sbox_0_2_3_0'
    assert constraints[-2] == '-xor_0_0_5_0 sbox_0_2_3_0'
    assert constraints[-1] == '-xor_0_0_4_0 sbox_0_2_3_0'


def test_sat_xor_differential_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    sat = SatModel(present)
    output_bit_ids, constraints = sbox_component.sat_xor_differential_propagation_constraints(sat)

    assert output_bit_ids[0] == 'sbox_0_2_0'
    assert output_bit_ids[1] == 'sbox_0_2_1'
    assert output_bit_ids[2] == 'sbox_0_2_2'

    assert constraints[-3] == 'hw_sbox_0_2_2 -hw_sbox_0_2_3'
    assert constraints[-2] == 'xor_0_0_5 xor_0_0_6 sbox_0_2_0 sbox_0_2_2 -hw_sbox_0_2_1'
    assert constraints[-1] == '-hw_sbox_0_2_0'


def test_sat_xor_linear_mask_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    sat = SatModel(present)
    bit_ids, constraints = sbox_component.sat_xor_linear_mask_propagation_constraints(sat)

    assert bit_ids[0] == 'sbox_0_2_0_i'
    assert bit_ids[1] == 'sbox_0_2_1_i'
    assert bit_ids[2] == 'sbox_0_2_2_i'

    assert constraints[-3] == '-sbox_0_2_0_i -sbox_0_2_1_i sbox_0_2_2_i sbox_0_2_1_o -hw_sbox_0_2_2_o'
    assert constraints[-2] == '-hw_sbox_0_2_1_o'
    assert constraints[-1] == '-hw_sbox_0_2_0_o'


def test_smt_constraints():
    present = PresentBlockCipher(key_bit_size=80, number_of_rounds=3)
    sbox_component = present.component_from(0, 1)
    output_bit_ids, constraints = sbox_component.smt_constraints()

    assert output_bit_ids == ['sbox_0_1_0', 'sbox_0_1_1', 'sbox_0_1_2', 'sbox_0_1_3']

    assert constraints[0] == '(assert (=> (and (not xor_0_0_0) (not xor_0_0_1) (not xor_0_0_2) (not xor_0_0_3)) ' \
                             '(and sbox_0_1_0 sbox_0_1_1 (not sbox_0_1_2) (not sbox_0_1_3))))'
    assert constraints[1] == '(assert (=> (and (not xor_0_0_0) (not xor_0_0_1) (not xor_0_0_2) xor_0_0_3) (and ' \
                             '(not sbox_0_1_0) sbox_0_1_1 (not sbox_0_1_2) sbox_0_1_3)))'
    assert constraints[-3] == '(assert (=> (and xor_0_0_0 xor_0_0_1 (not xor_0_0_2) xor_0_0_3) (and ' \
                              '(not sbox_0_1_0) sbox_0_1_1 sbox_0_1_2 sbox_0_1_3)))'
    assert constraints[-2] == '(assert (=> (and xor_0_0_0 xor_0_0_1 xor_0_0_2 (not xor_0_0_3)) (and ' \
                              '(not sbox_0_1_0) (not sbox_0_1_1) (not sbox_0_1_2) sbox_0_1_3)))'
    assert constraints[-1] == '(assert (=> (and xor_0_0_0 xor_0_0_1 xor_0_0_2 xor_0_0_3) (and (not sbox_0_1_0) ' \
                              '(not sbox_0_1_1) sbox_0_1_2 (not sbox_0_1_3))))'


def test_smt_xor_differential_propagation_constraints():
    fancy = FancyBlockCipher(number_of_rounds=3)
    smt = SmtModel(fancy)
    sbox_component = fancy.component_from(0, 5)
    output_bit_ids, constraints = sbox_component.smt_xor_differential_propagation_constraints(smt)

    assert output_bit_ids[0] == 'sbox_0_5_0'
    assert output_bit_ids[1] == 'sbox_0_5_1'
    assert output_bit_ids[-2] == 'hw_sbox_0_5_2'
    assert output_bit_ids[-1] == 'hw_sbox_0_5_3'

    assert constraints[0] == '(assert (or (not plaintext_20) sbox_0_5_3))'
    assert constraints[1] == '(assert (or plaintext_20 (not sbox_0_5_3)))'
    assert constraints[-2] == '(assert (or (not hw_sbox_0_5_1)))'
    assert constraints[-1] == '(assert (or (not hw_sbox_0_5_0)))'


def test_smt_xor_linear_mask_propagation_constraints():
    present = PresentBlockCipher(number_of_rounds=3)
    sbox_component = present.component_from(0, 2)
    smt = SmtModel(present)
    output_bit_ids, constraints = sbox_component.smt_xor_linear_mask_propagation_constraints(smt)

    assert output_bit_ids[0] == 'sbox_0_2_0_i'
    assert output_bit_ids[1] == 'sbox_0_2_1_i'
    assert output_bit_ids[-2] == 'hw_sbox_0_2_2_o'
    assert output_bit_ids[-1] == 'hw_sbox_0_2_3_o'

    assert constraints[0] == '(assert (or sbox_0_2_0_i sbox_0_2_1_i sbox_0_2_2_i (not sbox_0_2_0_o) sbox_0_2_1_o))'
    assert constraints[1] == '(assert (or sbox_0_2_2_i sbox_0_2_3_i sbox_0_2_0_o sbox_0_2_1_o (not sbox_0_2_3_o) ' \
                             'hw_sbox_0_2_2_o))'
    assert constraints[-2] == '(assert (or (not hw_sbox_0_2_1_o)))'
    assert constraints[-1] == '(assert (or (not hw_sbox_0_2_0_o)))'

def test_milp_bitwise_deterministic_truncated_xor_differential_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0,1)
    variables, constraints = sbox_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x_class[xor_0_0_0]', x_0)"
    assert str(variables[1]) == "('x_class[xor_0_0_1]', x_1)"
    assert str(variables[-2]) == "('x_class[sbox_0_1_2]', x_6)"
    assert str(variables[-1]) == "('x_class[sbox_0_1_3]', x_7)"


    assert str(constraints[0]) == 'x_0 + x_1 + x_2 + x_3 <= 8 - 8*x_8'
    assert str(constraints[1]) == '1 - 8*x_8 <= x_0 + x_1 + x_2 + x_3'
    assert str(constraints[-2]) == 'x_7 <= 2 + 2*x_8'
    assert str(constraints[-1]) == '2 <= x_7 + 2*x_8'

def test_milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints():
    present = PresentBlockCipher(number_of_rounds=6)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
    milp.init_model_in_sage_milp_class()
    sbox_component = present.component_from(0, 1)
    variables, constraints = sbox_component.milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[xor_0_0_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[xor_0_0_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[sbox_0_1_3_class_bit_0]', x_14)"
    assert str(variables[-1]) == "('x[sbox_0_1_3_class_bit_1]', x_15)"

    assert str(constraints[0]) == 'x_16 == 2*x_0 + x_1'
    assert str(constraints[1]) == 'x_17 == 2*x_2 + x_3'
    assert str(constraints[-2]) == '1 <= 2 - x_2 - x_15'
    assert str(constraints[-1]) == '1 <= 2 - x_0 - x_15'

    present = PresentBlockCipher(number_of_rounds=1)
    milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(present)
    plaintext = set_fixed_variables(component_id='plaintext', constraint_type='equal', bit_positions=range(64),
                                    bit_values=[2, 0, 0, 0] + [1, 0, 0, 1] + [0, 0, 0, 1] + [1, 0, 0, 0] + [0] * 48)
    key = set_fixed_variables(component_id='key', constraint_type='equal', bit_positions=range(64), bit_values=[0] * 64)
    trail = milp.find_one_bitwise_deterministic_truncated_xor_differential_trail(fixed_values=[plaintext, key])

    assert trail['components_values']['sbox_0_1']['value'] == '????'
    assert trail['components_values']['sbox_0_2']['value'] == '???0'
    assert trail['components_values']['sbox_0_3']['value'] == '???1'
    assert trail['components_values']['sbox_0_4']['value'] == '???1'

def test_milp_wordwise_deterministic_truncated_xor_differential_constraints():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    milp.init_model_in_sage_milp_class()
    sbox_component = aes.component_from(0,1)
    variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)

    assert str(variables[0]) == "('x[xor_0_0_word_0_class_bit_0]', x_0)"
    assert str(variables[1]) == "('x[xor_0_0_word_0_class_bit_1]', x_1)"
    assert str(variables[-2]) == "('x[sbox_0_1_word_0_class_bit_0]', x_2)"
    assert str(variables[-1]) == "('x[sbox_0_1_word_0_class_bit_1]', x_3)"

    assert str(constraints[0]) == 'x_0 + x_1 <= 1 + x_3'
    assert str(constraints[1]) == 'x_2 <= x_0 + x_1'
    assert str(constraints[-2]) == 'x_1 <= x_2'
    assert str(constraints[-1]) == 'x_0 <= x_2'

def test_milp_wordwise_deterministic_truncated_xor_differential_simple_constraints():
    aes = AESBlockCipher(number_of_rounds=2)
    milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(aes)
    milp.init_model_in_sage_milp_class()
    sbox_component = aes.component_from(0, 1)
    variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(milp)

    assert str(variables[0]) == "('x_class[xor_0_0_word_0_class]', x_0)"
    assert str(variables[1]) == "('x_class[sbox_0_1_word_0_class]', x_1)"

    assert str(constraints[0]) == 'x_0 <= 5 - 4*x_2'
    assert str(constraints[1]) == '2 - 4*x_2 <= x_0'
    assert str(constraints[-2]) == 'x_0 <= x_1 + 4*x_4'
    assert str(constraints[-1]) == 'x_1 <= x_0 + 4*x_4'
