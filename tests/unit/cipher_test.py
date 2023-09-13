import os
import sys
import pytest
import inspect
import os.path
import numpy as np
from io import StringIO
from decimal import Decimal

import claasp
from claasp.cipher import Cipher
from claasp.ciphers.block_ciphers.tea_block_cipher import TeaBlockCipher
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.xtea_block_cipher import XTeaBlockCipher
from claasp.ciphers.permutations.ascon_permutation import AsconPermutation
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.ciphers.permutations.xoodoo_permutation import XoodooPermutation
from claasp.ciphers.block_ciphers.fancy_block_cipher import FancyBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.identity_block_cipher import IdentityBlockCipher
from claasp.cipher_modules.neural_network_tests import find_good_input_difference_for_neural_distinguisher
from claasp.cipher_modules.neural_network_tests import get_differential_dataset
from claasp.cipher_modules.neural_network_tests import get_differential_dataset, get_neural_network


EVALUATION_PY = 'evaluation.py'
DICTIONARY_EXAMPLE_PY = "claasp/ciphers/dictionary_example.py"
BIT_BASED_C_FUNCTIONS_O_FILE = 'claasp/cipher_modules/generic_bit_based_c_functions.o'
FANCY_EVALUATE_O_FILE = 'claasp/cipher_modules/fancy_block_cipher_p24_k24_o24_r20_evaluate.o'
FANCY_EVALUATE_C_FILE = 'claasp/cipher_modules/fancy_block_cipher_p24_k24_o24_r20_evaluate.c'


def test_algebraic_tests():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=2)
    d = speck.algebraic_tests(5)
    assert d == {'input_parameters': {'timeout': 5}, 'test_results': {'number_of_variables': [304, 800],
                                                                      'number_of_equations': [240, 688],
                                                                      'number_of_monomials': [304, 800],
                                                                      'max_degree_of_equations': [1, 1],
                                                                      'test_passed': [False, False]}}

    aes = AESBlockCipher(word_size=4, state_size=2, number_of_rounds=2)
    d = aes.algebraic_tests(5)
    compare_result = {'input_parameters': {'timeout': 5},
                      'test_results': {'number_of_variables': [352, 592],
                                       'number_of_equations': [406, 748],
                                       'number_of_monomials': [520, 928],
                                       'max_degree_of_equations': [2, 2],
                                       'test_passed': [False, True]}}

    assert d != compare_result  # skipped (need to be fixed)


def test_analyze_cipher():
    sp = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    tests_configuration = {"diffusion_tests": {"run_tests": True,
                                               "number_of_samples": 100,
                                               "run_avalanche_dependence": True,
                                               "run_avalanche_dependence_uniform": True,
                                               "run_avalanche_weight": True,
                                               "run_avalanche_entropy": True,
                                               "avalanche_dependence_uniform_bias": 0.2,
                                               "avalanche_dependence_criterion_threshold": 0,
                                               "avalanche_dependence_uniform_criterion_threshold": 0,
                                               "avalanche_weight_criterion_threshold": 0.1,
                                               "avalanche_entropy_criterion_threshold": 0.1},
                           "component_analysis_tests": {"run_tests": True}}
    analysis = sp.analyze_cipher(tests_configuration)
    assert analysis["diffusion_tests"]["test_results"]["key"]["round_output"]["avalanche_dependence_vectors"][
        "differences"][31]["output_vectors"][0]["vector"] == [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]


def test_avalanche_probability_vectors():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    apvs = speck.avalanche_probability_vectors(100)
    assert apvs["key"]["round_output"][31][0] == [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                                                  0.0, 1.0]


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_component_analysis():
    fancy = FancyBlockCipher(number_of_rounds=2)
    result = fancy.component_analysis_tests()
    assert len(result) == 9

    aes = AESBlockCipher(word_size=8, state_size=2, number_of_rounds=2)
    result = aes.component_analysis_tests()
    assert len(result) == 7

    present = PresentBlockCipher(number_of_rounds=2)
    result = present.component_analysis_tests()
    assert len(result) == 5

    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
    result = speck.component_analysis_tests()
    assert len(result) == 4

    tea = TeaBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=32)
    result = tea.component_analysis_tests()
    assert len(result) == 4


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_print_component_analysis_as_radar_charts():
    aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=2)
    result = aes.component_analysis_tests()
    fig = aes.print_component_analysis_as_radar_charts(result)
    assert str(type(fig)) == "<class 'module'>"


def test_compute_criterion_from_avalanche_probability_vectors():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    apvs = speck.avalanche_probability_vectors(100)
    d = speck.compute_criterion_from_avalanche_probability_vectors(apvs, 0.2)
    assert d["key"]["round_output"][0][0]["avalanche_dependence_vectors"] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                                                              0, 0, 0]


def test_continuous_avalanche_factor():
    aes = AESBlockCipher(number_of_rounds=5)
    result = aes.continuous_avalanche_factor(0.001, 300)
    assert result['plaintext']['cipher_output']['continuous_avalanche_factor']['values'][0]['value'] > 0.1


def test_continuous_diffusion_factor():
    speck = SpeckBlockCipher(number_of_rounds=2)
    output = speck.continuous_diffusion_factor(5, 20)
    assert output['plaintext']['cipher_output']['diffusion_factor']['values'][0]['2'] > 0


def test_continuous_diffusion_tests():
    speck_cipher = SpeckBlockCipher(number_of_rounds=1)
    output = speck_cipher.continuous_diffusion_tests()
    assert output['plaintext']['round_key_output']['continuous_neutrality_measure']['values'][0]['1'] == 0.0


def test_continuous_neutrality_measure_for_bit_j():
    output = SpeckBlockCipher(number_of_rounds=2).continuous_neutrality_measure_for_bit_j(50, 200)
    assert output['plaintext']['cipher_output']['continuous_neutrality_measure']['values'][0]['2'] > 0


def test_delete_generated_evaluate_c_shared_library():
    file_c = open(FANCY_EVALUATE_C_FILE, 'a')
    file_o = open(FANCY_EVALUATE_O_FILE, 'a')
    file_generic = open(BIT_BASED_C_FUNCTIONS_O_FILE, 'a')
    file_c.close()
    file_o.close()
    file_generic.close()
    FancyBlockCipher().delete_generated_evaluate_c_shared_library()
    assert os.path.exists(FANCY_EVALUATE_C_FILE) is False
    assert os.path.exists(FANCY_EVALUATE_O_FILE) is False
    assert os.path.exists(BIT_BASED_C_FUNCTIONS_O_FILE) is False


def test_diffusion_tests():
    speck = SpeckBlockCipher(block_bit_size=16, key_bit_size=32, number_of_rounds=5)
    d = speck.diffusion_tests(number_of_samples=100)
    assert d["test_results"]["key"]["round_output"]["avalanche_dependence_vectors"]["differences"][0][
        "output_vectors"][0]["vector"] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    aes = AESBlockCipher(word_size=8, state_size=4, number_of_rounds=4)
    d = aes.diffusion_tests(number_of_samples=1000)
    avalanche_dependence_vectors = d["test_results"]['key']['round_key_output']['avalanche_dependence_vectors']
    assert avalanche_dependence_vectors['input_bit_size'] == 128
    assert avalanche_dependence_vectors['differences'][0]['output_vectors'][0]['output_component_id'] == \
           'intermediate_output_0_35'
    assert avalanche_dependence_vectors['differences'][0]['output_vectors'][2]['output_component_id'] == \
           'intermediate_output_2_34'

    ascon = AsconPermutation(number_of_rounds=5)
    d = ascon.diffusion_tests(number_of_samples=1000)
    avalanche_weight_vectors = d["test_results"]['plaintext']['cipher_output']['avalanche_weight_vectors']
    assert avalanche_weight_vectors['input_bit_size'] == 320
    assert avalanche_weight_vectors['differences'][0]['output_vectors'][0]['output_component_id'] == \
           'cipher_output_4_40'

    keccak = KeccakPermutation(number_of_rounds=5, word_size=8)
    d = keccak.diffusion_tests(number_of_samples=1000)
    avalanche_dependence_uniform_vectors = d["test_results"]['plaintext']['round_output_nonlinear'][
        'avalanche_dependence_uniform_vectors']
    assert avalanche_dependence_uniform_vectors['input_bit_size'] == 200
    assert avalanche_dependence_uniform_vectors['differences'][0]['output_vectors'][0]['output_component_id'] == \
           'intermediate_output_0_141'
    assert avalanche_dependence_uniform_vectors['differences'][0]['output_vectors'][3]['output_component_id'] == \
           'intermediate_output_3_141'


def test_evaluate_using_c():
    assert FancyBlockCipher(number_of_rounds=2).evaluate_using_c([0x012345, 0x89ABCD], True) == {
        'round_key_output': [3502917, 73728],
        'round_output': [9834215],
        'cipher_output': [7457252]}


def test_evaluate_vectorized():
    speck = SpeckBlockCipher(block_bit_size=32, key_bit_size=64, number_of_rounds=22)
    K = np.random.randint(256, size=(8, 2), dtype=np.uint8)
    X = np.random.randint(256, size=(4, 2), dtype=np.uint8)
    result = speck.evaluate_vectorized([X, K])
    K0Lib = int.from_bytes(K[:, 0].tobytes(), byteorder='big')
    K1Lib = int.from_bytes(K[:, 1].tobytes(), byteorder='big')
    X0Lib = int.from_bytes(X[:, 0].tobytes(), byteorder='big')
    X1Lib = int.from_bytes(X[:, 1].tobytes(), byteorder='big')
    C0Lib = speck.evaluate([X0Lib, K0Lib])
    C1Lib = speck.evaluate([X1Lib, K1Lib])
    assert int.from_bytes(result[-1][0].tobytes(), byteorder='big') == C0Lib

    assert int.from_bytes(result[-1][1].tobytes(), byteorder='big') == C1Lib


def test_evaluate_with_intermediate_outputs_continuous_diffusion_analysis():
    plaintext_input = [Decimal('1') for _ in range(32)]
    plaintext_input[10] = Decimal('0.802999073954890452142763024312444031238555908203125')
    key_input = [Decimal('-1') for _ in range(64)]
    cipher_inputs = [plaintext_input, key_input]
    output = SpeckBlockCipher(number_of_rounds=2).evaluate_with_intermediate_outputs_continuous_diffusion_analysis(
        cipher_inputs, {}, {})
    assert output[0][0] == Decimal('-1.000000000')


def test_find_good_input_difference_for_neural_distinguisher():
    cipher = SpeckBlockCipher()
    diff, scores, highest_round = find_good_input_difference_for_neural_distinguisher(cipher, [True, False],
                                                                                      verbose=False,
                                                                                      number_of_generations=5)

    assert str(type(diff)) == "<class 'numpy.ndarray'>"
    assert str(type(scores)) == "<class 'numpy.ndarray'>"


def test_neural_staged_training():
    cipher = SpeckBlockCipher()
    input_differences = [0x400000, 0]
    data_generator = lambda nr, samples: get_differential_dataset(cipher, input_differences, number_of_rounds = nr, samples = samples)
    neural_network = get_neural_network('gohr_resnet', input_size = 64, word_size = 16)
    results_gohr = cipher.train_neural_distinguisher(data_generator, starting_round = 5, neural_network = neural_network, training_samples = 10**5, testing_samples = 10**5, epochs = 1)
    assert results_gohr[5] >= 0
    neural_network = get_neural_network('dbitnet', input_size = 64)
    results_dbitnet = cipher.train_neural_distinguisher(data_generator, starting_round = 5, neural_network = neural_network, training_samples = 10**5, testing_samples = 10**5, epochs = 1)
    assert results_dbitnet[5] >= 0


def test_get_differential_dataset():
    diff_value_plain_key = [0x400000, 0]
    cipher = SpeckBlockCipher()
    x, y = get_differential_dataset(cipher, diff_value_plain_key, 5, samples=10)
    assert x.shape == (10, 64)
    assert y.shape == (10, )

def test_get_model():
    speck = SpeckBlockCipher(number_of_rounds=1)
    assert speck.get_model("cp", "xor_differential").__class__.__name__ == "CpXorDifferentialModel"
    assert speck.get_model("sat", "xor_differential").__class__.__name__ == "SatXorDifferentialModel"
    assert speck.get_model("smt", "xor_linear").__class__.__name__ == "SmtXorLinearModel"
    assert speck.get_model("milp", "xor_linear").__class__.__name__ == "MilpXorLinearModel"

def test_generate_bit_based_c_code():
    bit_based_c_code = FancyBlockCipher().generate_bit_based_c_code()
    assert bit_based_c_code[:8] == '#include'
    assert '\tprint_bitstring(output, 16);' in bit_based_c_code

    bit_based_c_code = SpeckBlockCipher().generate_bit_based_c_code(True, True)
    assert '\tprintf("\\nROUND 0\\n\\n");\n' in bit_based_c_code


def test_generate_csv_report():
    tii_path = inspect.getfile(claasp)
    tii_dir_path = os.path.dirname(tii_path)
    identity = IdentityBlockCipher()
    identity.generate_csv_report(10, f"{tii_dir_path}/{identity.id}_report.csv")
    assert os.path.isfile(f"{tii_dir_path}/{identity.id}_report.csv")

    os.remove(f"{tii_dir_path}/{identity.id}_report.csv")


def test_generate_heatmap_graphs_for_avalanche_tests():
    sp = SpeckBlockCipher(block_bit_size=64, key_bit_size=128, number_of_rounds=5)
    d = sp.diffusion_tests(number_of_samples=100)
    h = sp.generate_heatmap_graphs_for_avalanche_tests(d)
    documentclass_pt_ = '\\documentclass[12pt]'
    assert h[:20] == documentclass_pt_

    ascon = AsconPermutation(number_of_rounds=4)
    d = ascon.diffusion_tests(number_of_samples=100)
    h = ascon.generate_heatmap_graphs_for_avalanche_tests(d, [0], ["avalanche_weight_vectors"])
    assert h[:20] == documentclass_pt_

    cipher = XoodooPermutation(number_of_rounds=4)
    d = cipher.diffusion_tests(number_of_samples=100)
    h = cipher.generate_heatmap_graphs_for_avalanche_tests(d, [1, 193], ["avalanche_dependence_vectors",
                                                                         "avalanche_entropy_vectors"])
    assert h[:20] == documentclass_pt_


def test_generate_word_based_c_code():
    word_based_c_code = SpeckBlockCipher().generate_word_based_c_code(20)
    assert word_based_c_code[:8] == '#include'

    word_based_c_code = SpeckBlockCipher().generate_word_based_c_code(20, True, True)
    assert '\tprintf("\\nROUND 0\\n\\n");\n' in word_based_c_code
    assert '\t\tprintf("\\"%s\\" : [", descriptions[i]);' in word_based_c_code


def test_get_component_from_id():
    fancy = FancyBlockCipher(number_of_rounds=2)
    component = fancy.get_component_from_id('sbox_0_0')
    assert component.description == [0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15]


def test_get_current_component_id():
    cipher = Cipher("cipher_name", "permutation", ["input"], [4], 4)
    cipher.add_round()
    cipher.add_constant_component(4, 0xF)
    cipher.add_constant_component(4, 0xF)
    cipher.add_round()
    cipher.add_constant_component(4, 0xF)
    assert cipher.get_current_component_id() == 'constant_1_0'


def test_get_round_from_component_id():
    fancy = FancyBlockCipher(number_of_rounds=2)
    assert fancy.get_round_from_component_id('xor_1_14') == 1


def test_impossible_differential_search():
    speck6 = SpeckBlockCipher(number_of_rounds=6)
    #impossible_differentials = speck6.impossible_differential_search("smt", "yices-smt2")
    impossible_differentials = speck6.impossible_differential_search("cp", "chuffed")

    assert ((0x400000, 1) in impossible_differentials) and ((0x400000, 2) in impossible_differentials) and ((0x400000, 0x8000) in impossible_differentials)

def test_is_algebraically_secure():
    identity = IdentityBlockCipher()
    assert identity.is_algebraically_secure(120) is False


def test_is_andrx():
    midori = MidoriBlockCipher(number_of_rounds=20)
    assert midori.is_andrx() is False


def test_is_arx():
    midori = MidoriBlockCipher(number_of_rounds=20)
    assert midori.is_arx() is False


def test_is_power_of_2_word_based():
    assert XTeaBlockCipher(number_of_rounds=32).is_power_of_2_word_based() == 32

    assert MidoriBlockCipher(number_of_rounds=16).is_power_of_2_word_based() is False


def test_is_shift_arx():
    xtea = XTeaBlockCipher(number_of_rounds=32)
    assert xtea.is_shift_arx() is True


def test_is_spn():
    aes = AESBlockCipher(number_of_rounds=2)
    assert aes.is_spn() is True


@pytest.mark.filterwarnings("ignore::DeprecationWarning:")
def test_neural_network_blackbox_distinguisher_tests():
    results = SpeckBlockCipher(number_of_rounds=5).neural_network_blackbox_distinguisher_tests(nb_samples=10)
    assert results['neural_network_blackbox_distinguisher_tests']['input_parameters'] == \
           {'number_of_samples': 10, 'hidden_layers': [32, 32, 32], 'number_of_epochs': 10}
    assert results['neural_network_blackbox_distinguisher_tests']['test_results']['plaintext']['cipher_output'][
               'accuracies'][0]['component_output_id'] == 'cipher_output_4_12'


def test_neural_network_differential_distinguisher_tests():
    results = SpeckBlockCipher(number_of_rounds=5).neural_network_differential_distinguisher_tests(nb_samples=10)
    assert results['neural_network_differential_distinguisher_tests']['input_parameters'] == \
           {'number_of_samples': 10, 'input_differences': [1], 'hidden_layers': [32, 32, 32], 'number_of_epochs': 10}
    assert results['neural_network_differential_distinguisher_tests']['test_results']['plaintext'][1]['round_output'][
               'accuracies'][0]['component_output_id'] == 'intermediate_output_0_6'


def test_polynomial_system():
    assert str(IdentityBlockCipher().polynomial_system()) == 'Polynomial Sequence with 128 Polynomials in 256 Variables'


def test_polynomial_system_at_round():
    assert str(FancyBlockCipher(number_of_rounds=1).polynomial_system_at_round(0)) == \
           'Polynomial Sequence with 252 Polynomials in 288 Variables'


def test_print():
    old_stdout = sys.stdout
    cipher = Cipher("cipher_name", "permutation", ["input"], [32], 32)
    cipher.add_round()
    cipher.add_constant_component(16, 0xAB01)
    cipher.add_constant_component(16, 0xAB01)
    result = StringIO()
    sys.stdout = result
    cipher.print()
    sys.stdout = old_stdout
    assert result.getvalue() == """cipher_id = cipher_name_i32_o32_r1
cipher_type = permutation
cipher_inputs = ['input']
cipher_inputs_bit_size = [32]
cipher_output_bit_size = 32
cipher_number_of_rounds = 1

    # round = 0 - round component = 0
    id = constant_0_0
    type = constant
    input_bit_size = 0
    input_id_link = ['']
    input_bit_positions = [[]]
    output_bit_size = 16
    description = ['0xab01']

    # round = 0 - round component = 1
    id = constant_0_1
    type = constant
    input_bit_size = 0
    input_id_link = ['']
    input_bit_positions = [[]]
    output_bit_size = 16
    description = ['0xab01']
cipher_reference_code = None
"""


def test_print_as_python_dictionary_to_file():
    cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
    cipher.print_as_python_dictionary_to_file(DICTIONARY_EXAMPLE_PY)
    assert os.path.isfile(DICTIONARY_EXAMPLE_PY)
    os.remove(DICTIONARY_EXAMPLE_PY)


def test_print_evaluation_python_code():
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    IdentityBlockCipher().print_evaluation_python_code(verbosity=True)
    sys.stdout = old_stdout
    python_code = result.getvalue()

    assert ("components_io['concatenate_0_0'] = [component_input.uint, concatenate_0_0_output.uint]" in python_code) \
           is True
    assert ("components_io['intermediate_output_0_1'] = [component_input.uint, intermediate_output_0_1_output.uint]"
            in python_code) is True
    assert ("component_input = select_bits(concatenate_0_2_output, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,"
            " 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])" in python_code) is True


def test_print_evaluation_python_code_to_file():
    identity = IdentityBlockCipher()
    assert identity.file_name == 'identity_block_cipher_p32_k32_o32_r1.py'
    identity.print_evaluation_python_code_to_file(identity.id + EVALUATION_PY)
    assert os.path.isfile(identity.id + EVALUATION_PY)
    os.remove(identity.id + EVALUATION_PY)


def test_print_input_information():
    fancy = FancyBlockCipher()
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    fancy.print_input_information()
    sys.stdout = old_stdout
    assert result.getvalue() == """plaintext of bit size 24
key of bit size 24
"""


def test_print_as_python_dictionary():
    old_stdout = sys.stdout
    cipher = Cipher("cipher_name", "block_cipher", ["key", "plaintext"], [32, 32], 32)
    cipher.add_round()
    cipher.add_constant_component(16, 0xAB01)
    cipher.add_constant_component(16, 0xAB01)
    result = StringIO()
    sys.stdout = result
    cipher.print_as_python_dictionary()
    sys.stdout = old_stdout
    assert result.getvalue() == """cipher = {
'cipher_id': 'cipher_name_k32_p32_o32_r1',
'cipher_type': 'block_cipher',
'cipher_inputs': ['key', 'plaintext'],
'cipher_inputs_bit_size': [32, 32],
'cipher_output_bit_size': 32,
'cipher_number_of_rounds': 1,
'cipher_rounds' : [
  # round 0
  [
  {
    # round = 0 - round component = 0
    'id': 'constant_0_0',
    'type': 'constant',
    'input_bit_size': 0,
    'input_id_link': [''],
    'input_bit_positions': [[]],
    'output_bit_size': 16,
    'description': ['0xab01'],
  },
  {
    # round = 0 - round component = 1
    'id': 'constant_0_1',
    'type': 'constant',
    'input_bit_size': 0,
    'input_id_link': [''],
    'input_bit_positions': [[]],
    'output_bit_size': 16,
    'description': ['0xab01'],
  },
  ],
  ],
'cipher_reference_code': None,
}
"""

def test_inputs_size_to_dict():
    speck = SpeckBlockCipher(number_of_rounds=1, key_bit_size=64, block_bit_size=32)
    input_sizes = speck.inputs_size_to_dict()
    assert input_sizes['key'] == 64
    assert input_sizes['plaintext'] == 32

def test_vector_check():
    speck = SpeckBlockCipher(number_of_rounds=22)
    key1 = 0x1918111009080100
    plaintext1 = 0x6574694c
    ciphertext1 = 0xa86842f2
    key2 = 0x1918111009080100
    plaintext2 = 0x6574694d
    ciphertext2 = 0x2b5f25d6
    input_list = [[plaintext1, key1], [plaintext2, key2]]
    output_list = [ciphertext1, ciphertext2]
    assert speck.test_vector_check(input_list, output_list) is True

    input_list.append([0x11111111, 0x1111111111111111])
    output_list.append(0xFFFFFFFF)
    assert speck.test_vector_check(input_list, output_list) is False

def test_zero_correlation_linear_search():
    speck6 = SpeckBlockCipher(number_of_rounds=6)
    zero_correlation_linear_approximations = speck6.zero_correlation_linear_search("smt", "yices-smt2")
    assert len(zero_correlation_linear_approximations) > 0
