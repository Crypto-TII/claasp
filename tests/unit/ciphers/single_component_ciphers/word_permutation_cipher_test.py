from claasp.ciphers.single_component_ciphers.word_permutation_cipher import WordPermutationCipher
from claasp.cipher_modules.models.sat.sat_models.sat_xor_differential_model import SatXorDifferentialModel


def test_word_permutation_cipher_smoke():
    cipher = WordPermutationCipher(word_size=2, number_of_words=2, permutation_description=[1, 0])
    out = cipher.evaluate([0b1010])
    assert cipher.type == "permutation"
    assert isinstance(out, int)


def test_word_permutation_cipher_default_description_rotates_words():
    cipher = WordPermutationCipher(word_size=2, number_of_words=4)

    assert cipher.evaluate([0b00_01_10_11]) == 0b01_10_11_00


def test_word_permutation_cipher_sat_xor_differential_trail_search_matches_evaluate():
    # End-to-end spot check: build and solve a real SAT XOR-differential-trail model over
    # WordPermutationCipher (exercising the constraint-generation path inherited from
    # Permutation, not just the component in isolation), and confirm the solved
    # plaintext/ciphertext pair agrees with numeric evaluate(). A permutation has no
    # probability loss, so the lowest-weight trail must have total_weight 0.
    cipher = WordPermutationCipher(word_size=4, number_of_words=4, permutation_description=[1, 2, 3, 0])
    sat = SatXorDifferentialModel(cipher)
    trail = sat.find_lowest_weight_xor_differential_trail()

    assert trail["status"] == "SATISFIABLE"
    assert trail["total_weight"] == 0.0

    cipher_output_id = cipher.get_all_components_ids()[-1]
    plaintext = int(trail["components_values"]["plaintext"]["value"], 16)
    ciphertext = int(trail["components_values"][cipher_output_id]["value"], 16)

    assert cipher.evaluate([plaintext]) == ciphertext
