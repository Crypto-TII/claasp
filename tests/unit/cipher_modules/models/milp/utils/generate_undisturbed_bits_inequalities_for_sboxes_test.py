from sage.crypto.sbox import SBox
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.cipher_modules.models.milp.utils.generate_undisturbed_bits_inequalities_for_sboxes import *
def test_update_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits():
    delete_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits()
    dict = get_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits()
    assert dict == {}

    present = PresentBlockCipher(number_of_rounds=1)
    sbox_component = present.component_from(0, 1)
    valid_points = sbox_component.get_ddt_with_undisturbed_transitions()
    undisturbed_points = [i for i in valid_points if i[1]!= (2,2,2,2)]
    assert len(valid_points) == 81
    assert undisturbed_points == [((0, 0, 0, 0), (0, 0, 0, 0)), ((0, 0, 0, 1), (2, 2, 2, 1)), ((1, 0, 0, 0), (2, 2, 2, 1)), ((1, 0, 0, 1), (2, 2, 2, 0))]

    sbox = SBox(sbox_component.description)
    update_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits(sbox, valid_points)
    dict = get_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits()
    assert dict[str(sbox)][0][1] == ['------11-', '----11---', '--11-----', '11-------', '--------1']

