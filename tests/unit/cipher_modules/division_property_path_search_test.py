import pytest

from claasp.cipher_modules.division_property_path_search import (
    DivisionPropertyPathSearch,
    feistel_division_property_trail,
    spn_division_property_trail,
)
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.des_block_cipher import DESBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.serpent_block_cipher import SerpentBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.twine_block_cipher import TwineBlockCipher
from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation
from claasp.ciphers.toys.toyspn1 import ToySPN1

# Number of rounds -> log2 of the number of chosen plaintexts, from Y. Todo, Structural Evaluation by
# Generalized Integral Property, EUROCRYPT 2015 [Tod2015], https://eprint.iacr.org/2015/090
TODO_SPN_TABLES = {
    "present": ((4, 3, 16), {3: 12, 4: 28, 5: 52, 6: 60}),  # Table 4
    "aes": ((8, 7, 16), {3: 56, 4: 120}),  # Table 4
    "keccak_f1600": ((5, 2, 320), {8: 130, 9: 258, 10: 515, 11: 1025, 12: 1410, 13: 1538, 14: 1580,
                                   15: 1595}),  # Table 5
}
TODO_FEISTEL_TABLES = {
    "des": ((32, 5, False), {3: 6, 4: 26, 5: 51, 6: 62}),  # Tables 2 and 7
    "camellia": ((64, 7, True), {3: 8, 4: 50, 5: 98, 6: 124}),  # Tables 2 and 7, bijective F
    "simon32": ((16, 2, False), {6: 17, 7: 25, 8: 29, 9: 31}),  # Table 3
}


def spn_rounds(sbox_bit_size, sbox_degree, number_of_sboxes, data_bit_size):
    full_sboxes, remaining_bits = divmod(data_bit_size, sbox_bit_size)
    active_bits = [sbox_bit_size] * full_sboxes + [remaining_bits] * (remaining_bits > 0)
    active_bits += [0] * (number_of_sboxes - len(active_bits))
    return len(spn_division_property_trail(sbox_bit_size, sbox_degree, number_of_sboxes, active_bits)) - 1


def feistel_rounds(branch_bit_size, function_degree, bijective_function, data_bit_size):
    active_bits = (max(0, data_bit_size - branch_bit_size), min(data_bit_size, branch_bit_size))
    return len(feistel_division_property_trail(branch_bit_size, function_degree, active_bits, bijective_function)) - 1


def test_spn_division_property_trail():
    trail = spn_division_property_trail(5, 2, 320, [5] * 282 + [0] * 38)
    assert trail == [1410, 1030, 515, 258, 129, 65, 33, 17, 9, 5, 3, 2, 1]  # 12 rounds, [Tod2015] Table 5
    with pytest.raises(ValueError):
        spn_division_property_trail(5, 2, 320, [5, 5])
    with pytest.raises(ValueError):
        spn_division_property_trail(4, 1, 16, [4] + [0] * 15)
    with pytest.raises(ValueError):
        spn_division_property_trail(4, 3, 16, [4] * 16)


@pytest.mark.parametrize("parameters, table", TODO_SPN_TABLES.values(), ids=TODO_SPN_TABLES.keys())
def test_spn_division_property_trail_on_todo_tables(parameters, table):
    for number_of_rounds, data_bit_size in table.items():
        assert spn_rounds(*parameters, data_bit_size) >= number_of_rounds
        assert spn_rounds(*parameters, data_bit_size - 1) < number_of_rounds


def test_feistel_division_property_trail():
    trail = feistel_division_property_trail(4, 3, (4, 0))
    assert trail == [[(2, 0), (1, 1), (0, 4)], [(1, 0), (0, 2)], [(1, 0), (0, 1)]]
    trail = feistel_division_property_trail(4, 3, (4, 0), bijective_function=True)
    assert trail == [[(4, 0), (1, 1), (0, 4)], [(2, 0), (1, 1), (0, 4)], [(1, 0), (0, 2)], [(1, 0), (0, 1)]]
    with pytest.raises(ValueError):
        feistel_division_property_trail(16, 2, (17, 0))
    with pytest.raises(ValueError):
        feistel_division_property_trail(16, 1, (1, 1))
    with pytest.raises(ValueError):
        feistel_division_property_trail(16, 16, (1, 1), bijective_function=True)
    with pytest.raises(ValueError):
        feistel_division_property_trail(16, 2, (16, 16))


@pytest.mark.parametrize("parameters, table", TODO_FEISTEL_TABLES.values(), ids=TODO_FEISTEL_TABLES.keys())
def test_feistel_division_property_trail_on_todo_tables(parameters, table):
    for number_of_rounds, data_bit_size in table.items():
        assert feistel_rounds(*parameters, data_bit_size) >= number_of_rounds
        assert feistel_rounds(*parameters, data_bit_size - 1) < number_of_rounds


@pytest.mark.parametrize("cipher, structure", [
    (AESBlockCipher(number_of_rounds=2), "(8, 7, 16)-SPN"),  # [Tod2015] Section 5.1
    (SerpentBlockCipher(number_of_rounds=2), "(4, 3, 32)-SPN"),  # [Tod2015] Section 5.1
    (SimonBlockCipher(block_bit_size=48, key_bit_size=72, number_of_rounds=4), "(24, 2)-Feistel"),  # Section 4.1
], ids=["aes", "serpent", "simon48"])
def test_structure(cipher, structure):
    assert DivisionPropertyPathSearch(cipher).structure == structure


def test_structure_given_by_the_caller():
    simon = SimonBlockCipher(number_of_rounds=4)
    present = PresentBlockCipher(number_of_rounds=4)
    des = DESBlockCipher(number_of_rounds=4)
    assert DivisionPropertyPathSearch(des, structure="feistel").structure == "(32, 5)-Feistel"
    assert DivisionPropertyPathSearch(present, structure="spn").structure == "(4, 3, 16)-SPN"
    assert DivisionPropertyPathSearch(simon, structure="feistel", bijective_function=True).structure == \
        "(16, 2)-Feistel with bijective round function"

    with pytest.raises(ValueError):
        DivisionPropertyPathSearch(simon, structure="spn")
    with pytest.raises(ValueError):
        DivisionPropertyPathSearch(present, structure="feistel")
    with pytest.raises(ValueError):
        DivisionPropertyPathSearch(present, structure="aes")


def test_unsupported_cipher():
    for cipher in (SpeckBlockCipher(number_of_rounds=4), TwineBlockCipher(number_of_rounds=4),
                   SimonBlockCipher(number_of_rounds=1)):
        with pytest.raises(ValueError):
            DivisionPropertyPathSearch(cipher)


def test_find_division_property_trail():
    aes = DivisionPropertyPathSearch(AESBlockCipher(number_of_rounds=2))
    assert aes.find_division_property_trail([8] * 15 + [0]) == [120, 72, 11, 2, 1]  # [Tod2015] Table 4

    simon = DivisionPropertyPathSearch(SimonBlockCipher(number_of_rounds=4))
    assert simon.find_division_property_trail((15, 16))[0] == [(16, 15)]


def test_find_number_of_balanced_rounds():
    present = DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2))
    assert present.find_number_of_balanced_rounds([4] * 13 + [0] * 3) == 5  # [Tod2015] Table 4
    simon = DivisionPropertyPathSearch(SimonBlockCipher(number_of_rounds=4))
    assert simon.find_number_of_balanced_rounds((15, 16)) == 9  # [Tod2015] Table 3

    with pytest.raises(ValueError):
        present.find_number_of_balanced_rounds([4, 4])
    with pytest.raises(ValueError):
        present.find_number_of_balanced_rounds(present.todo_input(64))


def test_todo_input():
    toy_spn = DivisionPropertyPathSearch(ToySPN1(block_bit_size=9, key_bit_size=9))
    assert toy_spn.todo_input(5) == [3, 2, 0]

    des = DivisionPropertyPathSearch(DESBlockCipher(number_of_rounds=4))
    assert des.todo_input(26) == (0, 26)
    assert des.todo_input(62) == (30, 32)  # 6 rounds, [Tod2015] Table 2
    with pytest.raises(ValueError):
        des.todo_input(65)


def test_optimal_input():
    toy_spn = DivisionPropertyPathSearch(ToySPN1(block_bit_size=9, key_bit_size=9))
    assert toy_spn.optimal_input(5) == [3, 1, 1]

    keccak_f800 = DivisionPropertyPathSearch(KeccakSboxPermutation(number_of_rounds=1, word_size=32))
    assert keccak_f800.find_number_of_balanced_rounds(keccak_f800.todo_input(769)) == 11
    assert keccak_f800.find_number_of_balanced_rounds(keccak_f800.optimal_input(769)) == 12  # 770 in [Tod2015] Table 8

    for path_search in (DivisionPropertyPathSearch(PresentBlockCipher(number_of_rounds=2)),
                        DivisionPropertyPathSearch(SimonBlockCipher(number_of_rounds=4))):
        for data_bit_size in range(path_search.state_bit_size):
            optimal_rounds = path_search.find_number_of_balanced_rounds(path_search.optimal_input(data_bit_size))
            todo_rounds = path_search.find_number_of_balanced_rounds(path_search.todo_input(data_bit_size))
            assert optimal_rounds >= todo_rounds


def test_find_minimum_data_for_rounds():
    for cipher, table in [
        (PresentBlockCipher(number_of_rounds=2), {3: 12, 4: 28, 5: 52, 6: 60}),  # [Tod2015] Table 4
        (AESBlockCipher(number_of_rounds=2), {3: 56, 4: 120}),  # [Tod2015] Table 4
        (KeccakSboxPermutation(number_of_rounds=1), {11: 1025, 13: 1538}),  # [Tod2015] Table 5
        (DESBlockCipher(number_of_rounds=4), {4: 26, 5: 51, 6: 62}),  # [Tod2015] Table 2
        (SimonBlockCipher(number_of_rounds=4), {6: 17, 7: 25, 8: 29, 9: 31}),  # [Tod2015] Table 3
    ]:
        path_search = DivisionPropertyPathSearch(cipher)
        for number_of_rounds, data_bit_size in table.items():
            assert path_search.find_minimum_data_for_rounds(number_of_rounds)["data_bit_size"] == data_bit_size

    keccak = DivisionPropertyPathSearch(KeccakSboxPermutation(number_of_rounds=1))
    assert keccak.find_minimum_data_for_rounds(13, input_pattern="optimal")["data_bit_size"] == 1537
    with pytest.raises(ValueError):
        keccak.find_minimum_data_for_rounds(13, input_pattern="unknown")


def test_find_integral_distinguishers():
    cipher = PresentBlockCipher(number_of_rounds=2)
    result = DivisionPropertyPathSearch(cipher).find_integral_distinguishers(max_number_of_rounds=6)
    assert result["input_parameters"] == {"cipher": cipher, "test_name": "division_property_path_search",
                                          "structure": "(4, 3, 16)-SPN", "input_pattern": "todo",
                                          "max_number_of_rounds": 6}
    data = {rounds: entry["data_bit_size"] for rounds, entry in result["test_results"].items()}
    assert data == {1: 4, 2: 4, 3: 12, 4: 28, 5: 52, 6: 60}  # rounds 3 to 6: [Tod2015] Table 4
