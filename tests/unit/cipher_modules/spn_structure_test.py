import copy
import random
from types import ModuleType

import numpy as np
import pytest
from sage.matrix.constructor import matrix
from sage.matrix.special import identity_matrix
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher import Cipher
from claasp.cipher_modules import code_generator
from claasp.cipher_modules.spn_structure import Sbox, SpnStructure, SubstitutionLayer, UnsupportedCipherError
from claasp.ciphers.block_ciphers.aes_block_cipher import AESBlockCipher
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
from claasp.ciphers.block_ciphers.serpent_block_cipher import SerpentBlockCipher
from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
from claasp.ciphers.block_ciphers.ublock_block_cipher import UblockBlockCipher
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.ciphers.permutations.keccak_sbox_permutation import SBOX, KeccakSboxPermutation

F = GF(2)
CIPHERS = {
    "midori": lambda: MidoriBlockCipher(64, 128),
    "skinny": lambda: SkinnyBlockCipher(64, 64, 32),
    "keccak_sbox_w4": lambda: KeccakSboxPermutation(16, 4),
    "keccak_circuit_w4": lambda: KeccakPermutation(16, 4),
}
EXPECTED_SIZES = {
    # (state_size, key_size, number of layers)
    "midori": (64, 128, 16),
    "skinny": (64, 64, 32),
    "keccak_sbox_w4": (100, 0, 16),
    "keccak_circuit_w4": (100, 0, 16),
}


@pytest.fixture(scope="module")
def structures():
    cache = {}

    def get(name):
        if name not in cache:
            cipher = CIPHERS[name]()
            cache[name] = (cipher, SpnStructure(cipher))
        return cache[name]

    return get


def _bits(value, size):
    return [(value >> (size - 1 - i)) & 1 for i in range(size)]


def _bit_values(cipher, bits, components_io, inputs):
    """Values in the real cipher of the bits ``(component_id or input, bit)``."""
    values = []
    for link, position in bits:
        if link in cipher.inputs:
            index = cipher.inputs.index(link)
            values.append(_bits(inputs[index], cipher.inputs_bit_size[index])[position])
        else:
            component = cipher.component_from_id(link)
            values.append(_bits(components_io[link][1], component.output_bit_size)[position])
    return values


def _output_bits(cipher):
    output = next(c for c in cipher.all_components() if c.type == "cipher_output")
    return [(output.id, bit) for bit in range(output.output_bit_size)]


def _covers_the_state(layer):
    return sorted(p for sbox in layer.sboxes for p in sbox.positions) == list(range(layer.size))


@pytest.mark.parametrize("keccak, kind", [(KeccakSboxPermutation, "sbox"), (KeccakPermutation, "chi")])
@pytest.mark.parametrize("word_size", [4, 8])
def test_keccak_layers_are_the_chi_rows_in_both_forms(keccak, kind, word_size):
    layers = SpnStructure(keccak(3, word_size)).substitution_layers
    assert [layer.round_number for layer in layers] == [0, 1, 2]
    for layer in layers:
        assert isinstance(layer, SubstitutionLayer)
        assert layer.kind == kind
        assert layer.size == 25 * word_size
        assert len(layer.sboxes) == 5 * word_size
        assert {sbox.table for sbox in layer.sboxes} == {tuple(SBOX)}
        assert _covers_the_state(layer)


def test_chi_layer_bits():
    cipher = KeccakPermutation(2, 4)
    layer = SpnStructure(cipher).substitution_layers[0]
    round_0 = {c.id: c for c in cipher.rounds.components_in_round(0)}
    # the inputs are the lanes B[x, y] after rho and pi, never AND / NOT outputs; the outputs are the chi XORs
    assert {round_0[link].description[0] for link, _ in layer.input_bits} == {"ROTATE"}
    assert {round_0[link].description[0] for link, _ in layer.output_bits} == {"XOR"}
    assert len(set(layer.input_bits)) == len(set(layer.output_bits)) == layer.size


def test_midori_layers():
    layers = SpnStructure(MidoriBlockCipher()).substitution_layers
    assert len(layers) == 16
    assert all(layer.kind == "sbox" and layer.size == 64 and len(layer.sboxes) == 16 for layer in layers)
    assert isinstance(layers[0].sboxes[0], Sbox)
    assert layers[0].sboxes[0].positions == (0, 1, 2, 3)
    assert all(_covers_the_state(layer) for layer in layers)


def test_summaries():
    structure = SpnStructure(KeccakPermutation(2, 4))
    assert repr(structure) == "SpnStructure(keccak_p100_o100_r2, 2 layers of 20 5-bit S-boxes, state plaintext, no key)"
    # a chi row reads bit 0 of five lanes and writes bit 0 of five chi XORs
    assert repr(structure.substitution_layers[0].sboxes[0]) == (
        "Sbox(positions=(0, 20, 40, 60, 80), input=rot_0_40[0], rot_0_46[0], rot_0_52[0], rot_0_58[0], rot_0_64[0], "
        "output=xor_0_68[0], xor_0_83[0], xor_0_98[0], xor_0_113[0], xor_0_128[0], "
        "table=(0, 5, 10, 11, 20, 17, 22, 23, ...))")


def test_unsupported_components_raise():
    with pytest.raises(UnsupportedCipherError, match="MODADD"):
        SpnStructure(SpeckBlockCipher(number_of_rounds=2))


def test_and_outside_a_chi_layer_raises():
    with pytest.raises(UnsupportedCipherError):
        SpnStructure(SimonBlockCipher(number_of_rounds=3))


@pytest.mark.parametrize("name", list(CIPHERS))
def test_structure_sizes(structures, name):
    _, structure = structures(name)
    state_size, key_size, number_of_layers = EXPECTED_SIZES[name]
    assert structure.state_size == state_size
    assert structure.key_size == key_size
    assert len(structure.substitution_layers) == number_of_layers
    for layer in structure.substitution_layers:
        assert layer.size == state_size
        assert sorted(p for sbox in layer.sboxes for p in sbox.positions) == list(range(state_size))
    assert len(structure.linear_layers) == number_of_layers
    for linear in structure.linear_layers:
        assert linear.dimensions() == (state_size, state_size)
        assert linear.is_immutable() and linear.is_invertible()


def _compiled_evaluation(cipher):
    """The scalar evaluation function of ``cipher`` (returning components_io), compiled once."""
    module = ModuleType("evaluate")
    exec(code_generator.generate_python_code_string(copy.deepcopy(cipher)), module.__dict__)
    return module.evaluate


def _random_inputs_and_components(cipher, number_of_samples):
    evaluate = _compiled_evaluation(cipher)
    rng = random.Random(2026)
    for _ in range(number_of_samples):
        inputs = [rng.getrandbits(size) for size in cipher.inputs_bit_size]
        yield inputs, evaluate(inputs)[2]


def _apply_sbox_layer(points, sboxes):
    """Image of every row of ``points`` (an (N, n) bit array) by an S-box layer ``((positions, table), ...)``,
    computed independently of CLAASP's components."""
    points = np.asarray(points, dtype=np.uint8)
    image = points.copy()
    for positions, table in (sbox[:2] for sbox in sboxes):  # an Sbox, or a (positions, table) pair
        word = np.zeros(points.shape[0], dtype=np.int64)
        for position in positions:
            word = (word << 1) | points[:, position]
        output = np.asarray(table, dtype=np.int64)[word]
        for k, position in enumerate(positions):
            image[:, position] = (output >> (len(positions) - 1 - k)) & 1
    return image


@pytest.mark.parametrize("name", ["midori", "skinny", "keccak_sbox_w4", "keccak_circuit_w4"])
def test_sbox_tables_match_real_cipher(structures, name):
    cipher, structure = structures(name)
    for inputs, components_io in _random_inputs_and_components(cipher, 5):
        for layer in structure.substitution_layers:
            s_r = _bit_values(cipher, layer.input_bits, components_io, inputs)
            image = _apply_sbox_layer(np.array([s_r]), layer.sboxes)[0].tolist()
            assert image == _bit_values(cipher, layer.output_bits, components_io, inputs)


@pytest.mark.parametrize("build", [
    lambda: MidoriBlockCipher(number_of_rounds=4),
    lambda: KeccakPermutation(4, 4),
    lambda: AESBlockCipher(number_of_rounds=3),
    lambda: PresentBlockCipher(number_of_rounds=4),
], ids=["midori", "keccak_circuit", "aes", "present"])
def test_linear_layers_on_real_cipher(build):
    # two inputs differing only in the state: the key and constant additions cancel in the difference, so L_r must
    # map the difference of the S-box outputs to the difference of the next layer's inputs (or of the outputs),
    # whatever the key schedule
    cipher = build()
    structure = SpnStructure(cipher)
    layers = structure.substitution_layers
    evaluate = _compiled_evaluation(cipher)
    state_index = cipher.inputs.index(structure.state_input)
    rng = random.Random(3)
    for _ in range(10):
        inputs = [rng.getrandbits(size) for size in cipher.inputs_bit_size]
        other = list(inputs)
        other[state_index] = rng.getrandbits(structure.state_size)
        states = []
        for values in (inputs, other):
            components_io = evaluate(values)[2]
            states.append([_bit_values(cipher, bits, components_io, values)
                           for bits in [layer.input_bits for layer in layers] + [_output_bits(cipher)]])
        assert len(structure.linear_layers) == len(layers)
        for r, linear in enumerate(structure.linear_layers):
            images = [_apply_sbox_layer(np.array([state[r]]), layers[r].sboxes)[0].tolist() for state in states]
            difference = vector(F, images[0]) + vector(F, images[1])
            assert linear * difference == vector(F, states[0][r + 1]) + vector(F, states[1][r + 1])


@pytest.mark.parametrize("word_size", [4, 8])
def test_keccak_sbox_and_circuit_forms_agree(word_size):
    sbox_form = SpnStructure(KeccakSboxPermutation(4, word_size))
    circuit_form = SpnStructure(KeccakPermutation(4, word_size))
    assert sbox_form.linear_layers[0].charpoly() == circuit_form.linear_layers[0].charpoly()
    for structure, kind in ((sbox_form, "sbox"), (circuit_form, "chi")):
        assert all(layer.kind == kind for layer in structure.substitution_layers)
        tables = {sbox.table for layer in structure.substitution_layers for sbox in layer.sboxes}
        assert tables == {tuple(SBOX)}
        assert all(len(layer.sboxes) == 5 * word_size for layer in structure.substitution_layers)


@pytest.mark.parametrize("build, sbox_bit_size, number_of_sboxes", [
    (lambda: AESBlockCipher(number_of_rounds=2), 8, 16),
    (lambda: PresentBlockCipher(number_of_rounds=2), 4, 16),
    (lambda: SerpentBlockCipher(number_of_rounds=2), 4, 32),
    (lambda: UblockBlockCipher(128, 128, number_of_rounds=2), 4, 32),
], ids=["aes", "present", "serpent", "ublock"])
def test_key_schedule_sboxes_are_not_part_of_the_layers(build, sbox_bit_size, number_of_sboxes):
    cipher = build()  # AES and Serpent take the key as their first input
    structure = SpnStructure(cipher)
    assert structure.state_input == "plaintext"
    assert len(structure.substitution_layers) == cipher.number_of_rounds
    for layer in structure.substitution_layers:
        assert {len(sbox.positions) for sbox in layer.sboxes} == {sbox_bit_size}
        assert len(layer.sboxes) == number_of_sboxes
        assert _covers_the_state(layer)


def _is_permutation_matrix(linear):
    return all(row.hamming_weight() == 1 for row in linear.rows()) and linear.is_invertible()


def test_last_linear_layer_goes_to_the_output():
    # Keccak ends with chi then iota: the last linear layer only puts the chi rows back in lane order
    structure = SpnStructure(KeccakPermutation(1, 4))
    assert len(structure.substitution_layers) == len(structure.linear_layers) == 1
    assert _is_permutation_matrix(structure.linear_layers[0])
    # the last round of AES has no MixColumns: its linear layer is ShiftRows alone
    middle, last = SpnStructure(AESBlockCipher(number_of_rounds=3)).linear_layers[1:]
    assert not _is_permutation_matrix(middle) and _is_permutation_matrix(last)


PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]


def _toy_cipher(bypass):
    """4-bit rounds x -> S(x) + c_r, plus bit 1 of x XORed into bit 0 when ``bypass`` (a path avoiding the S-box)."""
    cipher = Cipher("toy", "permutation", ["plaintext"], [4], 4)
    state = "plaintext"
    for constant in (0x1, 0x3, 0x7):
        cipher.add_round()
        sbox = cipher.add_sbox_component([state], [[0, 1, 2, 3]], 4, PRESENT_SBOX)
        links, positions = [sbox.id, cipher.add_constant_component(4, constant).id], [[0, 1, 2, 3], [0, 1, 2, 3]]
        if bypass:
            links += [state, cipher.add_constant_component(3, 0).id]
            positions += [[1], [0, 1, 2]]
        state = cipher.add_xor_component(links, positions, 4).id
    cipher.add_cipher_output_component([state], [[0, 1, 2, 3]], 4)
    return cipher


def test_bypassing_a_substitution_layer_raises():
    assert len(SpnStructure(_toy_cipher(bypass=False)).substitution_layers) == 3
    with pytest.raises(UnsupportedCipherError, match="avoiding the substitution layer of round 0"):
        SpnStructure(_toy_cipher(bypass=True))


def test_bypassing_the_last_substitution_layer_raises():
    # y = S(x) + x: with S the identity the output would be 0, so the last linear layer would be wrong
    cipher = Cipher("toy", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    sbox = cipher.add_sbox_component(["plaintext"], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    xor = cipher.add_xor_component([sbox, "plaintext"], [[0, 1, 2, 3], [0, 1, 2, 3]], 4).id
    cipher.add_cipher_output_component([xor], [[0, 1, 2, 3]], 4)
    with pytest.raises(UnsupportedCipherError, match="the cipher output depends on the state"):
        SpnStructure(cipher)


def test_reading_a_missing_bit_raises():
    # a malformed definition: the S-box reads bit 4 of a 4-bit input
    cipher = Cipher("toy", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    sbox = cipher.add_sbox_component(["plaintext"], [[1, 2, 3, 4]], 4, PRESENT_SBOX).id
    cipher.add_cipher_output_component([sbox], [[0, 1, 2, 3]], 4)
    with pytest.raises(UnsupportedCipherError, match="reads bit 4 of plaintext, which has 4 bits"):
        SpnStructure(cipher)


def test_sequential_sboxes_in_one_layer_raise():
    # A = S(x_hi), B = S(A + x_lo): B reads A's output, so the round's S-boxes are not one parallel layer
    cipher = Cipher("toy", "permutation", ["plaintext"], [8], 8)
    state = "plaintext"
    for constant in (0x1B, 0x36, 0x6C):
        cipher.add_round()
        a = cipher.add_sbox_component([state], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
        mix = cipher.add_xor_component([a, state], [[0, 1, 2, 3], [4, 5, 6, 7]], 4).id
        b = cipher.add_sbox_component([mix], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
        c = cipher.add_constant_component(8, constant).id
        state = cipher.add_xor_component([a, b, c], [[0, 1, 2, 3], [0, 1, 2, 3], list(range(8))], 8).id
    cipher.add_cipher_output_component([state], [list(range(8))], 8)
    with pytest.raises(UnsupportedCipherError, match="not applied in parallel"):
        SpnStructure(cipher)


def test_layer_input_not_depending_on_the_state_raises():
    # one S-box of every layer reads only a constant: like the key schedule, it is not part of the layer, which then
    # covers 4 of the 8 state bits
    cipher = Cipher("toy", "permutation", ["plaintext"], [8], 8)
    state = "plaintext"
    for constant in (0x1B, 0x36):
        cipher.add_round()
        a = cipher.add_sbox_component([state], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
        b = cipher.add_sbox_component([cipher.add_constant_component(4, 5).id], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
        c = cipher.add_constant_component(8, constant).id
        state = cipher.add_xor_component([a, b, c], [[0, 1, 2, 3], [0, 1, 2, 3], list(range(8))], 8).id
    cipher.add_cipher_output_component([state], [list(range(8))], 8)
    with pytest.raises(UnsupportedCipherError, match="cover 4 bits"):
        SpnStructure(cipher)


def test_changes_to_the_cipher_after_construction_are_not_seen():
    cipher = MidoriBlockCipher(number_of_rounds=4)
    structure = SpnStructure(cipher)
    sbox = next(c for c in cipher.all_components() if c.type == "sbox")
    sbox.input_id_links, sbox.input_bit_positions = ["plaintext"], [[0, 1, 2, 3]]  # rewired after validation
    assert structure.linear_layers == SpnStructure(MidoriBlockCipher(number_of_rounds=4)).linear_layers


def test_state_reading_a_bit_twice():
    # the first S-box reads state bit 0 twice: the state does not reach the first layer bijectively, but the linear
    # layers only depend on what lies between the layers
    cipher = Cipher("toy", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    a = cipher.add_sbox_component(["plaintext"], [[0, 0, 2, 3]], 4, PRESENT_SBOX).id
    cipher.add_round()
    b = cipher.add_sbox_component([a], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    cipher.add_cipher_output_component([b], [[0, 1, 2, 3]], 4)
    assert SpnStructure(cipher).linear_layers == (identity_matrix(F, 4), identity_matrix(F, 4))


def test_singular_linear_layer():
    # between the two layers bit 0 is copied onto bit 1: the linear layer is not invertible, and is returned as is
    cipher = Cipher("toy", "permutation", ["plaintext"], [4], 4)
    cipher.add_round()
    a = cipher.add_sbox_component(["plaintext"], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    mid = cipher.add_xor_component([a, cipher.add_constant_component(4, 3).id], [[0, 0, 2, 3], [0, 1, 2, 3]], 4).id
    cipher.add_round()
    b = cipher.add_sbox_component([mid], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    cipher.add_cipher_output_component([b], [[0, 1, 2, 3]], 4)
    assert SpnStructure(cipher).linear_layers[0] == matrix(F, [[1, 0, 0, 0], [1, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]])


def test_layer_inputs_prepared_after_some_of_its_sboxes():
    # S-box B's input is prepared after S-box A of the same layer: the components are in a valid order, and the layer
    # inputs must be read once the whole walk is done
    cipher = Cipher("toy", "permutation", ["plaintext"], [8], 8)
    cipher.add_round()
    first = cipher.add_sbox_component(["plaintext"], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    second = cipher.add_sbox_component(["plaintext"], [[4, 5, 6, 7]], 4, PRESENT_SBOX).id
    cipher.add_round()
    a = cipher.add_sbox_component([first], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    prepared = cipher.add_xor_component([second, cipher.add_constant_component(4, 5).id],
                                        [[0, 1, 2, 3], [0, 1, 2, 3]], 4).id
    b = cipher.add_sbox_component([prepared], [[0, 1, 2, 3]], 4, PRESENT_SBOX).id
    cipher.add_cipher_output_component([a, b], [[0, 1, 2, 3], [0, 1, 2, 3]], 8)
    assert SpnStructure(cipher).linear_layers == (identity_matrix(F, 8), identity_matrix(F, 8))
