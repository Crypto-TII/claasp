import copy
import random
from types import ModuleType

import numpy as np
import pytest

from claasp.cipher import Cipher
from claasp.cipher_modules import code_generator
from claasp.cipher_modules.spn_structure import NonlinearLayer, SpnStructure, UnsupportedCipherError
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


def _layer_input(cipher, layer, components_io, inputs):
    """Bits entering the nonlinear layer in the real cipher."""
    values = []
    for link, position in layer.sources:
        if link in cipher.inputs:
            index = cipher.inputs.index(link)
            values.append(_bits(inputs[index], cipher.inputs_bit_size[index])[position])
        elif layer.kind == "sbox":
            component = cipher.component_from_id(link)
            values.append(_bits(components_io[link][0], component.input_bit_size)[position])
        else:
            component = cipher.component_from_id(link)
            values.append(_bits(components_io[link][1], component.output_bit_size)[position])
    return values


def _covers_the_state(layer):
    return sorted(p for positions, _ in layer.sboxes for p in positions) == list(range(layer.size))


@pytest.mark.parametrize("keccak, kind", [(KeccakSboxPermutation, "sbox"), (KeccakPermutation, "chi")])
@pytest.mark.parametrize("word_size", [4, 8])
def test_keccak_layers_are_the_chi_rows_in_both_forms(keccak, kind, word_size):
    layers = SpnStructure(keccak(3, word_size)).layers
    assert [layer.round_number for layer in layers] == [0, 1, 2]
    for layer in layers:
        assert isinstance(layer, NonlinearLayer)
        assert layer.kind == kind
        assert layer.size == 25 * word_size
        assert len(layer.sboxes) == 5 * word_size
        assert {table for _, table in layer.sboxes} == {tuple(SBOX)}
        assert _covers_the_state(layer)


def test_chi_sources_are_the_linear_operands_of_the_chi_xors():
    cipher = KeccakPermutation(2, 4)
    layer = SpnStructure(cipher).layers[0]
    round_0 = {c.id: c for c in cipher.rounds.components_in_round(0)}
    source_types = {round_0[link].description[0] for link, _ in layer.sources}
    assert source_types == {"ROTATE"}  # the lanes B[x, y] after rho and pi, never AND / NOT outputs
    assert len(set(layer.sources)) == layer.size


def test_midori_layers():
    layers = SpnStructure(MidoriBlockCipher()).layers
    assert len(layers) == 16
    assert all(layer.kind == "sbox" and layer.size == 64 and len(layer.sboxes) == 16 for layer in layers)
    assert layers[0].sboxes[0][0] == (0, 1, 2, 3)
    assert all(_covers_the_state(layer) for layer in layers)


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
    assert len(structure.layers) == number_of_layers
    for layer in structure.layers:
        assert layer.size == state_size
        assert sorted(p for positions, _ in layer.sboxes for p in positions) == list(range(state_size))


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


def _real_sbox_layer_output(cipher, layer, components_io):
    links = dict.fromkeys(link for link, _ in layer.sources)
    return [bit for link in links
            for bit in _bits(components_io[link][1], cipher.component_from_id(link).output_bit_size)]


def _apply_sbox_layer(points, sboxes):
    """Image of every row of ``points`` (an (N, n) bit array) by an S-box layer ``((positions, table), ...)``,
    computed independently of CLAASP's components."""
    points = np.asarray(points, dtype=np.uint8)
    image = points.copy()
    for positions, table in sboxes:
        word = np.zeros(points.shape[0], dtype=np.int64)
        for position in positions:
            word = (word << 1) | points[:, position]
        output = np.asarray(table, dtype=np.int64)[word]
        for k, position in enumerate(positions):
            image[:, position] = (output >> (len(positions) - 1 - k)) & 1
    return image


@pytest.mark.parametrize("name", ["midori", "skinny", "keccak_sbox_w4"])
def test_sbox_tables_match_real_cipher(structures, name):
    cipher, structure = structures(name)
    for inputs, components_io in _random_inputs_and_components(cipher, 5):
        for layer in structure.layers:
            s_r = _layer_input(cipher, layer, components_io, inputs)
            image = _apply_sbox_layer(np.array([s_r]), layer.sboxes)[0].tolist()
            assert image == _real_sbox_layer_output(cipher, layer, components_io)


@pytest.mark.parametrize("word_size", [4, 8])
def test_keccak_sbox_and_circuit_forms_agree(word_size):
    sbox_form = SpnStructure(KeccakSboxPermutation(4, word_size))
    circuit_form = SpnStructure(KeccakPermutation(4, word_size))
    for structure, kind in ((sbox_form, "sbox"), (circuit_form, "chi")):
        assert all(layer.kind == kind for layer in structure.layers)
        tables = {table for layer in structure.layers for _, table in layer.sboxes}
        assert tables == {tuple(SBOX)}
        assert all(len(layer.sboxes) == 5 * word_size for layer in structure.layers)


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
    assert len(structure.layers) == cipher.number_of_rounds
    for layer in structure.layers:
        assert {len(positions) for positions, _ in layer.sboxes} == {sbox_bit_size}
        assert len(layer.sboxes) == number_of_sboxes
        assert _covers_the_state(layer)


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


def test_bypassing_a_nonlinear_layer_raises():
    assert len(SpnStructure(_toy_cipher(bypass=False)).layers) == 3
    with pytest.raises(UnsupportedCipherError, match="avoiding the nonlinear layer of round 0"):
        SpnStructure(_toy_cipher(bypass=True))


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
