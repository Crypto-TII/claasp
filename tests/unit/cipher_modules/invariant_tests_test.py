"""
Tests of the round-constant invariant test, of the invariant closure W_L(D) and of the S-box coset check (Algorithm
1). They include the values given in [BCLR2017]_ for Midori-64 and Skinny-64-64, and the lane bound of the Keccak
linear layer, written from the specification rather than taken from CLAASP's implementation.
"""
import random
from types import SimpleNamespace

import numpy as np
import pytest
from sage.matrix.constructor import matrix
from sage.modules.free_module import VectorSpace
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF
from sage.rings.integer import Integer

from claasp.cipher import Cipher
from claasp.cipher_modules import invariant_tests
from claasp.cipher_modules.invariant_tests import (
    NOT_PROVEN,
    PROVEN_COSET_CHECK,
    PROVEN_DIMENSION_CRITERION,
    InvariantTests,
    _all_invariants_constant,
    _has_linear_invariant,
    _linear_invariant_in_every_layer,
    _CosetMap,
    _enumerate,
    _invariant_closure,
    _round_constant_closure,
    _uniform_points,
)
from claasp.cipher_modules.spn_structure import SpnStructure, UnsupportedCipherError
from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
from claasp.ciphers.permutations.keccak_permutation import KeccakPermutation
from claasp.ciphers.permutations.keccak_sbox_permutation import KeccakSboxPermutation

F = GF(2)
PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
IDENTITY_SBOX = list(range(16))

# Linear layer of Keccak-f[25 w] from its specification, independent of CLAASP's KeccakPermutation and of
# SpnStructure. State index: (5 y + x) w + z; L = pi o rho o theta.
# fmt: off
KECCAK_ROTATIONS = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
                    [27, 20, 39, 8, 14]]
# fmt: on
LANES = [(x, y) for x in range(5) for y in range(5)]


def _index(x, y, z, w):
    return (5 * y + x) * w + z


def _theta(a, w):
    column = [[sum(a[_index(x, y, z, w)] for y in range(5)) % 2 for z in range(w)] for x in range(5)]
    b = list(a)
    for x, y in LANES:
        for z in range(w):
            b[_index(x, y, z, w)] ^= column[(x - 1) % 5][z] ^ column[(x + 1) % 5][(z - 1) % w]
    return b


def _rho_pi(a, w):
    b = [0] * len(a)
    for x, y in LANES:
        for z in range(w):
            b[_index(y, (2 * x + 3 * y) % 5, (z + KECCAK_ROTATIONS[x][y]) % w, w)] = a[_index(x, y, z, w)]
    return b


def _keccak_linear_layer_from_spec(w):
    n = 25 * w
    columns = [_rho_pi(_theta([int(j == i) for j in range(n)], w), w) for i in range(n)]
    return matrix(F, columns).transpose()


def unit_space(n, positions):
    ambient = VectorSpace(F, n)
    return ambient.subspace([ambient.gen(i) for i in positions])


def random_sboxes(rng, n, sizes):
    positions = rng.permutation(n).tolist()
    sboxes = []
    for size in sizes:
        sboxes.append((tuple(positions[:size]), tuple(rng.integers(0, 2**size, 2**size).tolist())))
        positions = positions[size:]
    return tuple(sboxes)


def _results(cipher):
    return InvariantTests(cipher).round_constants_invariant_test()["test_results"]


# round_constants_invariant_test


def test_midori_64_matches_bclr17():
    results = _results(MidoriBlockCipher(64, 128))
    assert results["closure_dimension"] == 16
    assert len(results["closure_dimension_per_transition"]) == 13  # 15 transitions, 2 distinct key contributions
    assert results["linear_invariant_in_every_layer"] is False
    assert results["verdict"] == NOT_PROVEN


def test_skinny_64_64_matches_bclr17():
    results = _results(SkinnyBlockCipher(64, 64, 32))
    assert results["closure_dimension"] == 64
    assert len(results["closure_dimension_per_transition"]) == 15  # 31 transitions, 16 distinct key contributions
    assert results["closure_dimension_per_transition"][4] == [(20, 21), 64]
    assert results["verdict"] == PROVEN_DIMENSION_CRITERION
    assert results["coset_check"] is None


@pytest.mark.parametrize("keccak", [KeccakSboxPermutation, KeccakPermutation])
def test_keccak_f_100_is_proven_by_the_coset_check_in_both_forms(keccak):
    results = _results(keccak(16, 4))
    assert results["closure_dimension"] == 82
    assert results["coset_check"]["codimension"] == 20
    assert results["coset_check"]["status"] == "proven"
    assert results["verdict"] == PROVEN_COSET_CHECK


def test_keccak_without_round_constants_is_not_proven():
    cipher = KeccakSboxPermutation(16, 4)
    for component in cipher.all_components():
        if component.type == "constant":
            component.description = ["0x0"]
    results = _results(cipher)
    assert results["closure_dimension_per_transition"]  # the differences exist, and are all zero
    assert all(dimension == 0 for _, dimension in results["closure_dimension_per_transition"])
    assert results["closure_dimension"] == 0
    assert results["verdict"] == NOT_PROVEN


def test_result_format():
    result = InvariantTests(SkinnyBlockCipher(64, 64, 32)).round_constants_invariant_test(seed=3)
    assert list(result) == ["input_parameters", "test_results"]
    assert list(result["input_parameters"]) == ["cipher", "test_name", "max_codimension", "max_samples_factor",
                                                "exhaustive_limit", "seed"]
    assert result["input_parameters"]["test_name"] == "round_constants_invariant_test"
    assert result["input_parameters"]["seed"] == 3
    assert list(result["test_results"]) == ["verdict", "closure_dimension", "state_size",
                                            "linear_invariant_in_every_layer", "coset_check",
                                            "closure_dimension_per_transition", "transitions_skipped"]


def _toy_spn(tables, linear_positions, constants):
    """
    Rounds x -> L_r S_r(x) + c_r; S_r is made of 4-bit S-boxes with table tables[r], or is absent when tables[r] is
    None. L_r reads the bits linear_positions, or linear_positions[r] when it is a list per round (a repeated
    position makes L_r singular).
    """
    per_round = linear_positions if isinstance(linear_positions[0], list) else [linear_positions] * len(tables)
    n = len(per_round[0])
    cipher = Cipher("toy", "permutation", ["plaintext"], [n], n)
    state = "plaintext"
    for table, constant, read in zip(tables, constants, per_round):
        cipher.add_round()
        if table is None:
            links, positions = [state], [list(read)]
        else:
            sboxes = [cipher.add_sbox_component([state], [list(range(4 * j, 4 * j + 4))], 4, table).id
                      for j in range(n // 4)]
            links, positions = [sboxes[p // 4] for p in read], [[p % 4] for p in read]
        constant_id = cipher.add_constant_component(n, constant).id
        state = cipher.add_xor_component(links + [constant_id], positions + [list(range(n))], n).id
    cipher.add_cipher_output_component([state], [list(range(n))], n)
    return cipher


@pytest.mark.parametrize("first_table, linear_invariant_everywhere, verdict", [
    (PRESENT_SBOX, False, PROVEN_DIMENSION_CRITERION),
    (IDENTITY_SBOX, True, NOT_PROVEN),
])
def test_proposition_2_needs_one_layer_without_linear_invariant(first_table, linear_invariant_everywhere, verdict):
    # dim W_L(D) = n - 1 in both cases: an invariant must hold for every layer, so the PRESENT layer alone excludes
    # g(x) = a.x + c, while with identity S-boxes only, every a.x is an invariant and Prop. 2 cannot apply
    cipher = _toy_spn([first_table] + [IDENTITY_SBOX] * 4, [0, 1, 2, 3], [0x1, 0x3, 0x7, 0xE, 0xC])
    results = _results(cipher)
    assert results["closure_dimension"] == 3
    assert results["linear_invariant_in_every_layer"] is linear_invariant_everywhere
    assert results["verdict"] == verdict


def test_coset_check_succeeds_on_any_layer():
    # 12-bit rotation, W_L(D) of dimension 10: the identity layer of round 0 cannot prove it, the PRESENT one can
    rotation = [(i - 1) % 12 for i in range(12)]
    cipher = _toy_spn([IDENTITY_SBOX, PRESENT_SBOX, PRESENT_SBOX], rotation, [0x001, 0x631, 0x5A5])
    results = _results(cipher)
    assert results["closure_dimension"] == 10
    assert list(results["coset_check"]) == ["status", "codimension", "cosets_hit", "samples", "round"]
    assert (results["coset_check"]["status"], results["coset_check"]["round"]) == ("proven", 1)
    assert results["verdict"] == PROVEN_COSET_CHECK


def test_coset_check_status_tells_whether_a_larger_budget_can_help():
    # identity S-boxes meet one coset of Z only: once all of Z is enumerated, no budget can help; without any budget,
    # nothing is evaluated and a larger budget may help
    rotation = [(i - 1) % 12 for i in range(12)]
    tests = InvariantTests(_toy_spn([IDENTITY_SBOX] * 3, rotation, [0x001, 0x631, 0x5A5]))
    check = tests.round_constants_invariant_test()["test_results"]["coset_check"]
    assert (check["status"], check["codimension"], check["cosets_hit"], check["round"]) == ("not_proven", 3, 1, 0)
    check = tests.round_constants_invariant_test(max_samples_factor=0, exhaustive_limit=0)["test_results"]
    check = check["coset_check"]
    assert (check["status"], check["cosets_hit"], check["samples"], check["round"]) == ("incomplete", None, 0, None)


def _times_alpha(x):
    """Multiplication by a root of x^4 + x + 1 in GF(16): a linear S-box with no eigenvalue 1."""
    return ((x << 1) ^ (0b10011 if x & 0b1000 else 0)) & 0b1111


@pytest.mark.parametrize("table, expected", [
    (IDENTITY_SBOX, True),  # every a.x is an invariant
    ([x ^ 1 for x in range(16)], True),  # a.(S(x) + x) = a.1 is constant for every a
    (PRESENT_SBOX, False),
    ([0] * 16, False),  # constant components: a.(S(x) + x) = a.x is not constant
    ([_times_alpha(x) for x in range(16)], False),  # only linear components, yet no linear invariant
])
def test_linear_invariant_of_an_sbox(table, expected):
    assert _has_linear_invariant(tuple(table), 4) is expected


def test_one_layer_without_linear_invariant_is_enough():
    def layer(table):
        return SimpleNamespace(sboxes=[SimpleNamespace(positions=(0, 1, 2, 3), table=tuple(table))])
    assert _linear_invariant_in_every_layer([layer(IDENTITY_SBOX)]) is True
    assert _linear_invariant_in_every_layer([layer(PRESENT_SBOX), layer(IDENTITY_SBOX)]) is False
    # within a layer, one S-box with a linear invariant is enough: a.x on its bits is kept by the whole layer
    mixed = SimpleNamespace(sboxes=[SimpleNamespace(positions=(0, 1, 2, 3), table=tuple(PRESENT_SBOX)),
                                    SimpleNamespace(positions=(4, 5, 6, 7), table=tuple(IDENTITY_SBOX))])
    assert _linear_invariant_in_every_layer([mixed]) is True


def test_skipped_check_is_reported_with_no_layer():
    # the skip depends only on Z (codimension 3 here), not on the S-box layer, so no layer is reported
    rotation = [(i - 1) % 12 for i in range(12)]
    cipher = _toy_spn([IDENTITY_SBOX, PRESENT_SBOX, PRESENT_SBOX], rotation, [0x001, 0x631, 0x5A5])
    check = InvariantTests(cipher).round_constants_invariant_test(max_codimension=1)["test_results"]["coset_check"]
    assert (check["status"], check["cosets_hit"], check["samples"], check["round"]) == ("skipped", None, 0, None)


def test_transitions_are_identified_by_round_numbers():
    # substitution layers in rounds 0, 2 and 4: the affine parts go from round 0 to 2 and from 2 to 4
    cipher = _toy_spn([PRESENT_SBOX, None, PRESENT_SBOX, None, PRESENT_SBOX], [0, 1, 2, 3], [0x1, 0x3, 0x7, 0xE, 0xC])
    results = _results(cipher)
    assert results["transitions_skipped"] == []
    assert [transition for transition, _ in results["closure_dimension_per_transition"]] == [(2, 4)]


def test_transitions_with_another_linear_layer_are_skipped():
    # the transition (1, 2) rotates the bits, the others do not: only the most common L, and its constants, are used
    identity, rotation = [0, 1, 2, 3], [1, 2, 3, 0]
    cipher = _toy_spn([PRESENT_SBOX] * 4, [identity, rotation, identity, identity], [0x1, 0x3, 0x7, 0xE])
    results = _results(cipher)
    assert results["transitions_skipped"] == [(1, 2)]
    assert results["closure_dimension_per_transition"] == [[(2, 3), 1]]  # c_2 + c_0 = 0x6 only; c_1 is not used


def test_singular_linear_layer_raises():
    # bit 0 copied to bit 1: L has rank 3, so the constant differences are not linear structures of an invariant
    tests = InvariantTests(_toy_spn([PRESENT_SBOX] * 3, [0, 0, 2, 3], [0x1, 0x3, 0x7]))
    with pytest.raises(UnsupportedCipherError, match="rank 3 < 4"):
        tests.round_constants_invariant_test()


@pytest.mark.parametrize("parameter, value", [("max_samples_factor", -1), ("max_samples_factor", 0.5),
                                              ("exhaustive_limit", -1), ("max_codimension", 2.0), ("seed", -1),
                                              ("seed", None)])
def test_invalid_budgets_raise(parameter, value):
    tests = InvariantTests(KeccakSboxPermutation(16, 4))
    with pytest.raises(ValueError, match=f"{parameter} must be a non-negative integer"):
        tests.round_constants_invariant_test(**{parameter: value})


def test_parameters_can_be_sage_integers():
    # in a Sage session the literals are Sage integers, which numpy's random generator refuses
    rotation = [(i - 1) % 12 for i in range(12)]
    tests = InvariantTests(_toy_spn([IDENTITY_SBOX, PRESENT_SBOX, PRESENT_SBOX], rotation, [0x001, 0x631, 0x5A5]))
    with_sage = tests.round_constants_invariant_test(max_codimension=Integer(24), max_samples_factor=Integer(40),
                                                     exhaustive_limit=Integer(2)**24, seed=Integer(3))
    assert with_sage["test_results"] == tests.round_constants_invariant_test(seed=3)["test_results"]


def test_one_substitution_layer_raises():
    tests = InvariantTests(KeccakPermutation(1, 4))
    with pytest.raises(UnsupportedCipherError, match="at least two rounds"):
        tests.round_constants_invariant_test()


# invariant closure: _invariant_closure


def closure(linear_map, generators, powers=None):
    """W_L(generators), adding the generators one at a time through _invariant_closure."""
    n = linear_map.nrows()
    powers = [linear_map.transpose()] if powers is None else powers
    basis = matrix(F, 0, n)
    for generator in generators:
        basis = _invariant_closure(powers, basis, vector(F, generator))
    return VectorSpace(F, n).subspace(basis.rows())


def naive_closure(linear_map, generators):
    """Smallest linear_map-invariant subspace containing the generators, by iterating to a fixpoint."""
    ambient = VectorSpace(F, linear_map.nrows())
    space = ambient.subspace(list(generators))
    while True:
        grown = space + ambient.subspace([linear_map * b for b in space.basis()])
        if grown.dimension() == space.dimension():
            return space
        space = grown


def random_invertible(rng, n):
    while True:
        m = matrix(F, n, n, [rng.getrandbits(1) for _ in range(n * n)])
        if m.is_invertible():
            return m


def random_vector(n, rng):
    return vector(F, [rng.getrandbits(1) for _ in range(n)])


def test_invariant_closure_matches_naive_closure():
    rng = random.Random(1)
    for _ in range(30):
        n = rng.randint(1, 40)
        linear_map = random_invertible(rng, n)
        generators = [random_vector(n, rng) for _ in range(rng.randint(0, 3))]
        assert closure(linear_map, generators) == naive_closure(linear_map, generators)


def test_invariant_closure_reuses_the_powers_of_l():
    # powers computed for one closure serve the next ones; the level restarts at 0 for every generator
    rng = random.Random(4)
    linear_map = random_invertible(rng, 40)
    powers = [linear_map.transpose()]
    first = [random_vector(40, rng)]
    assert closure(linear_map, first, powers) == naive_closure(linear_map, first)
    assert len(powers) > 1
    second = [random_vector(40, rng) for _ in range(3)]
    assert closure(linear_map, second, powers) == naive_closure(linear_map, second)


def test_lemma_1_on_permutation_matrix():
    rng = random.Random(3)
    n = 12
    permutation = list(range(n))
    rng.shuffle(permutation)
    linear_map = matrix(F, n, n, lambda i, j: 1 if i == permutation[j] else 0)
    for _ in range(10):
        c = random_vector(n, rng)
        orbit = [linear_map**i * c for i in range(n)]
        assert closure(linear_map, [c]) == VectorSpace(F, n).subspace(orbit)
    shift = matrix(F, n, n, lambda i, j: 1 if i == (j + 1) % n else 0)
    assert closure(shift, [vector(F, [1] + [0] * (n - 1))]).dimension() == n
    assert closure(shift, [vector(F, [1] * n)]).dimension() == 1


# S-box coset check (Algorithm 1): _all_invariants_constant


def test_whole_space_is_trivially_proven():
    result = _all_invariants_constant(VectorSpace(F, 10), (((0, 1, 2), tuple(range(8))),))
    assert result == {'status': 'proven', 'method': 'trivial', 'codimension': 0,
                      'cosets_hit': None, 'cosets_total': None, 'samples': 0}


def test_codimension_above_maximum_is_skipped():
    sboxes = tuple(((i,), (0, 1)) for i in range(30))
    result = _all_invariants_constant(unit_space(30, range(5)), sboxes, max_codimension=24)
    assert result['status'] == 'skipped'
    assert result['method'] is None
    assert result['codimension'] == 25
    assert result['samples'] == 0


def test_identity_layer_hits_only_z():
    identity = tuple(((4 * i, 4 * i + 1, 4 * i + 2, 4 * i + 3), tuple(range(16))) for i in range(3))
    zero_structures = unit_space(12, [0, 3, 5, 6, 10])
    result = _all_invariants_constant(zero_structures, identity)
    assert result['status'] == 'not_proven'
    assert result['method'] == 'exhaustive'
    assert result['cosets_hit'] == 1
    assert result['cosets_total'] == 2**7
    assert result['codimension'] == 7


@pytest.mark.parametrize("factor", [0, 1, 40])
def test_sampling_stays_within_its_budget(factor):
    zero_structures = unit_space(4, [0, 1])
    result = _all_invariants_constant(zero_structures, (((0, 1, 2, 3), tuple(range(16))),),
                                      max_samples_factor=factor, exhaustive_limit=0)
    assert result['samples'] <= factor * 4
    assert result['method'] == ('sampling' if factor else None)


def test_uniform_points_match_direct_combinations():
    # the bit-plane products of _uniform_points against the points of Z built bit by bit, with the same
    # coefficients (the first draw of the generator)
    rng = np.random.default_rng(7)
    n, batch = 12, 50
    sboxes = random_sboxes(rng, n, [4, 3, 3, 2])
    zero_structures = VectorSpace(F, n).subspace([vector(F, rng.integers(0, 2, n).tolist()) for _ in range(7)])
    coset_map = _CosetMap(zero_structures, sboxes)
    words = _uniform_points(coset_map, np.random.default_rng(3), batch)

    coefficients = np.random.default_rng(3).integers(0, 2, (zero_structures.dimension(), batch))
    basis = np.array(zero_structures.basis_matrix().rows(), dtype=np.int64)
    points = coefficients.T @ basis % 2
    for row, (positions, _) in enumerate(sboxes):
        expected = points[:, list(positions)] @ (1 << np.arange(len(positions) - 1, -1, -1))
        assert words[row].tolist() == expected.tolist()


def test_sampling_reaches_points_of_high_weight():
    # the second coset needs at least 11 of the 16 coordinates of Z set (10.5% of Z), so only points of high
    # weight reach it; one batch of 80 uniform samples does
    zero_structures = unit_space(17, range(16))
    table = tuple((x & ~1) | (bin(x >> 1).count("1") >= 11) for x in range(1 << 17))
    result = _all_invariants_constant(zero_structures, ((tuple(range(17)), table),), exhaustive_limit=0)
    assert result['samples'] == 80
    assert result['status'] == 'proven'


def test_zero_subspace_is_enumerated():
    result = _all_invariants_constant(VectorSpace(F, 3).subspace([]), (((0, 1, 2), tuple(range(8))),))
    assert (result['status'], result['method'], result['cosets_hit'], result['cosets_total'], result['samples']) == (
        'not_proven', 'exhaustive', 1, 8, 1)


def test_exhaustive_proves_when_sampling_misses_a_coset():
    # Z = first 12 bits (top of a 16-bit S-box); coset = last 4 bits. Coset 15 is only reached from
    # the point with all 12 coordinates set (1 point in 4096), which the 640 samples of the default
    # budget miss with seed 0.
    def nibble(top):
        if top == 0xFFF:
            return 15
        return 0 if top & 15 == 15 else top & 15

    table = tuple((x & 0xFFF0) | (nibble(x >> 4) ^ (x & 15)) for x in range(2**16))
    sboxes = ((tuple(range(16)), table),)
    zero_structures = unit_space(16, range(12))

    result = _all_invariants_constant(zero_structures, sboxes)
    assert result['status'] == 'proven'
    assert result['method'] == 'exhaustive'
    assert (result['cosets_hit'], result['cosets_total']) == (16, 16)

    sampled = _all_invariants_constant(zero_structures, sboxes, exhaustive_limit=2**11)
    assert sampled['status'] == 'not_proven'
    assert sampled['method'] == 'sampling'
    assert (sampled['cosets_hit'], sampled['cosets_total']) == (15, 16)


@pytest.mark.parametrize("dimension, table", [
    (2, tuple((x & 12) | ((x + (x >> 2)) & 3) for x in range(16))),
    (3, tuple((x & 14) | ((x + (x >> 3)) & 1) for x in range(16))),
])
def test_sampling_alone_proves_when_every_point_of_z_is_reached(dimension, table):
    # the S-box maps the points of Z (top bits) onto every coset of Z, and sampling reaches every point of Z,
    # so no enumeration is needed
    result = _all_invariants_constant(unit_space(4, range(dimension)), (((0, 1, 2, 3), table),))
    assert (result['status'], result['method']) == ('proven', 'sampling')
    assert result['cosets_hit'] == result['cosets_total'] == 2 ** (4 - dimension)


@pytest.mark.parametrize("words_per_batch", [None, 8])
def test_enumeration_matches_brute_force_cosets(apply_sbox_layer, monkeypatch, words_per_batch):
    # with a small batch, most of Z is enumerated by the Gray code on the high coordinates, which otherwise only
    # runs for Z of more than about 2^20 points
    if words_per_batch:
        monkeypatch.setattr(invariant_tests, "_ENUMERATION_WORDS_PER_BATCH", words_per_batch)
    rng = np.random.default_rng(7)
    n = 14
    ambient = VectorSpace(F, n)
    for _ in range(5):
        sboxes = random_sboxes(rng, n, [3, 4, 2, 5])
        zero_structures = ambient.subspace([ambient.random_element() for _ in range(7)])
        points = np.array([list(z) for z in zero_structures], dtype=np.uint8)
        images = apply_sbox_layer(points, sboxes)
        kernel = np.array(zero_structures.basis_matrix().right_kernel_matrix().rows(), dtype=np.int64)
        codimension = kernel.shape[0]
        weights = 1 << np.arange(codimension - 1, -1, -1)
        expected = set(((images.astype(np.int64) @ kernel.T) % 2 @ weights).tolist())

        coset_map = _CosetMap(zero_structures, sboxes)
        hit = np.zeros(2**codimension, dtype=bool)
        assert _enumerate(coset_map, hit) == 2 ** zero_structures.dimension()
        assert set(np.flatnonzero(hit).tolist()) == expected

        result = _all_invariants_constant(zero_structures, sboxes)
        assert result['cosets_hit'] == len(expected)
        assert result['status'] == ('proven' if len(expected) == 2**codimension else 'not_proven')


def test_sampling_is_reproducible_with_fixed_seed():
    # 64 samples for 64 cosets and no enumeration: sampling decides, and reaches only some of the cosets
    sboxes = random_sboxes(np.random.default_rng(5), 16, [4, 4, 4, 4])
    zero_structures = unit_space(16, range(10))
    first = _all_invariants_constant(zero_structures, sboxes, max_samples_factor=1, exhaustive_limit=0, seed=3)
    second = _all_invariants_constant(zero_structures, sboxes, max_samples_factor=1, exhaustive_limit=0, seed=3)
    assert first == second
    assert first['method'] == 'sampling'


# Keccak linear layer (from the specification)


def test_keccak_200_lane_closure():
    w = 8
    linear_map = _keccak_linear_layer_from_spec(w)
    lane = [vector(F, [1 if k == z else 0 for k in range(25 * w)]) for z in range(w)]
    # support bound: differences confined to lane (0, 0) generate at most n - 18 dimensions under this L
    assert closure(linear_map, lane).dimension() == 182


# Midori-64: the invariant space of [BCLR2017]


def test_midori_64_invariant_space_is_the_one_of_bclr17():
    structure = SpnStructure(MidoriBlockCipher(64, 128))
    _, subspace, _ = _round_constant_closure(structure)
    n = structure.state_size
    lsb_of_every_cell = VectorSpace(F, n).subspace(
        [vector(F, [int(k == 4 * j + 3) for k in range(n)]) for j in range(16)]
    )
    assert subspace == lsb_of_every_cell
