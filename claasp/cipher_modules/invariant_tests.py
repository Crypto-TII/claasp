# ****************************************************************************
# Copyright 2026 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************
r"""
Tests against invariant attacks.

An invariant attack uses a nonconstant Boolean function `g` of the state that every round preserves up to a
constant, `g(R(x)) = g(x) + c`, for some keys (the weak keys); it distinguishes the cipher from a random permutation.
:meth:`InvariantTests.round_constants_invariant_test` checks whether the round constants exclude the invariants kept
by the S-box layer and by each affine part of the rounds, following [BCLR2017]_.
"""
import numbers
from collections import Counter

import numpy as np
from sage.matrix.constructor import matrix
from sage.modules.free_module import VectorSpace
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF

from claasp.cipher_modules.spn_structure import SpnStructure, UnsupportedCipherError

PROVEN_DIMENSION_CRITERION = "proven_dimension_criterion"
PROVEN_COSET_CHECK = "proven_coset_check"
NOT_PROVEN = "not_proven"

# default budgets of the S-box coset check
_MAX_CODIMENSION = 24
_MAX_SAMPLES_FACTOR = 40
_EXHAUSTIVE_LIMIT = 2**24

# coset check: random-walk steps and batch sizes
_FLIPS_PER_STEP = 8
_SAMPLING_BITS_PER_BATCH = 1 << 24
_MINIMUM_SAMPLING_BATCH = 1024
_ENUMERATION_WORDS_PER_BATCH = 1 << 22


def _constant_differences(parts, indices):
    """
    ``(i, c_i + c_first)`` for every affine part ``i`` whose key contribution (its matrix `M_i`) equals the one of an
    earlier part ``first``, i.e. whose round keys are equal up to a constant.
    """
    first_of_key_group, differences = {}, []
    for i in indices:
        key = parts[i].key
        if key in first_of_key_group:
            differences.append((i, parts[i].constant + parts[first_of_key_group[key]].constant))
        else:
            first_of_key_group[key] = i
    return differences


def _invariant_closure(powers, basis, generator):
    r"""
    Echelon basis of `W_L(generator) + V`, where `V`, the row space of ``basis`` (in echelon form), is
    `L`-invariant and ``powers[j]`` is `(L^T)^{2^j}`, extended in place. The Krylov space
    `S_K = V + \langle L^k g : k < K \rangle` is doubled, `S_{2K} = S_K + L^K S_K`, until `L^K S_K` lies in `S_K`.
    """
    basis = basis.stack(generator.row()).echelon_form()
    basis = basis.matrix_from_rows(range(basis.rank()))
    level = 0
    while True:
        if level == len(powers):
            powers.append(powers[-1] * powers[-1])
        grown = basis.stack(basis * powers[level]).echelon_form()
        rank = grown.rank()
        if rank == basis.nrows():
            return basis
        basis, level = grown.matrix_from_rows(range(rank)), level + 1


def _closure_per_transition(linear_layer, differences, transitions, state_size):
    """
    `W_L(D)` and its dimension after adding the difference of every affine part, labelled by its transition. The
    powers of `L` are computed once for all the differences.
    """
    powers = [linear_layer.transpose()]
    basis = matrix(GF(2), 0, state_size)
    closure_dimension_per_transition = []
    for i, difference in differences:
        basis = _invariant_closure(powers, basis, difference)
        closure_dimension_per_transition.append([transitions[i], basis.nrows()])
    subspace = VectorSpace(GF(2), state_size).subspace(basis.rows(), check=False, already_echelonized=True)
    return subspace, closure_dimension_per_transition


def _round_constant_closure(structure):
    """
    The most common linear layer `L` between two substitution layers, `W_L(D)` for the transitions that use it, and
    the ``test_results`` entries describing them. Raises :class:`UnsupportedCipherError` with fewer than two
    substitution layers or a singular `L`.
    """
    layers, n = structure.substitution_layers, structure.state_size
    parts = structure.affine_parts[:-1]  # between two substitution layers
    if not parts:
        raise UnsupportedCipherError("the test needs at least two rounds with a substitution layer")
    transitions = [(layers[i].round_number, layers[i + 1].round_number) for i in range(len(parts))]
    linear_layer, _ = Counter(part.linear for part in parts).most_common(1)[0]
    if not linear_layer.is_invertible():
        # the constant differences are linear structures of an invariant only when L x covers the whole state
        raise UnsupportedCipherError(f"the linear layer between substitution layers has rank "
                                     f"{linear_layer.rank()} < {n}; the criterion needs it invertible")
    used = [i for i, part in enumerate(parts) if part.linear == linear_layer]
    differences = _constant_differences(parts, used)
    subspace, closure_dimension_per_transition = _closure_per_transition(linear_layer, differences, transitions, n)
    summary = {
        "closure_dimension_per_transition": closure_dimension_per_transition,
        "transitions_skipped": [transitions[i] for i in range(len(parts)) if i not in used],
    }
    return linear_layer, subspace, summary


def _check_budgets(**budgets):
    """Raise ``ValueError`` unless every budget, and the seed, is a non-negative integer (zero disables a step)."""
    for name, value in budgets.items():
        if isinstance(value, bool) or not isinstance(value, numbers.Integral) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer, got {value!r}")


def _has_linear_invariant(table, size):
    r"""
    Whether `x \mapsto a \cdot x` is an invariant of the S-box for some `a \neq 0`, i.e. `a \cdot (S(x) + x)` is
    constant: the vectors `S(x) + x + S(0)` then span fewer than ``size`` dimensions. This is the condition the proof
    of Prop. 2 needs (once `\dim W_L(D) \geq n - 1`, every invariant is `a \cdot x + c`); the paper states the
    stronger "no component of degree 1".
    """
    basis = {}
    for x, y in enumerate(table):
        vector = y ^ x ^ table[0]
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = vector
                break
            vector ^= basis[pivot]
    return len(basis) < size


def _linear_invariant_in_every_layer(layers):
    r"""
    Whether every substitution layer has a linear invariant `a \cdot x`; it has one exactly when one of its S-boxes
    has one. Prop. 2 needs a layer without one; the coset check does not.
    """
    found = {}
    for sbox in (sbox for layer in layers for sbox in layer.sboxes):
        key = (sbox.table, len(sbox.positions))
        if key not in found:
            found[key] = _has_linear_invariant(*key)
    return all(any(found[(sbox.table, len(sbox.positions))] for sbox in layer.sboxes) for layer in layers)


class _CosetMap:
    """
    Coset of `S(z)` in `GF(2)^n / Z`, as an integer, for points `z` of `Z`. A point is given by its S-box input
    words (``words``, one row per S-box), linear in its coordinates in a basis of `Z`; the coset is then the XOR of
    one table lookup per S-box. The S-boxes cover every bit, as in the layers of :class:`SpnStructure`.
    """

    def __init__(self, zero_structures, sboxes):
        n = zero_structures.degree()
        groups = [(list(positions), np.array(table, dtype=np.int64)) for positions, table in sboxes]
        basis_matrix = zero_structures.basis_matrix()
        kernel = basis_matrix.right_kernel_matrix()
        codimension = kernel.nrows()
        projection = np.array(kernel.rows(), dtype=np.int64).reshape(codimension, n)
        weights = np.int64(1) << np.arange(codimension - 1, -1, -1, dtype=np.int64)
        column_values = weights @ projection
        basis = np.array(basis_matrix.rows(), dtype=np.int64).reshape(basis_matrix.nrows(), n)

        tables, offsets, basis_words = [], [], []
        offset = 0
        for positions, table in groups:
            size = len(positions)
            shifts = np.arange(size - 1, -1, -1, dtype=np.int64)
            output_bits = (table[:, None] >> shifts) & 1
            tables.append(np.bitwise_xor.reduce(output_bits * column_values[positions], axis=1))
            offsets.append(offset)
            offset += len(table)
            basis_words.append((basis[:, positions] << shifts).sum(axis=1))
        self.table = np.concatenate(tables)
        self.offsets = np.array(offsets, dtype=np.int64)[:, None]
        self.basis_words = np.array(basis_words, dtype=np.int64).reshape(len(groups), basis.shape[0])

    def cosets(self, words):
        return np.bitwise_xor.reduce(self.table[words + self.offsets], axis=0)


def _uniform_points(coset_map, rng, batch):
    """S-box input words of ``batch`` uniformly random points of `Z`."""
    values = coset_map.basis_words
    coefficients = rng.integers(0, 2, (values.shape[1], batch)).astype(np.float32)
    # XOR of the basis words selected by the coefficients, one bit plane at a time (exact: sums stay < 2^24)
    words = np.zeros((values.shape[0], batch), dtype=np.int64)
    for bit in range(int(values.max(initial=0)).bit_length()):
        plane = ((values >> bit) & 1).astype(np.float32)
        words |= ((plane @ coefficients).astype(np.int64) & 1) << bit
    # column order, like the gathers basis_words[:, steps] of the walk, so the XORs stay contiguous
    return np.asfortranarray(words)


def _sample(coset_map, hit, n, max_samples_factor, seed):
    """
    Random walks in `Z`; return the number of points evaluated, at most ``max_samples_factor`` per coset.
    The walks start at uniformly random points of `Z` and each step adds ``_FLIPS_PER_STEP`` random basis
    vectors, so every evaluated point is uniformly distributed in `Z`, as in the paper.
    """
    rng = np.random.default_rng(int(seed))  # numpy refuses Sage integers
    dimension = coset_map.basis_words.shape[1]
    budget = max_samples_factor * len(hit)
    batch = min(budget, max(_MINIMUM_SAMPLING_BATCH, _SAMPLING_BITS_PER_BATCH // n))
    words = _uniform_points(coset_map, rng, batch)
    samples = 0
    for _ in range(budget // batch):
        for _ in range(_FLIPS_PER_STEP):
            steps = rng.integers(0, dimension, batch)
            words ^= coset_map.basis_words[:, steps]
        hit[coset_map.cosets(words)] = True
        samples += batch
        if hit.all():
            break
    return samples


def _enumerate(coset_map, hit):
    """Every point of `Z`: binary counter on the low coordinates, Gray code on the high ones."""
    number_of_sboxes, dimension = coset_map.basis_words.shape
    low = min(dimension, max(0, (_ENUMERATION_WORDS_PER_BATCH // number_of_sboxes).bit_length() - 1))
    low_words = np.zeros((number_of_sboxes, 1), dtype=np.int64)
    for i in range(low):
        low_words = np.concatenate([low_words, low_words ^ coset_map.basis_words[:, i:i + 1]], axis=1)
    high_words = np.zeros((number_of_sboxes, 1), dtype=np.int64)
    samples = since_check = 0
    for counter in range(1 << (dimension - low)):
        if counter:
            i = low + (counter & -counter).bit_length() - 1
            high_words ^= coset_map.basis_words[:, i:i + 1]
        hit[coset_map.cosets(low_words ^ high_words)] = True
        samples += low_words.shape[1]
        since_check += low_words.shape[1]
        if since_check >= hit.size:
            since_check = 0
            if hit.all():
                break
    return samples


def _all_invariants_constant(zero_structures, sboxes, max_codimension=_MAX_CODIMENSION,
                             max_samples_factor=_MAX_SAMPLES_FACTOR, exhaustive_limit=_EXHAUSTIVE_LIMIT, seed=0):
    r"""
    S-box coset check (Algorithm 1 of [BCLR2017]_): decide whether `\{S(z) + Z : z \in Z\}` is the set of all
    cosets of `Z`, which leaves only constant invariants. ``sboxes`` is ``((positions, table), ...)``: each S-box
    reads the bits ``positions`` (the first one is the most significant) and writes ``table[word]`` back, and the
    S-boxes cover every bit. Points of `Z` are sampled uniformly first, then all of `Z` is enumerated if a coset was
    missed and `Z` has at most ``exhaustive_limit`` points. Returns, for this layer, ``status`` (``'proven'``,
    ``'not_proven'`` or ``'skipped'``), ``method`` (``'trivial'``, ``'sampling'``, ``'exhaustive'`` or ``None``),
    ``codimension``, ``cosets_hit``, ``cosets_total`` and ``samples``; :func:`_verdict` summarizes the layers.
    """
    n = zero_structures.degree()
    dimension = zero_structures.dimension()
    codimension = n - dimension
    result = {'status': None, 'method': None, 'codimension': codimension,
              'cosets_hit': None, 'cosets_total': None, 'samples': 0}
    if codimension == 0:
        result.update(status='proven', method='trivial')
        return result
    if codimension > max_codimension:
        result['status'] = 'skipped'
        return result

    coset_map = _CosetMap(zero_structures, sboxes)
    hit = np.zeros(1 << codimension, dtype=bool)
    if dimension and max_samples_factor:
        result['samples'] += _sample(coset_map, hit, n, max_samples_factor, seed)
        result['method'] = 'sampling'
    if not hit.all() and 2 ** dimension <= exhaustive_limit:
        result['samples'] += _enumerate(coset_map, hit)
        result['method'] = 'exhaustive'
    cosets_hit = int(np.count_nonzero(hit))
    result.update(status='proven' if cosets_hit == hit.size else 'not_proven',
                  cosets_hit=cosets_hit if result['method'] else None,
                  cosets_total=hit.size if result['method'] else None)
    return result


def _verdict(subspace, linear_layer, layers, linear_invariant_in_every_layer, coset_check_options):
    """
    The verdict and the ``coset_check`` summary (``None`` when the S-box coset check is not run). The check is run on
    each distinct S-box layer, in round order, until one succeeds; the summary describes all the layers tried.
    """
    if subspace.dimension() >= subspace.degree() - 1 and not linear_invariant_in_every_layer:
        return PROVEN_DIMENSION_CRITERION, None
    if not subspace.dimension():
        return NOT_PROVEN, None
    # Lemma 2: every v + L v with v in W_L(D) is a 0-linear structure; W_L(D) is L-invariant, so these vectors
    # already span the L-invariant subspace Z = W_L({d + L d})
    zero_structures = subspace.ambient_vector_space().subspace([v + linear_layer * v for v in subspace.basis()])
    checks, tried = [], set()
    for layer in layers:
        sboxes = tuple((sbox.positions, sbox.table) for sbox in layer.sboxes)
        if sboxes in tried:
            continue
        tried.add(sboxes)
        check = _all_invariants_constant(zero_structures, sboxes, **coset_check_options)
        if check["status"] == "skipped" or check["method"] == "trivial":  # decided by Z alone, no S-box evaluated
            summary = {"status": check["status"], "codimension": check["codimension"], "cosets_hit": None,
                       "samples": 0, "round": None}
            return (PROVEN_COSET_CHECK if check["status"] == "proven" else NOT_PROVEN), summary
        checks.append((layer.round_number, check))
        if check["status"] == "proven":
            break
    # the reported layer: the one that succeeded, otherwise the one that met the most cosets (coverage is per layer)
    evaluated = [(round_number, check) for round_number, check in checks if check["cosets_hit"] is not None]
    round_number, reported = max(evaluated, key=lambda item: item[1]["cosets_hit"], default=(None, None))
    if reported is not None and reported["status"] == "proven":
        status = "proven"
    elif all(check["method"] == "exhaustive" for _, check in checks):
        status = "not_proven"  # every point of Z was evaluated for every layer: no budget can succeed
    else:
        status = "incomplete"
    summary = {"status": status, "codimension": checks[0][1]["codimension"],
               "cosets_hit": reported["cosets_hit"] if reported else None,
               "samples": sum(check["samples"] for _, check in checks), "round": round_number}
    return (PROVEN_COSET_CHECK if status == "proven" else NOT_PROVEN), summary


class InvariantTests:
    """
    Tests of a cipher against invariant attacks.

    INPUT:

    - ``cipher`` -- **Cipher object**; a cipher made of S-box layers (S-box components, or chi-like NOT / AND / XOR
      layers) and affine operations, as recognized by :class:`SpnStructure`

    EXAMPLES:

    The round constant differences of Skinny-64-64, closed under its linear layer, span the whole state, as in
    [BCLR2017]_, so it has no nonconstant invariant kept by the S-box layer and by every affine part::

        sage: from claasp.cipher_modules.invariant_tests import InvariantTests
        sage: from claasp.ciphers.block_ciphers.skinny_block_cipher import SkinnyBlockCipher
        sage: InvariantTests(SkinnyBlockCipher()).round_constants_invariant_test()['test_results']['verdict']
        'proven_dimension_criterion'
    """

    def __init__(self, cipher):
        self._cipher = cipher

    def round_constants_invariant_test(self, max_codimension=_MAX_CODIMENSION, max_samples_factor=_MAX_SAMPLES_FACTOR,
                                       exhaustive_limit=_EXHAUSTIVE_LIMIT, seed=0):
        r"""
        Return whether the round constants exclude the invariants kept by the S-box layer and by every affine part,
        following [BCLR2017]_.

        The cipher is read as S-box layers separated by affine parts `x \mapsto L x + k_r + c_r` (linear layer `L`,
        round key `k_r`, round constant `c_r`). The test considers, as [BCLR2017]_ does, the invariants kept, up to a
        constant, by the S-box layer and by every affine part. The rounds whose round keys are equal up to a constant
        give differences `D` of their constants, and `W_L(D)` is the smallest subspace containing `D` that `L` maps to
        itself: translating the state by a vector of `W_L(D)` can only change such an invariant by a constant. The
        verdict is:

        - ``'proven_dimension_criterion'`` -- dimension criterion: `\dim W_L(D) \geq n - 1` and one S-box layer has
          no linear invariant `a \cdot x` (Prop. 2 of [BCLR2017]_): no invariant kept by the S-box layer and by every
          affine part exists, for any key
        - ``'proven_coset_check'`` -- the S-box coset check succeeds (Algorithm 1 of [BCLR2017]_), with the same
          conclusion
        - ``'not_proven'`` -- no proof, which does not mean that an invariant exists; ``closure_dimension`` and
          ``coset_check`` say why

        The coset check evaluates the S-box layer on points of `Z = (L + I) W_L(D)`, on whose cosets every invariant is
        constant, and succeeds when the images meet every coset. It is the costly part: about two minutes for
        Keccak-f[1600] or Ascon with the default budget.

        The verdict is for the cipher as CLAASP writes it: ``AsconPermutation`` (chi as the S-box) is proven,
        ``AsconSboxSigmaPermutation`` (Ascon's S-box, hence other affine parts) is not.

        Raises :class:`UnsupportedCipherError` when :class:`SpnStructure` does not recognize the cipher, when its key
        schedule is not made of affine operations (e.g. the S-boxes in the key schedules of AES and PRESENT), when it
        has fewer than two S-box layers, or when `L` is not invertible; raises ``ValueError`` for a budget or seed that
        is not a non-negative integer.

        INPUT:

        - ``max_codimension`` -- **integer** (default: `24`); skip the coset check when `Z` has more than
          ``2**max_codimension`` cosets; its memory and time grow like the number of cosets
        - ``max_samples_factor`` -- **integer** (default: `40`); the coset check tries at most this many random points
          of `Z` per coset and per distinct S-box layer; `0` skips sampling
        - ``exhaustive_limit`` -- **integer** (default: `2**24`); when sampling misses a coset, try every point of `Z`
          if there are at most this many; `0` skips this step
        - ``seed`` -- **integer** (default: `0`); seed of the sampling

        OUTPUT:

        A dictionary with ``input_parameters`` (the cipher, the test name and the parameters above) and
        ``test_results``, whose keys are:

        - ``verdict`` -- ``'proven_dimension_criterion'``, ``'proven_coset_check'`` or ``'not_proven'``, as
          explained above
        - ``closure_dimension``, ``state_size`` -- `\dim W_L(D)` and `n`; the dimension criterion needs at least
          `n - 1`
        - ``linear_invariant_in_every_layer`` -- ``True`` when every S-box layer has a linear invariant `a \cdot x`, so
          that the dimension criterion cannot be applied; it does not mean that the cipher has an invariant
        - ``coset_check`` -- ``None`` when the check is not run: the dimension criterion applies, or
          `W_L(D) = \{0\}` and the constants give nothing to work with; otherwise a dictionary that summarizes the
          S-box layers tried:

          - ``status`` -- ``'proven'`` (one layer meets every coset); ``'skipped'`` (``codimension`` above
            ``max_codimension``, no layer tried); ``'incomplete'`` (no proof, and a larger budget may give one);
            ``'not_proven'`` (every point of `Z` was evaluated for every layer, so no budget can make this check
            succeed)
          - ``codimension`` -- of `Z`, which has `2^{codimension}` cosets
          - ``cosets_hit``, ``round`` -- cosets met by one layer, and its round: the layer that succeeded, otherwise
            the one that met the most cosets; ``None`` when no point was evaluated
          - ``samples`` -- points of `Z` evaluated, over all the layers tried

        - ``closure_dimension_per_transition`` -- ``[(r, r'), d]`` for each difference in `D`, in round order:
          `\dim W_L(D)` once the difference from the affine part between the S-box layers of rounds ``r`` and ``r'``
          is added; an empty list means that no two parts used have the same key contribution (round keys equal up
          to a constant)
        - ``transitions_skipped`` -- the affine parts ``(r, r')`` whose linear layer is not the most common one;
          their constants are not used

        EXAMPLES:

        Midori-64 is not proven: `\dim W_L(D) = 16` out of `64`, as in [BCLR2017]_, and `Z` has too many cosets for
        the coset check. It has the invariant subspace of [GJNQSS2016]_ and the nonlinear invariant of [TLS2016]_ for
        weak keys::

            sage: from claasp.cipher_modules.invariant_tests import InvariantTests
            sage: from claasp.ciphers.block_ciphers.midori_block_cipher import MidoriBlockCipher
            sage: results = InvariantTests(MidoriBlockCipher()).round_constants_invariant_test()['test_results']
            sage: results['closure_dimension'], results['verdict'], results['coset_check']['status']
            (16, 'not_proven', 'skipped')
        """
        _check_budgets(max_codimension=max_codimension, max_samples_factor=max_samples_factor,
                       exhaustive_limit=exhaustive_limit, seed=seed)
        structure = SpnStructure(self._cipher)
        layers = structure.substitution_layers
        linear_layer, subspace, summary = _round_constant_closure(structure)
        linear_invariant_in_every_layer = _linear_invariant_in_every_layer(layers)
        verdict, coset_check = _verdict(
            subspace, linear_layer, layers, linear_invariant_in_every_layer,
            {"max_codimension": max_codimension, "max_samples_factor": max_samples_factor,
             "exhaustive_limit": exhaustive_limit, "seed": seed},
        )
        test_results = {
            "verdict": verdict,
            "closure_dimension": subspace.dimension(),
            "state_size": structure.state_size,
            "linear_invariant_in_every_layer": linear_invariant_in_every_layer,
            "coset_check": coset_check,
            **summary,
        }

        return {
            "input_parameters": {
                "cipher": self._cipher,
                "test_name": "round_constants_invariant_test",
                "max_codimension": max_codimension,
                "max_samples_factor": max_samples_factor,
                "exhaustive_limit": exhaustive_limit,
                "seed": seed,
            },
            "test_results": test_results,
        }
