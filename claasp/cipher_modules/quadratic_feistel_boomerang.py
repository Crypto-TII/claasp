# Copyright (C) 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later

"""Affine rank certification of retained quadratic Feistel boomerang windows."""

from dataclasses import dataclass
from fractions import Fraction
from operator import index
from typing import Callable


def _affine_system(function, target, input_bits, output_bits):
    """Encode g(x)=target from zero and basis evaluations; g must be affine."""
    offset = function(0) ^ target
    columns = [function(1 << i) ^ function(0) for i in range(input_bits)]
    return [
        (
            sum(((column >> j) & 1) << i for i, column in enumerate(columns)),
            (offset >> j) & 1,
        )
        for j in range(output_bits)
    ]


def _eliminate(rows):
    """Return rank, consistency, one solution, and an XOR contradiction mask."""
    basis = {}
    contradiction = None
    for row_index, (mask, rhs) in enumerate(rows):
        proof = 1 << row_index
        while mask:
            pivot = mask.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (mask, rhs, proof)
                break
            row, value, certificate = basis[pivot]
            mask ^= row
            rhs ^= value
            proof ^= certificate
        if mask == 0 and rhs:
            contradiction = proof
    solution = 0
    for pivot in sorted(basis):
        mask, rhs, _ = basis[pivot]
        solution |= (rhs ^ ((mask & solution).bit_count() & 1)) << pivot
    return dict(
        rank=len(basis),
        consistent=contradiction is None,
        solution=solution if contradiction is None else None,
        contradiction=contradiction,
    )


@dataclass(frozen=True)
class QuadraticFeistelBoomerangAnalyzer:
    r"""Certify a three-round retained event of a quadratic XOR-Feistel network.

    Rounds have the form ``H_k(L,R) = (R XOR f(L) XOR k,L)``. The round
    function must have algebraic degree at most two; affine terms and a
    constant are allowed. This assumption is supplied by the caller, not
    inferred from a few black-box evaluations. The function need not be a
    permutation. Three binary affine systems give compatibility, an XOR
    contradiction certificate, or a free-round-key witness.

    INPUT:

    - ``word_bits`` -- positive integer, the size of each branch.
    - ``function`` -- callable mapping unsigned ``word_bits``-bit integers to
      integers of the same width, with algebraic degree at most two.

    OUTPUT: an analyzer; call :meth:`analyze` with the six retained boundary
    words. Compatibility with freely chosen round keys does not imply
    compatibility with an actual master-key schedule. An incompatible event
    is impossible for every such schedule. Exact probabilities returned by
    this class assume independent uniform round keys and uniform input;
    they must not be multiplied across overlapping windows. Returning quartets
    are included; this analyzer does not apply a nondegeneracy filter.

    This uses the quadratic polar identity and Feistel boomerang closure
    from Boukerrou et al., ToSC 2020(1),
    https://doi.org/10.13154/tosc.v2020.i1.331-362, and Bonnetain and
    Lallemand, ToSC 2023(3),
    https://doi.org/10.46586/tosc.v2023.i3.101-145. The three-round affine
    projection is described in :meth:`analyze`; it is a specialization of
    dependency-aware four-path analysis, not a fixed-master-key probability
    estimator or a new definition of boomerang probability.

    EXAMPLES::

        sage: from claasp.cipher_modules.quadratic_feistel_boomerang import QuadraticFeistelBoomerangAnalyzer
        sage: analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: (x & 1) * ((x >> 1) & 1))
        sage: result = analyzer.analyze(2, 0, 0, 2, 1, 0)
        sage: result['compatible'], result['probability']
        (True, Fraction(1, 8))
        sage: [result['systems'][name]['rank'] for name in ('upper', 'lower', 'joint')]
        [1, 1, 1]
        sage: analyzer.analyze(1, 0, 0, 2, 0, 0)['compatible']
        False
    """

    word_bits: int
    function: Callable[[int], int]

    def __post_init__(self):
        try:
            width = index(self.word_bits)
        except TypeError as exc:
            raise ValueError("word_bits must be a positive integer") from exc
        if isinstance(self.word_bits, bool) or width <= 0:
            raise ValueError("word_bits must be a positive integer")
        if not callable(self.function):
            raise ValueError("function must be callable and quadratic")
        object.__setattr__(self, "word_bits", width)
        self._evaluate(0)

    def _evaluate(self, value):
        try:
            output = index(self.function(value))
        except TypeError as exc:
            raise ValueError(
                "The round function must return a word-sized integer"
            ) from exc
        if not 0 <= output < 1 << self.word_bits:
            raise ValueError("The round function output does not fit word_bits")
        return output

    def _derivative(self, a, x):
        return self._evaluate(x ^ a) ^ self._evaluate(x)

    def _polar(self, a, b):
        return self._derivative(a, b) ^ self._derivative(a, 0)

    def analyze(self, alpha, beta, gamma, c, d, e):
        r"""Analyze upper ``(alpha,beta)->(gamma,alpha)`` and lower ``(c,d)->(e,c)``.

        INPUT:

        - ``alpha``, ``beta`` -- upper difference words before the first round.
        - ``gamma`` -- upper left difference after the first round; its right
          difference is ``alpha``. The transition is retained on both upper pairs.
        - ``c``, ``d`` -- lower difference words after the middle round.
        - ``e`` -- lower left difference after the last round; its right
          difference is ``c``. The transition is retained on both lower pairs.

        Each argument is an unsigned ``word_bits``-bit integer. Zero words
        are allowed: this routine analyzes events, not whether they constitute
        useful nondegenerate distinguishers. The three round keys are shared
        by all four paths but otherwise freely chosen.

        OUTPUT: dictionary with ``compatible`` and exact ``probability`` as a
        :class:`fractions.Fraction`. A constant closure obstruction returns
        ``obstruction`` and ``nonzero_word``. Otherwise ``systems`` contains
        ``upper``, ``lower`` and ``joint`` affine equations, with coefficient
        bitmasks, rank, consistency and one solution. For an inconsistent
        system, ``contradiction`` is a bitmask selecting rows whose XOR is
        ``0=1``. Compatible results also return total ``rank`` and ``witness``:
        a concatenated input, three round keys and the selected middle words.

        Put ``M_a(x)=f(x XOR a) XOR f(x) XOR f(a) XOR f(0)`` and
        ``eta_a=f(a) XOR f(0)``. First require ``M_gamma(d)=0``. The separate
        systems are ``D_alpha f(R)=gamma XOR beta``,
        ``D_c f(Y)=e XOR d``, and the stacked equations
        ``M_alpha(M_d(L))=M_alpha(c XOR eta_d)``,
        ``M_c(M_gamma(L))=M_c(alpha XOR eta_gamma)``. Their rank sum gives
        the independent-round-key exponent. Construction and elimination cost
        ``O(word_bits * T_f + word_bits**3)`` elementary operations. References and assumptions are in the class docstring.

        EXAMPLES::

            sage: from claasp.cipher_modules.quadratic_feistel_boomerang import QuadraticFeistelBoomerangAnalyzer
            sage: analyzer = QuadraticFeistelBoomerangAnalyzer(2, lambda x: (x & 1) * ((x >> 1) & 1))
            sage: rejected = analyzer.analyze(1, 0, 0, 2, 0, 0)
            sage: rejected['systems']['upper']['consistent'], rejected['systems']['lower']['consistent']
            (True, True)
            sage: joint = rejected['systems']['joint']
            sage: selected = [row for i, row in enumerate(joint['rows']) if (joint['contradiction'] >> i) & 1]
            sage: from functools import reduce
            sage: from operator import xor
            sage: reduce(lambda a, b: (xor(a[0], b[0]), xor(a[1], b[1])), selected, (0, 0))
            (0, 1)
        """
        w = self.word_bits
        try:
            alpha, beta, gamma, c, d, e = map(index, (alpha, beta, gamma, c, d, e))
        except TypeError as exc:
            raise ValueError("Differences must be word-sized integers") from exc
        if any(v < 0 or v >= 1 << w for v in (alpha, beta, gamma, c, d, e)):
            raise ValueError("Differences must fit the word size")
        closure = self._polar(gamma, d)
        if closure:
            return dict(
                compatible=False,
                obstruction="middle_second_derivative",
                nonzero_word=closure,
                probability=Fraction(0),
            )
        functions = [
            ("upper", lambda r: self._derivative(alpha, r), gamma ^ beta, w),
            ("lower", lambda y: self._derivative(c, y), e ^ d, w),
            (
                "joint",
                lambda l: (
                    self._polar(alpha, c ^ self._derivative(d, l))
                    | (self._polar(c, alpha ^ self._derivative(gamma, l)) << w)
                ),
                0,
                2 * w,
            ),
        ]
        systems = {}
        for name, function, target, width in functions:
            rows = _affine_system(function, target, w, width)
            systems[name] = dict(rows=rows, **_eliminate(rows))
        compatible = all(s["consistent"] for s in systems.values())
        result = dict(
            compatible=compatible,
            systems=systems,
            probability=Fraction(0),
            event="retained_three_round_window",
        )
        if compatible:
            rank = sum(s["rank"] for s in systems.values())
            l, r, y = [
                systems[name]["solution"] for name in ("joint", "upper", "lower")
            ]
            result.update(
                rank=rank,
                probability=Fraction(1, 1 << rank),
                witness=dict(
                    input=(r << w) | (l ^ self._evaluate(r)),
                    keys=[0, y ^ r ^ self._evaluate(l), 0],
                    middle_left=l,
                    middle_right=r,
                    next_left=y,
                ),
            )
        return result
