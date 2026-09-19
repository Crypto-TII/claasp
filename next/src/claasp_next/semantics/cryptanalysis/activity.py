"""Component-table activity feasibility, independent of primitive wiring."""

from dataclasses import dataclass
from fractions import Fraction
from math import log2

from .trails import SBoxTransitionSemantics


@dataclass(frozen=True, slots=True)
class AESTwoRoundDifferentialEvidence:
    """Exact evidence behind the legacy two-step active-S-box search.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import AESTwoRoundDifferentialEvidence
        >>> evidence = AESTwoRoundDifferentialEvidence(30, 5, (255,) * 4, 224, 1, 1)
        >>> (evidence.minimum_weight, evidence.minimum_active_sboxes)
        (30, 5)
    """

    minimum_weight: int
    minimum_active_sboxes: int
    trails_per_minimum_activity_pattern: tuple[int, ...]
    full_activity_weight: int
    full_activity_input: int
    full_activity_output: int


@dataclass(frozen=True, slots=True)
class WordwiseActiveSBoxEvidence:
    """Reviewed exact and lower-bound active-S-box sequences.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import WordwiseActiveSBoxEvidence
        >>> WordwiseActiveSBoxEvidence().aes_exact
        (1, 5, 9, 25)
    """

    aes_exact: tuple[int, ...] = (1, 5, 9, 25)
    ublock_decomposed_lower_bounds: tuple[int, ...] = (1, 6)
    ublock_consolidated_lower_bounds: tuple[int, ...] = (1, 8, 9)
    ublock_published_exact: tuple[int, ...] = (1, 8, 13)
    claim_kind: str = "mixed-exact-and-lower-bound"

    def __post_init__(self) -> None:
        if self.claim_kind != "mixed-exact-and-lower-bound":
            raise ValueError("wordwise evidence must distinguish exact values from lower bounds")


def legacy_wordwise_active_sbox_evidence() -> WordwiseActiveSBoxEvidence:
    """Return fixed active-S-box evidence with its claim distinction intact.

    AES values are the Rijndael wide-trail bound.  uBlock's decomposed and
    consolidated values are deliberately retained as model lower bounds; the
    published exact values are stored separately and never inferred from them.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import legacy_wordwise_active_sbox_evidence
        >>> legacy_wordwise_active_sbox_evidence().ublock_published_exact
        (1, 8, 13)
    """

    return WordwiseActiveSBoxEvidence()


def aes_two_round_differential_evidence(table) -> AESTwoRoundDifferentialEvidence:
    """Derive the reduced two-round AES fixtures without a two-step heuristic.

    The first AES round includes MixColumns and the second is final-round style.
    AES's branch number forces at least five active S-boxes.  For every minimum
    three-to-two column activity pattern, exact DDT/MixColumns enumeration finds
    255 weight-30 characteristics.  The all-``ff`` difference supplies the
    preserved feasible weight-224 characteristic.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import aes_two_round_differential_evidence
        >>> aes_two_round_differential_evidence(range(4))
        Traceback (most recent call last):
        ...
        ValueError: AES evidence requires a bijective eight-bit lookup table
    """

    table = tuple(table)
    if len(table) != 256 or sorted(table) != list(range(256)):
        raise ValueError("AES evidence requires a bijective eight-bit lookup table")
    ddt = [[0] * 256 for _ in range(256)]
    for source in range(256):
        for alpha in range(256):
            ddt[alpha][table[source] ^ table[source ^ alpha]] += 1
    maximum = max(max(row) for row in ddt[1:])
    if maximum != 4:
        raise ValueError("the supplied table does not have the AES differential bound")
    input_choices = [sum(ddt[alpha][beta] == maximum for alpha in range(1, 256))
                     for beta in range(256)]
    output_choices = [sum(count == maximum for count in ddt[alpha]) for alpha in range(256)]

    coefficients = (9, 11, 13, 14)
    products = {coefficient: tuple(_gf256_multiply(value, coefficient) for value in range(256))
                for coefficient in coefficients}
    inverse = ((14, 11, 13, 9), (9, 14, 11, 13),
               (13, 9, 14, 11), (11, 13, 9, 14))
    pattern_counts = [0, 0, 0, 0]
    for third in range(1, 256):
        for fourth in range(1, 256):
            column = tuple(products[row[2]][third] ^ products[row[3]][fourth]
                           for row in inverse)
            zero_positions = [index for index, value in enumerate(column) if value == 0]
            if len(zero_positions) != 1:
                continue
            ways = output_choices[third] * output_choices[fourth]
            for value in column:
                if value:
                    ways *= input_choices[value]
            pattern_counts[zero_positions[0]] += ways

    if ddt[0xFF][0xFF] != 2:
        raise ValueError("the fixed full-activity AES transition is absent")
    full_weight = int(32 * -log2(ddt[0xFF][0xFF] / 256))
    return AESTwoRoundDifferentialEvidence(
        minimum_weight=int(5 * -log2(maximum / 256)),
        minimum_active_sboxes=5,
        trails_per_minimum_activity_pattern=tuple(pattern_counts),
        full_activity_weight=full_weight,
        full_activity_input=(1 << 128) - 1,
        full_activity_output=(1 << 128) - 1,
    )


def _gf256_multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ (0x11B if left & 0x80 else 0)) & 0xFF
        right >>= 1
    return result


def branch_number_activity_table(input_units, output_units, branch_number):
    """Return the legacy branch-bound abstraction in MSB-first row order.

    A branch number is a caller-supplied proven bound. These rows are a
    necessary condition only: for a general matrix a retained row need not
    have a concrete field-valued witness.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import branch_number_activity_table
        >>> branch_number_activity_table(1, 1, 2)
        ((0, 0), (1, 1))
    """
    for size in (input_units, output_units, branch_number):
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValueError("unit counts and branch number must be positive integers")
    total = input_units + output_units
    if branch_number > total:
        raise ValueError("branch number exceeds the combined unit count")
    if total > 16:
        raise ValueError("explicit activity tables are limited to 16 units")
    return tuple(tuple((value >> bit) & 1 for bit in reversed(range(total)))
                 for value in range(1 << total)
                 if value == 0 or value.bit_count() >= branch_number)


def possible_active_sbox_counts(tables, weight, *, maximum_active=None):
    """Return counts whose exact DDT probabilities multiply to ``2**-weight``.

    This is a table-only necessary condition, not a whole-primitive trail
    claim. Zero input differences are inactive and excluded. Non-dyadic
    entries are compared rationally without rounding logarithms.

    EXAMPLES::

        >>> from claasp_next.semantics.cryptanalysis import possible_active_sbox_counts
        >>> possible_active_sbox_counts([(0, 1)], 0, maximum_active=2)
        frozenset({0, 1, 2})
    """
    if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
        raise ValueError("weight must be a nonnegative integer")
    if maximum_active is not None and (not isinstance(maximum_active, int)
            or isinstance(maximum_active, bool) or maximum_active < 0):
        raise ValueError("maximum_active must be a nonnegative integer")
    probabilities = set()
    for table in tables:
        semantics = SBoxTransitionSemantics(table)
        for alpha in range(1, len(semantics.table)):
            for beta in range(len(semantics.table)):
                transition = semantics.xor_differential(alpha, beta)
                if transition.numerator:
                    probabilities.add(Fraction(transition.numerator, transition.denominator))
    target = Fraction(1, 1 << weight)
    if maximum_active is None:
        if Fraction(1) in probabilities:
            raise ValueError("probability-one active transitions require maximum_active")
        maximum_active = 0
        if probabilities:
            bound = max(probabilities)
            product = bound
            while product >= target:
                maximum_active += 1
                product *= bound
    current = {Fraction(1)}
    counts = {0} if weight == 0 else set()
    for count in range(1, maximum_active + 1):
        current = {previous * probability for previous in current
                   for probability in probabilities if previous * probability >= target}
        if target in current:
            counts.add(count)
        if not current:
            break
    return frozenset(counts)
