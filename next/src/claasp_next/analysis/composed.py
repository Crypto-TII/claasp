"""Independently checked fixtures for composed cryptanalysis."""

from dataclasses import dataclass
from random import Random

from claasp_next.semantics.cryptanalysis import (
    DifferentialLinearTrail,
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    ProbabilisticTruncatedModularAddTransition,
    ProbabilisticTruncatedTrail,
    Trail,
    TrailKind,
    TrailStep,
    TruncatedXorDifference,
    XorDifference,
    XorMask,
    check_probabilistic_truncated_modular_add,
)


@dataclass(frozen=True, slots=True)
class DifferentialLinearFixture:
    """A composed trail with its legacy search objective and provenance.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DifferentialLinearFixture.__dataclass_params__.frozen, tuple(field.name for field in fields(DifferentialLinearFixture)))
        (True, ('trail', 'legacy_search_weight', 'provenance'))
    """

    trail: DifferentialLinearTrail
    legacy_search_weight: float
    provenance: str

    @property
    def exact_weight(self) -> float:
        """Return the composed correlation weight, including the exact connector term."""

        return self.trail.total_weight


@dataclass(frozen=True, slots=True)
class DifferentialLinearExperimentResult:
    """Seeded empirical correlation, deliberately carrying no proof status.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (DifferentialLinearExperimentResult.__dataclass_params__.frozen, tuple(field.name for field in fields(DifferentialLinearExperimentResult)))
        (True, ('input_difference', 'output_mask', 'rounds', 'samples', 'even_parities', 'seed', 'provenance', 'claim_kind'))
    """

    input_difference: int
    output_mask: int
    rounds: int
    samples: int
    even_parities: int
    seed: int
    provenance: str
    claim_kind: str = "empirical"

    def __post_init__(self) -> None:
        if self.rounds <= 0 or self.samples <= 0:
            raise ValueError("rounds and samples must be positive")
        if not 0 <= self.even_parities <= self.samples:
            raise ValueError("even parity count must lie within the sample count")
        if self.claim_kind != "empirical":
            raise ValueError("sampled correlations cannot claim proof status")

    @property
    def correlation(self) -> float:
        """Return the observed signed correlation."""

        return 2 * self.even_parities / self.samples - 1.0


def run_chacha_differential_linear_experiment(
    input_difference: int,
    output_mask: int,
    *,
    rounds: int,
    samples: int,
    seed: int,
) -> DifferentialLinearExperimentResult:
    """Evaluate a fixed ChaCha differential-linear pair reproducibly.

    ``rounds`` follows the official ChaCha convention used by the v5 public
    primitive.  One official round equals two legacy ``ROUND_MODE_HALF``
    rounds.  The dependency-free scalar loop intentionally owns empirical
    evidence only; it neither proves feasibility nor validates a search
    objective.


    EXAMPLES::

        >>> try:
        ...     run_chacha_differential_linear_experiment()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    limit = 1 << 512
    for name, value in (("input_difference", input_difference), ("output_mask", output_mask)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < limit:
            raise ValueError(f"{name} must be a 512-bit integer")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or rounds <= 0:
        raise ValueError("rounds must be a positive integer")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples <= 0:
        raise ValueError("samples must be a positive integer")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")

    generator = Random(seed)
    even = 0
    for _ in range(samples):
        state = generator.getrandbits(512)
        difference = _chacha_permute(state, rounds) ^ _chacha_permute(
            state ^ input_difference, rounds
        )
        even += ((difference & output_mask).bit_count() & 1) == 0
    return DifferentialLinearExperimentResult(
        input_difference,
        output_mask,
        rounds,
        samples,
        even,
        seed,
        "legacy CLAASP ChaCha differential-linear empirical fixture",
    )


def run_speck32_differential_linear_experiment(
    input_difference: int,
    output_mask: int,
    *,
    rounds: int,
    samples: int,
    seed: int,
) -> DifferentialLinearExperimentResult:
    """Evaluate a fixed zero-key Speck32/64 pair reproducibly.

    EXAMPLES::

        >>> try:
        ...     run_speck32_differential_linear_experiment()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    limit = 1 << 32
    for name, value in (("input_difference", input_difference), ("output_mask", output_mask)):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < limit:
            raise ValueError(f"{name} must be a 32-bit integer")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 22:
        raise ValueError("rounds must be between 1 and 22")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples <= 0:
        raise ValueError("samples must be a positive integer")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")

    from claasp_next.analysis.boomerang import _encrypt, _expand_key

    round_keys = _expand_key((0, 0, 0, 0), rounds)
    generator = Random(seed)
    even = 0
    for _ in range(samples):
        value = generator.getrandbits(32)
        first = _encrypt(divmod(value, 1 << 16), round_keys)
        paired = _encrypt(divmod(value ^ input_difference, 1 << 16), round_keys)
        difference = ((first[0] ^ paired[0]) << 16) | (first[1] ^ paired[1])
        even += ((difference & output_mask).bit_count() & 1) == 0
    return DifferentialLinearExperimentResult(
        input_difference,
        output_mask,
        rounds,
        samples,
        even,
        seed,
        "legacy CLAASP zero-key Speck32/64 differential-linear empirical fixture",
    )


_CHACHA_COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
_CHACHA_DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
_WORD_MASK = (1 << 32) - 1


def _rotate_left_32(value: int, amount: int) -> int:
    return ((value << amount) & _WORD_MASK) | (value >> (32 - amount))


def _chacha_permute(value: int, rounds: int) -> int:
    state = [(value >> (32 * (15 - index))) & _WORD_MASK for index in range(16)]
    for round_number in range(rounds):
        groups = _CHACHA_COLUMNS if round_number % 2 == 0 else _CHACHA_DIAGONALS
        for a, b, c, d in groups:
            state[a] = (state[a] + state[b]) & _WORD_MASK
            state[d] = _rotate_left_32(state[d] ^ state[a], 16)
            state[c] = (state[c] + state[d]) & _WORD_MASK
            state[b] = _rotate_left_32(state[b] ^ state[c], 12)
            state[a] = (state[a] + state[b]) & _WORD_MASK
            state[d] = _rotate_left_32(state[d] ^ state[a], 8)
            state[c] = (state[c] + state[d]) & _WORD_MASK
            state[b] = _rotate_left_32(state[b] ^ state[c], 7)
    return sum(word << (32 * (15 - index)) for index, word in enumerate(state))


def speck32_differential_linear_legacy_fixture() -> DifferentialLinearFixture:
    """Restore the fixed six-round Speck32/64 CP differential-linear fixture.

    The legacy solver minimizes ``p + r + 2q`` and reports 14 for this
    witness. The returned trail separately retains ``p=1``, ``r=7``, and
    ``q=3``; :attr:`DifferentialLinearFixture.exact_weight` applies the exact
    connector expression instead of relabelling the search approximation.

    EXAMPLES::

        >>> from claasp_next.analysis import speck32_differential_linear_legacy_fixture
        >>> fixture = speck32_differential_linear_legacy_fixture()
        >>> (fixture.legacy_search_weight, round(fixture.exact_weight, 6))
        (14.0, 14.994353)
    """

    differential_semantics = ModularAddTransitionSemantics(16)
    differential_steps = (
        TrailStep("round_0_modular_add", differential_semantics.xor_differential(0x2000, 0x2000, 0)),
        TrailStep("round_1_modular_add", differential_semantics.xor_differential(0, 0x8000, 0x8000)),
    )
    differential = Trail(
        TrailKind.XOR_DIFFERENTIAL,
        XorDifference(0x00102000, 32),
        XorDifference(0x80008002, 32),
        differential_steps,
    )

    parse = TruncatedXorDifference.parse
    connector_transition = ProbabilisticTruncatedModularAddTransition(
        parse("0000000100000000"),
        parse("1000000000000010"),
        parse("?111111100000010"),
        parse("?111111000000000"),
        (0, 100, 100, 100, 100, 100, 100, 0, 0, 0, 0, 0, 0, 100, 0, 0),
    )
    connector = ProbabilisticTruncatedTrail(
        parse("10000000000000001000000000000010"),
        parse("?111111100000010?111111100001000"),
        (connector_transition,),
    )

    linear_semantics = ModularAddLinearSemantics(16)
    linear_inputs = (
        ("key_3_modular_add", 0x0080, 0x00C0, 0x0080),
        ("round_3_modular_add", 0x4081, 0x60C1, 0x4081),
        ("key_4_modular_add", 0x0001, 0x0001, 0x0001),
        ("round_4_modular_add", 0x0001, 0x0001, 0x0001),
        ("key_5_modular_add", 0, 0, 0),
        ("round_5_modular_add", 0, 0, 0),
    )
    linear = Trail(
        TrailKind.XOR_LINEAR,
        XorMask(0x00804001, 32),
        XorMask(0x00040004, 32),
        tuple(TrailStep(name, linear_semantics.xor_linear(left, right, output))
              for name, left, right, output in linear_inputs),
    )
    return DifferentialLinearFixture(
        DifferentialLinearTrail(differential, connector, linear),
        14.0,
        "legacy CLAASP MznDifferentialLinearModel Speck32/64-6 fixed fixture",
    )


def check_speck32_differential_linear_fixture(fixture: DifferentialLinearFixture) -> bool:
    """Recompute all probability-bearing transitions without solver output.

    EXAMPLES::

        >>> try:
        ...     check_speck32_differential_linear_fixture()
        ... except TypeError:
        ...     print("required arguments rejected")
        required arguments rejected
    """

    if not isinstance(fixture, DifferentialLinearFixture):
        return False
    trail = fixture.trail
    differential = ModularAddTransitionSemantics(16)
    linear = ModularAddLinearSemantics(16)
    return (
        all(differential.check(step.transition) for step in trail.differential.steps)
        and all(linear.check(step.transition) for step in trail.linear.steps)
        and all(check_probabilistic_truncated_modular_add(step)
                for step in trail.connector.transitions)
        and fixture.legacy_search_weight
        == trail.differential.total_weight + trail.connector.weight + 2 * trail.linear.total_weight
    )
