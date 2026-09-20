"""Reproducible empirical checks for boomerang distinguishers.

Empirical results deliberately have no SAT/UNSAT or optimality status. They
corroborate a fixed distinguisher; they do not prove its probability.
"""

from dataclasses import dataclass
from random import Random


@dataclass(frozen=True, slots=True)
class BoomerangExperimentResult:
    """Portable metadata and outcome of a seeded boomerang experiment.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (BoomerangExperimentResult.__dataclass_params__.frozen, tuple(field.name for field in fields(BoomerangExperimentResult)))
        (True, ('input_difference', 'output_difference', 'rounds', 'samples', 'successes', 'seed', 'provenance'))
    """

    input_difference: int
    output_difference: int
    rounds: int
    samples: int
    successes: int
    seed: int
    provenance: str

    def __post_init__(self) -> None:
        if self.rounds <= 0 or self.samples <= 0:
            raise ValueError("rounds and samples must be positive")
        if not 0 <= self.successes <= self.samples:
            raise ValueError("successes must be between zero and samples")

    @property
    def rate(self) -> float:
        """Return the observed rate, without interpreting it as an exact probability."""

        return self.successes / self.samples


def run_speck32_boomerang_experiment(
    input_difference: int,
    output_difference: int,
    *,
    rounds: int = 8,
    samples: int = 1 << 16,
    seed: int = 0xC1AA5,
) -> BoomerangExperimentResult:
    """Run the legacy single-key Speck32/64 boomerang experiment reproducibly.

    The high and low 16-bit halves follow the Speck word ordering. A fresh
    random 64-bit key and plaintext are generated for every sample, matching
    the intent of the legacy vectorized experiment while making the evidence
    stable and dependency-free.

    EXAMPLES::

        >>> result = run_speck32_boomerang_experiment(
        ...     0x28000010, 0x8000840A, samples=256, seed=1
        ... )
        >>> (result.samples, result.seed, result.successes >= 0)
        (256, 1, True)
    """

    limit = 1 << 32
    for name, value in (
        ("input_difference", input_difference),
        ("output_difference", output_difference),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < limit:
            raise ValueError(f"{name} must be a 32-bit integer")
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 22:
        raise ValueError("rounds must be between 1 and 22")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples <= 0:
        raise ValueError("samples must be a positive integer")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("seed must be an integer")

    generator = Random(seed)
    delta = divmod(input_difference, 1 << 16)
    nabla = divmod(output_difference, 1 << 16)
    successes = 0
    for _ in range(samples):
        round_keys = _expand_key(tuple(generator.getrandbits(16) for _ in range(4)), rounds)
        first = (generator.getrandbits(16), generator.getrandbits(16))
        paired = (first[0] ^ delta[0], first[1] ^ delta[1])
        first_output = _encrypt(first, round_keys)
        paired_output = _encrypt(paired, round_keys)
        lower_first = _decrypt((first_output[0] ^ nabla[0], first_output[1] ^ nabla[1]), round_keys)
        lower_paired = _decrypt(
            (paired_output[0] ^ nabla[0], paired_output[1] ^ nabla[1]), round_keys
        )
        successes += (lower_first[0] ^ lower_paired[0], lower_first[1] ^ lower_paired[1]) == delta

    return BoomerangExperimentResult(
        input_difference,
        output_difference,
        rounds,
        samples,
        successes,
        seed,
        "legacy CLAASP MznBoomerangModelARXOptimized Speck32/64-8 witness",
    )


_MASK = (1 << 16) - 1


def _rotate_left(value: int, amount: int) -> int:
    return ((value << amount) & _MASK) | (value >> (16 - amount))


def _rotate_right(value: int, amount: int) -> int:
    return (value >> amount) | ((value << (16 - amount)) & _MASK)


def _round(state: tuple[int, int], key: int) -> tuple[int, int]:
    left, right = state
    left = ((_rotate_right(left, 7) + right) & _MASK) ^ key
    return left, _rotate_left(right, 2) ^ left


def _expand_key(key: tuple[int, ...], rounds: int) -> tuple[int, ...]:
    round_keys = [key[-1]] + [0] * (rounds - 1)
    schedule = list(reversed(key[:-1]))
    for index in range(rounds - 1):
        schedule[index % len(schedule)], round_keys[index + 1] = _round(
            (schedule[index % len(schedule)], round_keys[index]), index
        )
    return tuple(round_keys)


def _encrypt(state: tuple[int, int], round_keys: tuple[int, ...]) -> tuple[int, int]:
    for key in round_keys:
        state = _round(state, key)
    return state


def _decrypt(state: tuple[int, int], round_keys: tuple[int, ...]) -> tuple[int, int]:
    left, right = state
    for key in reversed(round_keys):
        right = _rotate_right(right ^ left, 2)
        left = _rotate_left(((left ^ key) - right) & _MASK, 7)
    return left, right
