"""Independently checked fixtures for composed cryptanalysis."""

from dataclasses import dataclass

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
    """A composed trail with its legacy search objective and provenance."""

    trail: DifferentialLinearTrail
    legacy_search_weight: float
    provenance: str

    @property
    def exact_weight(self) -> float:
        """Return the composed correlation weight, including the exact connector term."""

        return self.trail.total_weight


def speck32_differential_linear_legacy_fixture() -> DifferentialLinearFixture:
    """Restore the fixed six-round Speck32/64 CP differential-linear fixture.

    The legacy solver minimizes ``p + r + 2q`` and reports 14 for this
    witness. The returned trail separately retains ``p=1``, ``r=7``, and
    ``q=3``; :attr:`DifferentialLinearFixture.exact_weight` applies the exact
    connector expression instead of relabelling the search approximation.
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
    """Recompute all probability-bearing transitions without solver output."""

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
