"""Qualified fixed evidence whose typed catalogue primitive is not yet present."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LegacyBoundedDifferentialCluster:
    """A preserved legacy solver regression, not a newly re-proved result.

    EXAMPLES::

        >>> from dataclasses import fields
        >>> (LegacyBoundedDifferentialCluster.__dataclass_params__.frozen, tuple(field.name for field in fields(LegacyBoundedDifferentialCluster)))
        (True, ('primitive_family', 'rounds', 'input_difference', 'output_difference', 'maximum_weight', 'trail_count', 'aggregate_weight', 'provenance', 'claim_kind'))
    """

    primitive_family: str
    rounds: int
    input_difference: int
    output_difference: int
    maximum_weight: int
    trail_count: int
    aggregate_weight: float
    provenance: str
    claim_kind: str = "legacy-solver-regression"

    def __post_init__(self) -> None:
        if self.rounds <= 0 or self.maximum_weight < 0 or self.trail_count <= 0:
            raise ValueError("cluster bounds and count must be positive")
        if self.aggregate_weight < 0:
            raise ValueError("aggregate weight cannot be negative")
        if self.claim_kind != "legacy-solver-regression":
            raise ValueError("unreproved evidence cannot claim proof status")


def ublock_three_round_legacy_cluster() -> LegacyBoundedDifferentialCluster:
    """Return the fixed uBlock-128 KISSAT cluster without upgrading its claim.

    EXAMPLES::

        >>> from claasp_next.analysis import ublock_three_round_legacy_cluster
        >>> evidence = ublock_three_round_legacy_cluster()
        >>> (evidence.trail_count, evidence.aggregate_weight, evidence.claim_kind)
        (8, 25.7146, 'legacy-solver-regression')
    """

    return LegacyBoundedDifferentialCluster(
        primitive_family="uBlock",
        rounds=3,
        input_difference=0x04400000000000000044400000000000,
        output_difference=0x00044004444404004400444044400040,
        maximum_weight=31,
        trail_count=8,
        aggregate_weight=25.7146,
        provenance=(
            "legacy CLAASP SatXorDifferentialModel external KISSAT regression; "
            "preserved pending independent typed-catalogue reproduction"
        ),
    )
