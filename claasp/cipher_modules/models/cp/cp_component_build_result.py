from dataclasses import dataclass, field


@dataclass
class CpComponentBuildResult:
    """Value returned by decoupled CP constraint generators.

    Bundles the declarations, constraints and optional metadata produced
    by a single component generator call so the caller never needs to
    inspect positional-tuple semantics.
    """

    declarations: list = field(default_factory=list)
    constraints: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
