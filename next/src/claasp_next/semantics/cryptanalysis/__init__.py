"""Cryptanalytic propagation meanings, transitions, and trails."""

from claasp_next.semantics.cryptanalysis.trails import (
    BitPattern, ModularAddLinearSemantics, ModularAddTransitionSemantics,
    SBoxTransitionSemantics, Trail, TrailKind, TrailSearchResult, TrailStep,
    Transition, XorDifference, XorMask,
)
from claasp_next.semantics.cryptanalysis.problem import (
    ComponentSemanticsBinding, ComponentSemanticsRegistry, PropagationObjective,
    PropagationProblem, TransitionProvider, default_component_semantics,
)
from claasp_next.semantics.cryptanalysis.composed import (
    BoomerangSwitchBoundary, BoomerangTrail, DifferentialLinearTrail,
)
from claasp_next.semantics.cryptanalysis.truncated import (
    ImpossiblePropagationBoundary, ProbabilisticTruncatedModularAddTransition,
    ProbabilisticTruncatedTrail,
    TruncatedBit, TruncatedXorDifference,
    WordwiseDifferenceKind, WordwiseXorDifference,
    check_probabilistic_truncated_modular_add,
    propagate_two_word_speck_inverse_round, propagate_two_word_speck_round,
    propagate_two_word_simon_inverse_round, propagate_two_word_simon_round,
    propagate_single_active_aes_byte,
    truncated_modular_add, truncated_modular_subtract,
)

__all__ = [
    "BitPattern", "ModularAddLinearSemantics", "ModularAddTransitionSemantics",
    "SBoxTransitionSemantics", "Trail", "TrailKind", "TrailSearchResult",
    "TrailStep", "Transition", "XorDifference", "XorMask",
    "ComponentSemanticsBinding", "ComponentSemanticsRegistry",
    "PropagationObjective", "PropagationProblem", "TransitionProvider",
    "default_component_semantics",
    "TruncatedBit", "TruncatedXorDifference", "propagate_two_word_speck_round",
    "propagate_two_word_speck_inverse_round", "ImpossiblePropagationBoundary",
    "propagate_two_word_simon_inverse_round", "propagate_two_word_simon_round",
    "truncated_modular_add", "truncated_modular_subtract",
    "ProbabilisticTruncatedModularAddTransition",
    "ProbabilisticTruncatedTrail",
    "check_probabilistic_truncated_modular_add",
    "propagate_single_active_aes_byte",
    "WordwiseDifferenceKind", "WordwiseXorDifference",
    "BoomerangSwitchBoundary", "BoomerangTrail", "DifferentialLinearTrail",
]
