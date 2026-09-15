"""Cryptanalytic propagation meanings, transitions, and trails."""

from claasp_next.semantics.cryptanalysis.bitwise import BitwiseAndSemantics
from claasp_next.semantics.cryptanalysis.activity import (
    branch_number_activity_table, possible_active_sbox_counts,
)

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
    BoomerangConnectivity, BoomerangSwitchBoundary, BoomerangTrail,
    DifferentialLinearTrail, SBoxBoomerangSemantics,
    ModularAddBoomerangConnectivity, ModularAddBoomerangSemantics,
    ModularAddBoomerangAutomaton,
)
from claasp_next.semantics.cryptanalysis.continuous import (
    ContinuousHeuristicResult, continuous_modular_add, continuous_rotate_left,
    continuous_rotate_right, continuous_speck32, continuous_xor,
)
from claasp_next.semantics.cryptanalysis.monomial import ComponentMonomialSemantics
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
    "BitwiseAndSemantics",
    "branch_number_activity_table", "possible_active_sbox_counts",
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
    "BoomerangConnectivity", "BoomerangSwitchBoundary", "BoomerangTrail",
    "DifferentialLinearTrail", "SBoxBoomerangSemantics",
    "ModularAddBoomerangConnectivity", "ModularAddBoomerangSemantics",
    "ModularAddBoomerangAutomaton",
    "ContinuousHeuristicResult", "continuous_modular_add",
    "continuous_rotate_left", "continuous_rotate_right", "continuous_speck32",
    "continuous_xor",
    "ComponentMonomialSemantics",
]
