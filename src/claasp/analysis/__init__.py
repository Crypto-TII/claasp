"""Backend-independent analysis problems, constraints, and results."""

from claasp.analysis.algebraic import BooleanAlgebraicEvidence, analyze_boolean_algebra
from claasp.analysis.avalanche import AvalancheResult, avalanche_probabilities
from claasp.analysis.boomerang import (
    BoomerangExperimentResult,
    run_speck32_boomerang_experiment,
)
from claasp.analysis.component_properties import (
    ComponentAnalysisProvenance,
    ComponentGroup,
    ComponentOccurrence,
    ComponentProperty,
    ComponentPropertyResult,
    ComponentSemanticKey,
    DiagnosticCode,
    PropertyClaim,
    PropertyDiagnostic,
    PropertyDomain,
    PropertyRequest,
    analyze_component_property,
    analyze_lookup_table,
    semantic_component_groups,
    semantic_component_key,
)
from claasp.analysis.composed import (
    DifferentialLinearExperimentResult,
    DifferentialLinearFixture,
    check_speck32_differential_linear_fixture,
    run_chacha_differential_linear_experiment,
    run_speck32_differential_linear_experiment,
    speck32_differential_linear_legacy_fixture,
)
from claasp.analysis.constraints import (
    Equal,
    FixedValue,
    HammingWeight,
    Nonzero,
    NotEqual,
)
from claasp.analysis.cube import CubeSumResult, evaluate_cube_sum
from claasp.analysis.datasets import (
    AvalancheDataset,
    AvalancheSample,
    EvaluationDataset,
    EvaluationSample,
    generate_avalanche_dataset,
    generate_random_dataset,
)
from claasp.analysis.facade import Analysis, AnalysisResult
from claasp.analysis.legacy_evidence import (
    LegacyBoundedDifferentialCluster,
    ublock_three_round_legacy_cluster,
)
from claasp.analysis.monomial import (
    MonomialParityResult,
    MonomialTrail,
    MonomialTrailStep,
    MultiRoundMonomialTrail,
    PresentMonomialSemantics,
    PresentRoundMonomialSemantics,
    enumerate_optimal_monomial_parity,
)
from claasp.analysis.neural import (
    NeuralDataset,
    NeuralExperiment,
    NeuralExperimentResult,
    NeuralTrainingDriver,
    black_box_dataset,
    component_output_dataset,
    round_component_ids,
    xor_differential_component_dataset,
    xor_differential_dataset,
)
from claasp.analysis.neural_experiments import (
    DatasetPartition,
    NeuralRun,
    NeuralRunProvenance,
    dataset_digest,
    deterministic_partition,
)
from claasp.analysis.problem import AnalysisProblem, MinimizeWeight
from claasp.analysis.statistical_datasets import (
    StatisticalDataset,
    StatisticalDatasetManifest,
    StatisticalRecord,
    cbc_dataset,
    correlation_dataset,
    high_density_dataset,
    low_density_dataset,
)
from claasp.analysis.statistical_results import (
    DieharderObservation,
    DieharderReport,
    NISTFinalReport,
    NISTSummaryRow,
    StatisticalAssessment,
    StatisticalTestRun,
)
from claasp.analysis.targets import AttackTarget
from claasp.analysis.truncated import (
    TruncatedBit,
    TruncatedXorDifference,
    propagate_two_word_speck_round,
    truncated_modular_add,
)
from claasp.semantics.cryptanalysis import (
    BitPattern,
    ModularAddLinearSemantics,
    ModularAddTransitionSemantics,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)


def __getattr__(name):
    if name in {"SpeckHybridDifferentialProblem", "HybridDifferentialResult"}:
        from claasp.analysis import hybrid

        return getattr(hybrid, name)
    raise AttributeError(name)


__all__ = [
    "Analysis",
    "AnalysisProblem",
    "AnalysisResult",
    "AttackTarget",
    "AvalancheDataset",
    "AvalancheResult",
    "AvalancheSample",
    "BitPattern",
    "BooleanAlgebraicEvidence",
    "BoomerangExperimentResult",
    "ComponentAnalysisProvenance",
    "ComponentGroup",
    "ComponentOccurrence",
    "ComponentProperty",
    "ComponentPropertyResult",
    "ComponentSemanticKey",
    "CubeSumResult",
    "DatasetPartition",
    "DiagnosticCode",
    "DieharderObservation",
    "DieharderReport",
    "DifferentialLinearExperimentResult",
    "DifferentialLinearFixture",
    "Equal",
    "EvaluationDataset",
    "EvaluationSample",
    "FixedValue",
    "HammingWeight",
    "HybridDifferentialResult",
    "LegacyBoundedDifferentialCluster",
    "MinimizeWeight",
    "ModularAddLinearSemantics",
    "ModularAddTransitionSemantics",
    "MonomialParityResult",
    "MonomialTrail",
    "MonomialTrailStep",
    "MultiRoundMonomialTrail",
    "NISTFinalReport",
    "NISTSummaryRow",
    "NeuralDataset",
    "NeuralExperiment",
    "NeuralExperimentResult",
    "NeuralRun",
    "NeuralRunProvenance",
    "NeuralTrainingDriver",
    "Nonzero",
    "NotEqual",
    "PresentMonomialSemantics",
    "PresentRoundMonomialSemantics",
    "PropertyClaim",
    "PropertyDiagnostic",
    "PropertyDomain",
    "PropertyRequest",
    "SBoxTransitionSemantics",
    "SpeckHybridDifferentialProblem",
    "StatisticalAssessment",
    "StatisticalDataset",
    "StatisticalDatasetManifest",
    "StatisticalRecord",
    "StatisticalTestRun",
    "Trail",
    "TrailKind",
    "TrailSearchResult",
    "TrailStep",
    "Transition",
    "TruncatedBit",
    "TruncatedXorDifference",
    "XorDifference",
    "XorMask",
    "analyze_boolean_algebra",
    "analyze_component_property",
    "analyze_lookup_table",
    "avalanche_probabilities",
    "black_box_dataset",
    "cbc_dataset",
    "check_speck32_differential_linear_fixture",
    "component_output_dataset",
    "correlation_dataset",
    "dataset_digest",
    "deterministic_partition",
    "enumerate_optimal_monomial_parity",
    "evaluate_cube_sum",
    "generate_avalanche_dataset",
    "generate_random_dataset",
    "high_density_dataset",
    "low_density_dataset",
    "propagate_two_word_speck_round",
    "round_component_ids",
    "run_chacha_differential_linear_experiment",
    "run_speck32_boomerang_experiment",
    "run_speck32_differential_linear_experiment",
    "semantic_component_groups",
    "semantic_component_key",
    "speck32_differential_linear_legacy_fixture",
    "truncated_modular_add",
    "ublock_three_round_legacy_cluster",
    "xor_differential_component_dataset",
    "xor_differential_dataset",
]
