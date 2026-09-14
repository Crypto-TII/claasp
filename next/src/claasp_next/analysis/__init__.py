"""Backend-independent analysis problems, constraints, and results."""

from claasp_next.analysis.constraints import (
    Equal,
    FixedValue,
    HammingWeight,
    Nonzero,
    NotEqual,
)
from claasp_next.analysis.facade import Analysis, AnalysisResult
from claasp_next.analysis.problem import AnalysisProblem, MinimizeWeight
from claasp_next.semantics.cryptanalysis import (
    BitPattern,
    ModularAddTransitionSemantics,
    ModularAddLinearSemantics,
    SBoxTransitionSemantics,
    Trail,
    TrailKind,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)
from claasp_next.analysis.truncated import (
    TruncatedBit,
    TruncatedXorDifference,
    propagate_two_word_speck_round,
    truncated_modular_add,
)
from claasp_next.analysis.targets import AttackTarget
from claasp_next.analysis.boomerang import (
    BoomerangExperimentResult,
    run_speck32_boomerang_experiment,
)
from claasp_next.analysis.composed import (
    DifferentialLinearFixture,
    check_speck32_differential_linear_fixture,
    speck32_differential_linear_legacy_fixture,
)
from claasp_next.analysis.monomial import (
    MonomialTrail, MonomialTrailStep, MultiRoundMonomialTrail,
    MonomialParityResult, PresentMonomialSemantics, PresentRoundMonomialSemantics,
    enumerate_optimal_monomial_parity,
)
from claasp_next.analysis.algebraic import BooleanAlgebraicEvidence, analyze_boolean_algebra
from claasp_next.analysis.cube import CubeSumResult, evaluate_cube_sum
from claasp_next.analysis.neural import (
    NeuralDataset, NeuralExperiment, NeuralExperimentResult, NeuralTrainingDriver,
    black_box_dataset, xor_differential_dataset,
)
from claasp_next.analysis.datasets import (
    AvalancheDataset, AvalancheSample, EvaluationDataset, EvaluationSample,
    generate_avalanche_dataset, generate_random_dataset,
)
from claasp_next.analysis.avalanche import AvalancheResult, avalanche_probabilities
from claasp_next.analysis.neural_experiments import (
    DatasetPartition, NeuralRun, NeuralRunProvenance, dataset_digest,
    deterministic_partition,
)
from claasp_next.analysis.statistical_datasets import (
    StatisticalDataset, StatisticalDatasetManifest, StatisticalRecord,
    cbc_dataset, correlation_dataset,
    high_density_dataset, low_density_dataset,
)

__all__ = [
    "Analysis",
    "AttackTarget",
    "AnalysisProblem",
    "AnalysisResult",
    "Equal",
    "FixedValue",
    "HammingWeight",
    "MinimizeWeight",
    "Nonzero",
    "NotEqual",
    "BitPattern",
    "ModularAddTransitionSemantics",
    "ModularAddLinearSemantics",
    "SBoxTransitionSemantics",
    "Trail",
    "TrailKind",
    "TrailSearchResult",
    "TrailStep",
    "Transition",
    "XorDifference",
    "XorMask",
    "TruncatedBit",
    "TruncatedXorDifference",
    "propagate_two_word_speck_round",
    "truncated_modular_add",
    "BoomerangExperimentResult",
    "run_speck32_boomerang_experiment",
    "DifferentialLinearFixture",
    "check_speck32_differential_linear_fixture",
    "speck32_differential_linear_legacy_fixture",
    "MonomialTrail",
    "MonomialTrailStep",
    "PresentRoundMonomialSemantics",
    "MultiRoundMonomialTrail",
    "PresentMonomialSemantics",
    "MonomialParityResult",
    "enumerate_optimal_monomial_parity",
    "BooleanAlgebraicEvidence",
    "analyze_boolean_algebra",
    "CubeSumResult",
    "evaluate_cube_sum",
    "NeuralDataset",
    "NeuralExperiment",
    "NeuralExperimentResult",
    "NeuralTrainingDriver",
    "black_box_dataset",
    "xor_differential_dataset",
    "AvalancheDataset",
    "AvalancheResult",
    "AvalancheSample",
    "EvaluationDataset",
    "EvaluationSample",
    "avalanche_probabilities",
    "generate_avalanche_dataset",
    "generate_random_dataset",
    "DatasetPartition",
    "NeuralRun",
    "NeuralRunProvenance",
    "dataset_digest",
    "deterministic_partition",
    "StatisticalDataset",
    "StatisticalDatasetManifest",
    "StatisticalRecord",
    "cbc_dataset",
    "correlation_dataset",
    "high_density_dataset",
    "low_density_dataset",
]
