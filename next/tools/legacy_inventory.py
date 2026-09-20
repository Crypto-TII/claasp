#!/usr/bin/env python3
"""Build and verify the exhaustive CLAASP 4 Python migration inventory.

The output is deterministic and intentionally uses only the Python standard
library. Run from ``next/`` with ``python tools/legacy_inventory.py --check``.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import warnings
from pathlib import Path
from typing import Any

TOOLS_ROOT = Path(__file__).resolve().parent
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from catalogue_classification import classify_bijectivity

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "next" / "migration" / "legacy_inventory.json"
LEGACY_ROOTS = (ROOT / "claasp", ROOT / "tests")
SCHEMA_VERSION = 1

CATEGORY_BY_DIRECTORY = {
    "block_ciphers": "block_ciphers",
    "permutations": "permutations",
    "hash_functions": "functions",
    "mac": "block_functions",
    "stream_ciphers": "block_functions",
    "single_component_ciphers": "single_component_primitives",
    "toys": "toy_primitives",
}

SEMANTIC_PRIMITIVE_CATEGORIES = {
    "permutations",
    "functions",
    "block_ciphers",
    "block_functions",
    "tweakable_block_ciphers",
    "tweakable_block_functions",
}
ORTHOGONAL_CATALOGUE_FOLDERS = {"single_component_primitives", "toy_primitives"}
CATALOGUE_CATEGORIES = (
    SEMANTIC_PRIMITIVE_CATEGORIES | ORTHOGONAL_CATALOGUE_FOLDERS | {"outside_scope"}
)
CATALOGUE_OUT_OF_SCOPE = {
    "claasp/ciphers/block_ciphers/lowmc_generate_matrices.py": "LowMC matrix-generation helper",
    "claasp/ciphers/permutations/util.py": "permutation helper algorithms",
    "claasp/ciphers/single_component_ciphers/_base.py": "abstract fixture base",
    "claasp/ciphers/single_component_ciphers/single_component_ciphers_usage_doctest.py": "documentation-only module",
}
OFFICIAL_NAME_OVERRIDES = {
    "claasp/ciphers/block_ciphers/aradi_block_cipher_sbox.py": "AradiSBox",
    "claasp/ciphers/block_ciphers/aradi_block_cipher_sbox_and_compact_linear_map.py": "AradiSBoxCompactLinearMap",
    "claasp/ciphers/block_ciphers/cham_block_cipher.py": "CHAM",
    "claasp/ciphers/block_ciphers/chilow_block_cipher.py": "Chilow",
    "claasp/ciphers/block_ciphers/hight_block_cipher.py": "HIGHT",
    "claasp/ciphers/block_ciphers/idea_block_cipher.py": "IDEA",
    "claasp/ciphers/block_ciphers/lea_block_cipher.py": "LEA",
    "claasp/ciphers/block_ciphers/sparx_block_cipher.py": "SPARX",
    "claasp/ciphers/block_ciphers/tea_block_cipher.py": "TEA",
    "claasp/ciphers/block_ciphers/xtea_block_cipher.py": "XTEA",
    "claasp/ciphers/permutations/chacha_permutation.py": "ChaCha",
    "claasp/ciphers/permutations/subterranean_permutation.py": "Subterranean",
    "claasp/ciphers/stream_ciphers/chacha_stream_cipher.py": "ChaChaKeystreamBlock",
    "claasp/ciphers/stream_ciphers/bluetooth_stream_cipher_e0.py": "BluetoothE0",
}
PROPOSED_MODULE_STEM_OVERRIDES = {
    "claasp/ciphers/stream_ciphers/bluetooth_stream_cipher_e0.py": "bluetooth_e0",
}
PROPOSED_MODULE_OVERRIDES = {
    "claasp/ciphers/block_ciphers/aradi_block_cipher_sbox.py": "block_ciphers.aradi.sbox",
    "claasp/ciphers/block_ciphers/aradi_block_cipher_sbox_and_compact_linear_map.py": "block_ciphers.aradi.sbox_compact_linear_map",
    "claasp/ciphers/block_ciphers/des_exact_key_length_block_cipher.py": "block_ciphers.des.exact_key_length",
    "claasp/ciphers/block_ciphers/gift_sbox_block_cipher.py": "block_ciphers.gift.sbox",
    "claasp/ciphers/block_ciphers/katan_fsr_block_cipher.py": "block_ciphers.katan.fsr",
    "claasp/ciphers/block_ciphers/ktantan_fsr_block_cipher.py": "block_ciphers.ktantan.fsr",
    "claasp/ciphers/block_ciphers/prince_v2_block_cipher.py": "block_ciphers.prince_v2",
    "claasp/ciphers/block_ciphers/qarmav2_with_mixcolumn_block_cipher.py": "tweakable_block_ciphers.qarmav2.mixcolumn",
    "claasp/ciphers/block_ciphers/simeck_sbox_block_cipher.py": "block_ciphers.simeck.sbox",
    "claasp/ciphers/block_ciphers/simon_sbox_block_cipher.py": "block_ciphers.simon.sbox",
    "claasp/ciphers/block_ciphers/ublock_single_linear_layer_block_cipher.py": "block_ciphers.ublock.single_linear_layer",
    "claasp/ciphers/permutations/ascon_sbox_sigma_no_matrix_permutation.py": "permutations.ascon.sbox_sigma_no_matrix",
    "claasp/ciphers/permutations/ascon_sbox_sigma_permutation.py": "permutations.ascon.sbox_sigma",
    "claasp/ciphers/permutations/gaston_sbox_permutation.py": "permutations.gaston.sbox",
    "claasp/ciphers/permutations/gaston_sbox_theta_permutation.py": "permutations.gaston.sbox_theta",
    "claasp/ciphers/permutations/gimli_sbox_permutation.py": "permutations.gimli.sbox",
    "claasp/ciphers/permutations/keccak_invertible_permutation.py": "permutations.keccak.invertible",
    "claasp/ciphers/permutations/keccak_sbox_permutation.py": "permutations.keccak.sbox",
    "claasp/ciphers/permutations/spongent_pi_fsr_permutation.py": "permutations.spongent_pi.fsr",
    "claasp/ciphers/permutations/spongent_pi_precomputation_permutation.py": "permutations.spongent_pi.precomputation",
    "claasp/ciphers/permutations/tinyjambu_32bits_word_permutation.py": "block_ciphers.tinyjambu.word",
    "claasp/ciphers/permutations/tinyjambu_fsr_32bits_word_permutation.py": "block_ciphers.tinyjambu.fsr_word",
    "claasp/ciphers/permutations/xoodoo_invertible_permutation.py": "permutations.xoodoo.invertible",
    "claasp/ciphers/permutations/xoodoo_sbox_permutation.py": "permutations.xoodoo.sbox",
}

# Legacy one-operation fixtures are evidence for the corresponding v5 base
# component wrapper. The v5 catalogue itself is recorded separately because
# it also contains components that had no CLAASP 4 fixture primitive.
_SINGLE_COMPONENT_REPLACEMENTS = {
    "and_cipher": ("BitwiseAnd", "bitwise_and"),
    "constant_cipher": ("Constant", "constant"),
    "fsr_cipher": ("FeedbackRegister", "feedback_register"),
    "idea_modmul_cipher": ("IDEAMultiply", "idea_multiply"),
    "identity_cipher": ("Identity", "identity"),
    "linear_layer_cipher": ("LinearMap", "linear_map"),
    "mix_column_cipher": ("LinearMap", "linear_map"),
    "modadd_cipher": ("ModularAdd", "modular_add"),
    "modmul_cipher": ("ModularMultiply", "modular_multiply"),
    "modsub_cipher": ("ModularSubtract", "modular_subtract"),
    "not_cipher": ("BitwiseNot", "bitwise_not"),
    "or_cipher": ("BitwiseOr", "bitwise_or"),
    "permutation_cipher": ("Permutation", "permutation"),
    "reverse_cipher": ("Permutation", "permutation"),
    "rotate_cipher": ("Rotate", "rotate"),
    "sbox_cipher": ("BitVectorSBox", "bit_vector_sbox"),
    "shift_cipher": ("Shift", "shift"),
    "shift_rows_cipher": ("Permutation", "permutation"),
    "sigma_cipher": ("LinearMap", "linear_map"),
    "theta_gaston_cipher": ("LinearMap", "linear_map"),
    "theta_keccak_cipher": ("LinearMap", "linear_map"),
    "theta_xoodoo_cipher": ("LinearMap", "linear_map"),
    "variable_rotate_cipher": ("VariableRotate", "variable_rotate"),
    "variable_shift_cipher": ("VariableShift", "variable_shift"),
    "word_permutation_cipher": ("Permutation", "permutation"),
    "xor_cipher": ("Xor", "xor"),
}
for _stem, (_name, _module) in _SINGLE_COMPONENT_REPLACEMENTS.items():
    _path = f"claasp/ciphers/single_component_ciphers/{_stem}.py"
    OFFICIAL_NAME_OVERRIDES[_path] = _name
    PROPOSED_MODULE_OVERRIDES[_path] = f"single_component_primitives.{_module}"

M10_9C_PATHS_BY_SLICE = {
    "M10.9c2": {
        "claasp/DTOs/component_state.py",
        "claasp/DTOs/power_of_2_word_based_dto.py",
        "claasp/component.py",
        "claasp/input.py",
        "claasp/name_mappings.py",
        "claasp/round.py",
        "claasp/rounds.py",
        "claasp/utils/integer.py",
        "claasp/utils/integer_functions.py",
        "claasp/utils/sage_scripts.py",
        "claasp/utils/sequence_operations.py",
        "claasp/utils/templates.py",
        "claasp/utils/utils.py",
        "tests/unit/component_test.py",
        "tests/unit/utils/integer_test.py",
        "tests/unit/utils/sequence_operations_test.py",
        "tests/unit/utils/utils_test.py",
    },
    "M10.9c3": {
        "claasp/components/cipher_output_component.py",
        "claasp/components/constant_component.py",
        "claasp/components/intermediate_output_component.py",
        "claasp/components/permutation_component.py",
        "claasp/components/reverse_component.py",
        "claasp/components/word_permutation_component.py",
        "tests/unit/components/cipher_output_component_test.py",
        "tests/unit/components/constant_component_test.py",
        "tests/unit/components/intermediate_output_component_test.py",
        "tests/unit/components/permutation_component_test.py",
        "tests/unit/components/reverse_component_test.py",
        "tests/unit/components/word_permutation_component_test.py",
    },
    "M10.9c4": {
        "claasp/components/and_component.py",
        "claasp/components/multi_input_non_linear_logical_operator_component.py",
        "claasp/components/not_component.py",
        "claasp/components/or_component.py",
        "claasp/components/sbox_component.py",
        "claasp/components/xor_component.py",
        "tests/unit/components/and_component_test.py",
        "tests/unit/components/multi_input_non_linear_logical_operator_component_test.py",
        "tests/unit/components/not_component_test.py",
        "tests/unit/components/or_component_test.py",
        "tests/unit/components/sbox_component_test.py",
        "tests/unit/components/xor_component_test.py",
    },
    "M10.9c5": {
        "claasp/components/idea_modmul_component.py",
        "claasp/components/modadd_component.py",
        "claasp/components/modmul_component.py",
        "claasp/components/modsub_component.py",
        "claasp/components/modular_component.py",
        "claasp/components/rotate_component.py",
        "claasp/components/shift_component.py",
        "claasp/components/variable_rotate_component.py",
        "claasp/components/variable_shift_component.py",
        "tests/unit/components/idea_modmul_component_test.py",
        "tests/unit/components/modadd_component_test.py",
        "tests/unit/components/modmul_component_test.py",
        "tests/unit/components/modsub_component_test.py",
        "tests/unit/components/modular_component_test.py",
        "tests/unit/components/rotate_component_test.py",
        "tests/unit/components/shift_component_test.py",
        "tests/unit/components/variable_rotate_component_test.py",
        "tests/unit/components/variable_shift_component_test.py",
    },
    "M10.9c6": {
        "claasp/components/linear_layer_component.py",
        "claasp/components/mix_column_component.py",
        "tests/unit/components/linear_layer_component_test.py",
        "tests/unit/components/mix_column_component_test.py",
    },
    "M10.9c7": {
        "claasp/components/fsr_component.py",
        "tests/unit/components/fsr_component_test.py",
    },
    "M10.9c8": {
        "claasp/components/shift_rows_component.py",
        "claasp/components/sigma_component.py",
        "claasp/components/theta_gaston_component.py",
        "claasp/components/theta_keccak_component.py",
        "claasp/components/theta_xoodoo_component.py",
        "tests/unit/components/shift_rows_component_test.py",
        "tests/unit/components/sigma_component_test.py",
        "tests/unit/components/theta_gaston_component_test.py",
        "tests/unit/components/theta_keccak_component_test.py",
        "tests/unit/components/theta_xoodoo_component_test.py",
    },
}
M10_9C_PACKAGE_MARKERS = {
    "claasp/DTOs/__init__.py",
    "claasp/components/__init__.py",
}
M10_9C_PREREQUISITE_BY_SLICE = {
    "M10.9c2": "M10.9c1",
    "M10.9c3": "M10.9c2",
    "M10.9c4": "M10.9c3",
    "M10.9c5": "M10.9c4",
    "M10.9c6": "M10.9c5",
    "M10.9c7": "M10.9c6",
    "M10.9c8": "M10.9c7",
}

M10_9D_WORD_BLOCK_STEMS = {
    "aradi_block_cipher",
    "cham_block_cipher",
    "hight_block_cipher",
    "idea_block_cipher",
    "lea_block_cipher",
    "raiden_block_cipher",
    "rc5_block_cipher",
    "simeck_block_cipher",
    "simon_block_cipher",
    "sparx_block_cipher",
    "speck_block_cipher",
    "tea_block_cipher",
    "threefish_block_cipher",
    "trax_block_cipher",
    "xtea_block_cipher",
}
M10_9D_COMPLETION_SLICES = (
    "M10.9d1",
    "M10.9d2",
    "M10.9d3",
    "M10.9d4",
    "M10.9d5",
    "M10.9d6",
    "M10.9d7",
    "M10.9d8",
)
M10_9D_COMPLETED_SLICES = {
    "M10.9d1",
    "M10.9d2",
    "M10.9d4",
    "M10.9d5",
    "M10.9d6",
    "M10.9d7",
    "M10.9d8",
}
M10_9D_TEST_DESTINATIONS = {
    "M10.9d1": "next/tests/unit/test_chacha.py",
    "M10.9d2": "next/tests/unit/test_salsa.py",
    "M10.9d4": (
        "next/tests/unit/test_single_component_primitives.py; "
        "next/tests/unit/test_toy_primitive_catalogue.py"
    ),
    "M10.9d5": (
        "next/tests/unit/test_word_block_catalogue.py; "
        "next/tests/unit/test_simon_cipher.py; next/tests/unit/test_speck.py"
    ),
    "M10.9d6": (
        "next/tests/unit/test_catalogue_graph_migration.py; "
        "next/tests/integration/test_substitution_block_catalogue.py"
    ),
    "M10.9d7": (
        "next/tests/unit/test_permutation_catalogue.py; "
        "next/tests/integration/test_permutation_catalogue_evidence.py"
    ),
    "M10.9d8": (
        "next/tests/unit/test_function_catalogue.py; "
        "next/tests/integration/test_function_catalogue_evidence.py"
    ),
}


def _m10_9c_slice(path: str) -> str | None:
    owners = [slice_name for slice_name, paths in M10_9C_PATHS_BY_SLICE.items() if path in paths]
    if len(owners) > 1:
        raise ValueError(f"M10.9c path has multiple owners: {path}: {owners}")
    return owners[0] if owners else None


def _m10_9d_source_slice(path: str, catalogue: dict[str, Any]) -> str:
    """Assign every classified catalogue source to one dependency slice."""

    if path == "claasp/ciphers/permutations/chacha_permutation.py":
        return "M10.9d1"
    if path == "claasp/ciphers/permutations/salsa_permutation.py":
        return "M10.9d2"
    category = catalogue["primitive_category"]
    if category == "outside_scope":
        return "M10.9d3"
    if category in {"single_component_primitives", "toy_primitives"}:
        return "M10.9d4"
    if category in {"block_ciphers", "tweakable_block_ciphers"}:
        return "M10.9d5" if Path(path).stem in M10_9D_WORD_BLOCK_STEMS else "M10.9d6"
    if category == "permutations":
        return "M10.9d7"
    if category in {"functions", "block_functions"}:
        return "M10.9d8"
    raise ValueError(f"M10.9d catalogue category has no owner: {path}: {category}")


def _m10_9d_test_slice(path: str) -> str | None:
    if not path.startswith("tests/unit/ciphers/") or not path.endswith("_test.py"):
        return None
    stem = Path(path).stem.removesuffix("_test")
    matches = sorted((ROOT / "claasp" / "ciphers").glob(f"**/{stem}.py"))
    if len(matches) == 1:
        source_path = matches[0].relative_to(ROOT).as_posix()
        tree = _parse(matches[0])
        catalogue = _catalogue_metadata(matches[0].relative_to(ROOT), _public_entries(tree), tree)
        if catalogue:
            return _m10_9d_source_slice(source_path, catalogue)
    return "M10.9d3"


MIGRATION_OVERRIDES = {
    "claasp/cipher_modules/models/milp/milp_models/Gurobi/monomial_prediction.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/monomial.py; next/src/claasp_next/analysis/algebraic.py; next/src/claasp_next/representations/constraints/milp/monomial.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Dependency-free ANF/cube semantics, portable GLPK reachability/parity and proof-qualified results cover every executed legacy fixture without a proprietary solver.",
        "rationale": "The Sage/Gurobi monolith mixes exact symbolic algebra, structural bounds, incomplete solution pools and divide-and-conquer experiments. v5 separates these claims and rejects non-terminal enumeration as proof. Literal expectations from tests permanently skipped behind a Gurobi license are recorded as unverified claims, not promoted to oracle values.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/Gurobi/monomial_prediction_test.py": {
        "v5_destination": "next/tests/unit/test_monomial_prediction.py; next/tests/unit/test_monomial_composition.py; next/tests/unit/test_algebraic_evidence.py; next/tests/unit/test_trivium_algebra.py; next/tests/integration/test_glpk_monomial_prediction.py; next/tests/integration/test_glpk_trivium_monomials.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All previously executable Simon/PRESENT/Trivium results and newly verified 13-/200-clock Trivium claims have independent exact or terminal-solver evidence.",
        "rationale": "uBlock/Gaston/divide-and-conquer and Trivium-508/590 methods are all decorated Requires Gurobi license and have never run in legacy CI; their literals are therefore unverified hypotheses, not applicable fixed results. They remain documented verbatim but are removed from the v5 proof baseline rather than falsely marked preserved or deferred.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_wordwise_branch_number_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "AES exact wide-trail values and uBlock decomposed/consolidated lower bounds are retained with explicit claim kinds distinct from published exact values.",
        "rationale": "Sage branch-number MILP, MiniZinc matrix probes and cache timing are search machinery. The semantic evidence is the resulting bound plus its exact-versus-lower-bound qualification.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_wordwise_branch_number_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "AES 1/5/9/25, uBlock decomposed 1/6 and consolidated 1/8/9 are preserved while published uBlock exact 1/8/13 stays separate.",
        "rationale": "A 15-second performance ceiling, cache call count, helper delegation and rejection messages are implementation tests. The v5 evidence object preserves every numeric result without misreporting loose bounds as exact trails.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_wordwise_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The reduced-AES input/key/output and forward/backward wordwise boundary patterns are retained as a typed abstract incompatibility witness.",
        "rationale": "Sage sentinel variables and graph-copy naming do not define a distinct mathematical model. The witness remains explicitly abstract and is not relabelled a concrete field-valued differential proof.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_wordwise_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "All five fixed patterns 1003..., zero key, 1000..., 22223333..., and 2000... are preserved exactly with an abstract-witness claim kind.",
        "rationale": None,
    },
    "claasp/cipher_modules/models/utils.py": {
        "v5_destination": "next/src/claasp_next/analysis; next/src/claasp_next/semantics/cryptanalysis; next/src/claasp_next/presentation/formatting.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed constraints/results, exact measure conversion and seeded empirical analysis replace a mixed NumPy/Sage/file/helper module.",
        "rationale": "The 1,600-line utility module conflates formatting, random sampling, graph execution, multiprocessing and cryptanalytic claim types. v5 separates these concerns; empirical results carry seeds/provenance and never become SAT or optimum evidence.",
    },
    "tests/unit/cipher_modules/models/models_utils_test.py": {
        "v5_destination": "next/tests/unit/test_constraints.py; next/tests/unit/test_results.py; next/tests/unit/test_composed_trails.py; next/tests/unit/test_continuous_heuristics.py; next/tests/unit/test_formatting.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Fixed result conversions, formatting, seeded Speck/ChaCha experiments, boomerang evidence and continuous correlations retain executable typed coverage.",
        "rationale": "Shape-only worker assertions, temporary-file existence, broad unseeded Salsa ranges and duplicate sequential/parallel smoke tests are implementation checks rather than fixed scientific results. Exact vectors and deterministic empirical fixtures are owned by focused v5 modules.",
    },
    "claasp/cipher_modules/models/milp/milp_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp; next/src/claasp_next/drivers/solvers/glpk.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Portable immutable linear models, typed constraints/objectives and explicit GLPK results replace Sage mixed-integer state and solver registries.",
        "rationale": "Variable-name dictionaries, Sage backend selection, mutable constraint lists and result parsing are split across representation, analysis and driver layers. Scientific subclasses are inventoried separately.",
    },
    "tests/unit/cipher_modules/models/milp/milp_model_test.py": {
        "v5_destination": "next/tests/unit/test_milp_representation.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed equal/not-equal/nonzero constraints, deterministic LP export and real GLPK SAT/UNSAT/assignment decoding are covered.",
        "rationale": "Sage variable names, list positions and installed solver-brand catalogues are not v5 contracts. Backend provenance and status are explicit driver results.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_bitwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed strongest three-valued propagation preserves fixed Speck boundaries; exact finite relations provide a portable MILP baseline where solving is required.",
        "rationale": "Integer sentinel encodings, Sage constraints and minimization of unknown indicators are representation choices. They do not define a different primitive graph or execution engine.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_bitwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_finite_relation_milp.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Both fixed Speck outputs are retained and exact finite-relation MILP decoding is exhaustively checked.",
        "rationale": "The 62,624 generated constraints, Sage variable indices and arbitrary minimum unknown count 14 are encoding/search artifacts, not fixed primitive evidence.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_bitwise_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed forward/backward propagation preserves the fixed Simon-11 middle patterns and contradiction with real solver confirmation.",
        "rationale": "A second Sage encoding of the same impossible-boundary semantics adds no public capability. Generated constraint order and arbitrary Ascon witnesses are discarded.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_bitwise_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Simon input/output and both fixed middle patterns preserve their bit-23 incompatibility independently of backend.",
        "rationale": "Internal/external duplicate tests, 2,400-line counts and solver-selected Ascon components do not add scientific evidence beyond the shared typed boundary.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_wordwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed word activity/value domains and exact finite relations replace sentinel-coded Sage variables.",
        "rationale": "The legacy model exposes encoding-specific integer pairs and mutable cache-derived inequalities. v5 retains the wordwise transfer semantics independently of backend.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_wordwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every wordwise XOR/MDS row and typed AES singleton diffusion is checked exhaustively.",
        "rationale": "The test's 19,768 constraints, first/last Sage expressions and arbitrary feasible/minimum-count statuses are not fixed cryptanalytic results.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact differential relations support fixed/bounded/optimal/complete enumeration with independent graph and weight decoding.",
        "rationale": "Sage probability variables and solver modes are replaced by portable MILP for S-box graphs and generic word-SMT composition for ARX graphs, sharing one semantic contract.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy Speck counts 6/7, optima 1/4, and fixed feasible weights 5/15 are retained by generic independently checked graph models.",
        "rationale": "Arbitrary first witnesses and solver metadata are removed; all exact numeric assertions are preserved by shared representations.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_differential_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Branch-number and exact DDT reasoning derive reduced AES active-S-box minima and distinguish necessary activity bounds from concrete trails.",
        "rationale": "A Sage objective over activity flags is a coarse search abstraction. v5 exposes the bound as semantic evidence and never relabels it an exact differential probability.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_differential_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Reduced AES activity minima and the trivial one-active-S-box first-round bound are derived independently.",
        "rationale": "Building time, Sage solver name and model tag are not scientific results. uBlock's one-round value follows directly from a required nonzero input and one bijective S-box layer; broader uBlock evidence is audited separately.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/trails.py; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Signed exact correlations support complete enumeration, optima and fixed weights through shared graph semantics.",
        "rationale": "Sage variables, solver/license branches and probability-array conventions are replaced by portable representation/driver boundaries and exact Walsh decoders.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy counts 12/13, standard optimum 3 and feasible weights 1/7 retain exact signs and independent decoding.",
        "rationale": "The 12,371-expression layout, fixed Sage indices and proprietary solver error branches are not v5 API contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/milp_truncated_utils.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed truncated domains and exact finite relations replace Sage inequality helper mutation.",
        "rationale": "Variable-index allocation and in-place constraint assembly belong to the representation. The semantic transition tables are now immutable and exhaustively tested.",
    },
    "claasp/cipher_modules/models/milp/utils/mzn_predicates.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "MiniZinc predicates live in the CP representation and are derived from shared semantic providers.",
        "rationale": "A MiniZinc source template in the MILP package violates the v5 representation boundary and duplicates the reviewed CP lowering.",
    },
    "claasp/cipher_modules/models/milp/utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp; next/src/claasp_next/semantics/cryptanalysis",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed semantic registries, immutable linear expressions and exact decoders replace Sage variable/constraint helper dictionaries.",
        "rationale": "Backend variable factories, decimal precision constants and component-method name maps are representation internals, not public semantic APIs.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/composed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed composition separates exact differential, connector and linear terms from seeded empirical correlations for fixed Speck and ChaCha pairs.",
        "rationale": "A heterogeneous list of component method names, guessed unknown counts and one CNF objective do not define a distinct semantic model. v5 preserves reproducible fixed evidence and does not give sampled or approximate results SAT-proof status.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_differential_linear_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed Speck weight decomposition, zero-key empirical bound and fixed ChaCha 6/8-half-round pairs are retained with deterministic sample counts.",
        "rationale": "Unfixed existence checks for Speck, ChaCha and Aradi return arbitrary witnesses; their requested upper bounds are search parameters, not proven optima. Fixed result-bearing pairs are retained. Aradi primitive evaluation evidence remains owned by its catalogue migration rather than this removed SAT wrapper.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_probabilistic_xor_truncated_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact prefixes and typed probabilistic/deterministic truncated suffixes compose explicitly and preserve all fixed Speck boundary patterns.",
        "rationale": "Per-component string dispatch and heterogeneous SAT encodings are replaced by explicit phase composition. Empirical probability estimates remain labelled observations, not model weights or solver proofs.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_probabilistic_xor_truncated_differential_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed four-/five-round Speck outputs and modular-add probability costs are independently retained; invalid ternary values are rejected by typed constructors.",
        "rationale": "Monte Carlo ranges are empirical and backend-independent; the Aradi/ChaCha searches fix no complete solver witness. Exact boundary literals and result-bearing weights are preserved by shared semantics, while catalogue-specific empirical vectors belong with their primitives.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_semi_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed partial differences preserve fixed Speck/ChaCha boundary values without exposing unknown-run counters as semantics.",
        "rationale": "Unknown-window limits are optional pruning constraints, not probabilities. Direct strongest propagation owns deterministic claims; probabilistic transitions carry independently checked costs.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_semi_deterministic_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Both fixed three-round Speck outputs and the fixed reduced-ChaCha empirical evidence remain executable with explicit claim types.",
        "rationale": "SAT/UNSAT caused solely by caller-selected unknown-run caps characterizes a heuristic configuration, not primitive infeasibility. The fixed semantic boundaries are retained; mutable counter configuration is removed.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/composed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared-input-difference experiments use explicit fixed differences, deterministic sampling and empirical result types.",
        "rationale": "Four graph copies and equality clauses are an experimental construction, not a new propagation meaning. v5 keeps permutation execution separate from the statistical observation.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Reduced ChaCha fixed-difference empirical evidence is represented without claiming an exact probability or SAT proof.",
        "rationale": "The legacy checker has no seed and the assertion only bounds one stochastic run; solver status plus sampled weight cannot establish a cryptanalytic proof. The fixed ChaCha family is covered by deterministic composed experiments.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/composed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Backward composed evidence is represented as explicit permutation execution plus an empirical observation, never as an exact trail probability.",
        "rationale": "Graph inversion, prefix mutation, pickled cache files and four-copy CNF construction conflate graph editing, representation and experiment. Those concerns are separated in v5.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_linear_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Fixed reduced-ChaCha composed observations retain empirical provenance without generated inverse-graph cache state.",
        "rationale": "The legacy test mutates/pickles a graph, uses only 256 unseeded samples and asserts a broad bound. It is not reproducible proof evidence; deterministic fixed-pair experiments supersede it.",
    },
    "claasp/cipher_modules/models/sat/utils/mzn_predicates.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/transitions.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact word-operation relations are derived from shared semantics by each representation rather than embedded as cross-backend MiniZinc strings.",
        "rationale": "Despite its SAT location this file is a large MiniZinc source template. Typed CP and SMT lowerings replace copied predicate text and fixed search annotations.",
    },
    "claasp/cipher_modules/models/sat/utils/n_window_heuristic_helper.py": {
        "v5_destination": "next/src/claasp_next/analysis",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "Exact trail models remain complete without window pruning; optional search strategies cannot change decoded transition validity.",
        "rationale": "Full-window counters constrain solver search and may deliberately discard valid trails. They are neither primitive semantics nor probability evidence and are not part of the simple v5 public API.",
    },
    "claasp/cipher_modules/models/sat/utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/semantics/cryptanalysis",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Component semantics selection, phase composition and CNF helpers use typed registries/models and fail explicitly for unsupported operations.",
        "rationale": "Method-name dictionaries and in-place component-list rewrites conflate semantic selection with backend dispatch. v5 uses immutable propagation problems and explicit phase boundaries.",
    },
    "claasp/cipher_modules/models/sat/sat_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat/cnf.py; next/src/claasp_next/drivers/solvers/minisat.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Immutable CNF, typed constraints and explicit MiniSat/Z3 drivers cover construction, solving, status and named assignment decoding.",
        "rationale": "Mutable variable-name clauses, solver registries, subprocess parsing and mixed semantic/search methods are split across v5 representations, drivers and analysis problems. Result-bearing subclasses are inventoried separately.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_bitwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed universal three-valued propagation preserves both fixed reduced-Speck output patterns.",
        "rationale": "Two Boolean variables per ternary bit, generated clause ordering and a solver-specific minimization loop are representation details. The strongest sound output is computed directly and checked independently.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_bitwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck fixed inputs preserve round-one output ????100000000000????100000000011 and round-three output ???????????????0????????????????.",
        "rationale": "The 28,761-clause count, literal spelling/order and an unfixed SAT status are not v5 contracts; both fixed semantic results are retained directly.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_bitwise_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed directional propagation retains the exact Simon-11 fixed patterns and contradiction position, with executable solver confirmation.",
        "rationale": "Forward/backward SAT variable suffixes and graph-copy mutation are replaced by explicit impossible boundaries. Component-local Ascon arbitrary witnesses are not stable public results.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_bitwise_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Simon input 000...001 and output 000000?0?... preserve both exact middle patterns and their bit-23 incompatibility.",
        "rationale": "Generated clause counts and solver-selected Ascon intermediate values are arbitrary witnesses. The fully fixed Simon evidence is preserved and independently checked.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact, deterministic and probabilistic truncated meanings use separate typed result classes and validation rules.",
        "rationale": "The legacy base mixes encodings and result parsing through inheritance. v5 makes the claim kind explicit and shares no mutable SAT model state between them.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Generic graph differential composition retains fixed/bounded/optimal/complete enumeration and independently checked exact weights.",
        "rationale": "CNF counter layouts, window-search clauses and solver parsing are not semantic APIs. Shared transition semantics and complete graph enumeration preserve the exact results across open backends.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck-5 optimum/count, fixed weights, Speck-9 27-trail aggregate 29.47 and all exact graph transitions are retained.",
        "rationale": "Window constraints are optional search heuristics over otherwise exact trails; requested-weight existence does not make literal counter placement a contract. File-output formatting and arbitrary witnesses are removed. The separate uBlock aggregate remains owned by the typed-primitive prerequisite audit.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Signed Walsh semantics and graph composition preserve complete counts, optima, feasible weights and fixed masks.",
        "rationale": "Branch literal naming, CNF ordering, sequential counters and solver dictionaries are replaced by typed masks, exact correlations and independent decoding.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck count 73, optimum 3, feasible weight 7, fixed masks and empirical-correlation bound are preserved.",
        "rationale": "CNF literal order and generated fixed-value strings are representation details. Complete semantic assignments exclude auxiliary-counter multiplicity and retain signed correlations.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "AES branch-number reasoning and exact DDT/MixColumns enumeration derive the minimum five active S-boxes and weight 30 without heuristic XOR augmentation.",
        "rationale": "The first-step Boolean activity search and repeated synthesized XOR components are a search heuristic. v5 records the proven branch property and independently derives the exact result-bearing second-step evidence.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact AES evidence derives the active-S-box lower bound; no mutable helper-list cardinality is exposed.",
        "rationale": "The sole assertion, 188 synthesized XOR components, measures one repetition of an internal redundancy heuristic and carries no mathematical result.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py; next/src/claasp_next/semantics/cryptanalysis/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The two-round reduced AES minimum 30, 255 exact trails per selected minimum activity pattern and feasible all-ff weight 224 are independently derived from DDT and MixColumns semantics.",
        "rationale": "Two sequential solver models, retries, generated tables and warning behavior are an optimization strategy rather than a distinct graph realization. Exact semantic enumeration retains its fixed results without binding the public API to the heuristic.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Independent enumeration preserves minimum weight 30, count 255 for each of four minimum column patterns, and the all-ff weight-224 characteristic.",
        "rationale": "Solver metadata, arbitrary witnesses, retry mocks and generated component names are removed. The three exact numeric scientific assertions are retained and strengthened by derivation over all four symmetric activity patterns.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/usefulfunctions.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact modular-add differential relations and explicit weight bounds are emitted by typed CP representations and independently decoded.",
        "rationale": "The embedded MiniZinc word-operation text, search annotations and fixed scale constants are representation internals. Typed model parts now derive the relation from shared semantics and keep exact versus scaled weights explicit.",
    },
    "claasp/cipher_modules/models/cp/mzn_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/model.py; next/src/claasp_next/drivers/solvers/minizinc.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Immutable MiniZinc IR, explicit solver configuration and typed result/status decoding cover model assembly, fixed constraints, enumeration and weight bounds.",
        "rationale": "Mutable declarations, generated variable-name parsing, subprocess command dictionaries and mixed model/driver state are replaced by the representation/driver boundary. Scientific helper tables and result fixtures are inventoried separately.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Three-valued deterministic propagation is typed, graph-derived and independently checked, including the fixed Speck round boundary.",
        "rationale": "Generated declarations, model-line counts and arbitrary first witnesses are not public contracts. Shared truncated semantics and native CP projection replace component method-name dispatch.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The ARX subset uses the same checked deterministic truncated semantics without a distinct public graph model.",
        "rationale": "The legacy test is assertion-free construction. A separate optimized class would conflate graph realization with execution/search strategy; v5 keeps the semantic problem shared and solver selection explicit.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed Speck deterministic boundary and real MiniZinc projection are independently preserved.",
        "rationale": "The count four is enumeration of unconstrained symmetric unknown patterns and the remaining checks are generated names, line counts, metadata and arbitrary witnesses. v5 tests the fixed mathematical boundary rather than serialization accidents.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "The shared deterministic ARX semantics has executable fixed-vector coverage.",
        "rationale": "The legacy test calls a builder and contains no assertion.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_semi_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Probabilistic-truncated modular addition retains independently checked scaled costs 309/700 and multi-round Speck patterns/weights 1.0/0.0.",
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_semi_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py; next/tests/unit/test_truncated_differences.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed modular-add costs and Speck output/weight fixtures are solved and independently checked.",
        "rationale": "Unfixed one-solution/optimization metadata and Monte Carlo ChaCha smoke checks have no stable oracle. Fixed result-bearing CP fixtures are retained; empirical composed ChaCha evidence is owned by the separately seeded differential-linear audit.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_wordwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed zero/known/nonzero/unknown word domains propagate through graph-derived AES diffusion and native CP projection.",
        "rationale": "Activity integers, negative value sentinels and generated declaration counts are replaced by explicit typed domains. Exact and coarse abstractions are labelled separately.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_wordwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "A fixed one-byte AES input difference becomes four guaranteed nonzero column bytes and projects losslessly through MiniZinc.",
        "rationale": "The legacy test checks only mutable line counts and declarations. The v5 fixed diffusion fixture provides stronger semantic coverage without exposing sentinel encodings.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed forward/backward boundaries, Speck-7 UNSAT and the exact Simon-11 middle contradiction are independently preserved through CP.",
        "rationale": "Cipher graph mutation, inverse-name correspondence, generated-line cleanup and arbitrary low-complexity witnesses are replaced by explicit directional dataflows and contradiction positions.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The seven-round Speck split is proven UNSAT and Simon-11 fixed external/middle patterns preserve the bit-23 contradiction.",
        "rationale": "Generated counts, solver labels and unfixed arbitrary witnesses are not stable evidence. The fully automatic Simon literals and the result-bearing Speck infeasibility are retained with independent semantic checks.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_hybrid_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact local incompatibility and typed multi-round forward/backward contradiction composition replace mixed sentinel domains.",
        "rationale": "The legacy LBlock tests fix no input/output difference and assert counts of six placeholder-only solutions, solver metadata and arbitrary weights. They establish no reproducible cryptanalytic result beyond the shared incompatibility semantics.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_hybrid_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Possible and impossible middle boundaries receive real CP SAT/UNSAT checks and independent contradiction decoding.",
        "rationale": "Six all-unknown LBlock outputs, generated declarations and a first arbitrary weight in {2,3} are not fixed scientific vectors. Exact typed boundary tests supersede them.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/composed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed differential/connector/linear composition preserves the fixed Speck p=1,r=7,q=3 fixture and seeded ChaCha differential-linear evidence with explicit claim kinds.",
        "rationale": "Mutable component partitions, mixed approximate/exact objectives and solver-shaped dictionaries are replaced by typed composition. Search weight, exact composed weight and sampled correlation are never conflated.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_differential_linear_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck's fixed weight-14 decomposition and all three fixed ChaCha input/mask empirical bounds are retained with deterministic samples.",
        "rationale": "Ballet/SipHash and golden-search cases assert only existence of an unfixed solver witness. Generated component names and arbitrary intermediate formatting are not contracts; all fixed boundaries, objective terms and empirical threshold fixtures are preserved.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Generic word-graph composition, explicit bounds/enumeration and independent transition decoding retain all fixed Speck optimum/count fixtures.",
        "rationale": "Search annotations, mutable probability arrays and permutation/key-schedule variable-name partitions are optimizer details. Exact semantics are shared across CP and SMT rather than exposed as a separate graph realization.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py; next/tests/integration/test_word_differential.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck-5 optimum 9, short optimum 5, min-max 5 and fixed-weight/count evidence are independently solved and checked.",
        "rationale": "Assertions on nSolutions>1, arbitrary weights>1 and internal probability-variable names are not scientific fixtures. Every exact numeric result is retained by generic graph models.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared exact differential semantics support fixed/bounded/optimal/enumerated trails with independently validated graph wiring.",
        "rationale": "The legacy model duplicates search modes, parsing and component dispatch. v5 separates one semantic problem from CP/SMT representations and explicit solver drivers.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared signed-correlation semantics support fixed/bounded/optimal/enumerated graph trails and preserve every fixed Speck result.",
        "rationale": "Generated declarations, probability arrays, mutable dispatch and result dictionaries are backend internals. v5 retains masks, exact Walsh counts/signs and complete enumeration independently of the solver encoding.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/mzn_bct_predicates.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact S-box and modular-add boomerang connectivity is counted independently, including the fixed 16-bit Speck switch entry.",
        "rationale": "The fixed four-worker MiniZinc table is an optimization-specific restricted switch predicate. v5 exposes exact BCT semantics and a scalable carry/borrow automaton instead of treating that table or its unweighted acceptance as the mathematical contract.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_boomerang_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/boomerang.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed upper/switch/lower composition retains explicit weights and exact switch counts; the fixed Speck32/64-8 distinguisher is reproducibly evaluated.",
        "rationale": "Graph splitting, generated filenames, mutable model concatenation and solver-output parsing are representation details. Exact switch semantics and separately labelled seeded empirical evidence replace an optimizer-specific builder; an observed rate is never presented as a proof probability.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_boomerang_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The Speck32/64-8 differences 28000010 and 8000840A retain a seeded positive empirical rate; exact BCT and modular-add switch counts are independently checked.",
        "rationale": "The legacy Speck assertion depends on random os.urandom samples and does not fix the solver-selected boundaries; the ChaCha case only checks temporary-file creation and self-consistent parsing. v5 retains the scientific distinguisher as deterministic empirical evidence and replaces construction smoke checks with typed composition tests.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/mzn_continuous_predicates.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/continuous.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Equations 3--5 for continuous XOR, modular addition and rotations preserve the fixed one- and two-round Speck vectors within the legacy tolerance.",
        "rationale": None,
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_differential_linear_continuous_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/continuous.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Continuous propagation and fixed-mask correlation retain numeric provenance and tolerance while never claiming feasibility, optimality or exact probability.",
        "rationale": "The legacy floating SCIP search uses a piecewise approximation and labels numerical candidates SATISFIED. v5 preserves the underlying heuristic equations and fixed evidence but deliberately removes proof-shaped status from continuous results.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_differential_linear_continuous_model_test.py": {
        "v5_destination": "next/tests/unit/test_continuous_heuristics.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed component, one-/two-round and mask-correlation values are preserved with the stated tolerances and explicitly heuristic result type.",
        "rationale": "The unconstrained lowest-correlation test asserts only that SCIP returned an in-range nonzero float and supplies no fixed oracle. Typed dependency-free equations preserve every fixed literal while removing solver and generated-variable incidental contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_and_operation_2_input_bits.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/bitwise.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact independent-bit AND DDT/LAT counts and weights are retained; finite binary relations provide an exact open extended formulation.",
        "rationale": "Sage convex-hull construction and greedy/minimum-facet selection tune an encoding, not cryptanalytic semantics. The exact baseline replaces these algorithms without promising identical facets, inequality counts or Sage object types.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_large_sboxes.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/sbox.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact full DDT and signed Walsh relations support small and eight-bit tables, including nonzero probability-one transitions, with independently checked weights and signs.",
        "rationale": "Espresso product-of-sum minimization, PLA formatting and mutable pickled caches are replaced by an exact one-hot baseline. Full Walsh counts are explicit rather than silently mixing half-Walsh LAT scales. Encoding minimization is not a scientific fixture contract.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_sbox_inequalities_for_trail_search.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/sbox.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Full probability-class support is retained, and the legacy PRESENT probability-2/16 facet is independently valid on every corresponding row.",
        "rationale": "The module itself calls the small-S-box convex-hull code a comparison-only alternative to large-S-box Espresso generation. v5 uses the same exact finite-relation baseline for both; greedy/minimum-facet algorithms, Sage polyhedra and pickled caches are not public APIs.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_sbox_inequalities_for_trail_search_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_milp_relation.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every supported PRESENT DDT/LAT entry and exact objective/sign is checked; the fixed legacy facet holds for all probability-2/16 entries.",
        "rationale": "A particular Sage inequality's position and printed object representation are not v5 contracts; its mathematical validity is preserved explicitly.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_undisturbed_bits_inequalities_for_sboxes.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/trails.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All 81 PRESENT truncated inputs and four undisturbed transitions match the fixed evidence; exact finite relations replace single-output-bit minimization.",
        "rationale": "Typed strongest bitwise derivative joins retain semantics without Espresso, Sage SBox objects, mutable pickle caches or a fixed chosen cube ordering. Unknown bits remain sound abstractions, not probability-bearing joint witnesses.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_undisturbed_bits_inequalities_for_sboxes_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_undisturbed.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All 81 rows, four fixed undisturbed transitions and the five legacy projected forbidden cubes are independently checked.",
        "rationale": "Global cache deletion/repopulation and a particular Espresso output sequence are replaced by immutable in-memory exact relations.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_mds_matrices.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed dense-layer activity reproduces every one of the 256 model-5 rows; the caller must prove nonzero coefficients and no exact joint field witness is claimed.",
        "rationale": "The coarse domain transfer, not Espresso output or a wordsize-keyed mutable cache, owns the mathematics. This abstraction is distinct from the separate 94-row branch-number table and from exact field-matrix support.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_mds_matrix_test.py": {
        "v5_destination": "next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "All 256 rows match the isolated dependency-free legacy generator, including its four fixed first/last row values.",
        "rationale": None,
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed word domains and n-ary XOR reproduce all 18 input/324 binary-XOR rows and all 1000 three-input width-three rows, including recovery of a lone nonzero term after known cancellation.",
        "rationale": "Direct semantic transfer and exact finite relations replace Espresso and mutable arity/matrix-indexed pickle caches. Unknown and nonzero words have no fabricated concrete sentinel values.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits_test.py": {
        "v5_destination": "next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed counts/rows and full generators match; the seven fixed input cubes define exactly the same domain, and four fixed three-input XOR cubes reject no valid row.",
        "rationale": "Exact semantic rows supersede pickle-cache updates and deterministic choices of minimized Espresso cubes; no minimum-cube count is claimed.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_xor_with_n_input_bits.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat/lowering.py; next/src/claasp_next/representations/constraints/milp/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete multi-operand XOR truth tables and exact binary clause inequalities retain parity without external dependencies.",
        "rationale": "Parity clauses are compiled directly from graph wiring. LSB-first point-string enumeration, matrix-arity cache population and pickled global dictionaries are obsolete representation details.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed analysis constraints compile graph execution and projections; MiniZinc independently reproduces the full Speck-22 fixed output A86842F2.",
        "rationale": "The mutable legacy component-method factory, generated declarations and output directives are replaced by shared Boolean graph lowering and explicit projections. Unsupported components fail rather than printing and retaining stale constraints; per-component catalogue coverage is separately inventoried.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete Speck-22 execution is compiled and checked through the shared Boolean-to-CP representation.",
        "rationale": "The legacy optimized builder accepts only ROTATE, SHIFT and XOR and silently omits MODADD; its smoke test establishes no nonlinear correctness. v5 uses complete execution lowering with explicit unsupported-component errors, not an incomplete model labelled optimized.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/sat/lowering.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed fixed/equal/unequal/nonzero constraints and graph projections retain execution witnesses, including full Speck-22 output A86842F2 and Simon AND recovery.",
        "rationale": "Per-component method-name dictionaries, compact-graph mutation, solver registries and result-string parsing are replaced by immutable typed graph lowering and optional drivers. Shared exact/truncated phase composition is explicit, not hidden in a method-name factory.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every Boolean execution clause is translated exactly to a binary inequality; full Speck-22 scalar and GLPK witnesses reproduce A86842F2.",
        "rationale": "The legacy builder omits nonlinear operations and even documents that execution cannot be represented with inequalities. Binary clause inequalities do represent them exactly; the incomplete Sage model and its incidental 9296-constraint count are not retained.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "MiniZinc reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.",
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_z3_integration.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Boolean CLI solving reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.",
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete full-round execution is solved and independently validated rather than merely constructed.",
        "rationale": "The assertion-free legacy construction smoke test accepts a builder that skips modular addition; a checked complete execution witness supersedes it.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_cipher_model_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_graph_milp.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact binary-linear clauses match complete truth tables and full Speck-22 graph witnesses, including modular additions omitted by the legacy builder.",
        "rationale": "Legacy Sage variable names, first/last wiring inequalities and the count 9296 describe an incomplete encoding, not a fixed scientific result.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/model.py",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed model declarations retain explicit identities; no variable groups are inferred by parsing declaration strings.",
        "rationale": "The only helpers filter declaration strings and infer groups from legacy _y names. Typed graph ports and immutable MiniZinc model parts remove this formatting-dependent responsibility.",
    },
    "claasp/cipher_modules/models/sat/utils/constants.py": {
        "v5_destination": "next/src/claasp_next/graph",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "Input/output port identities and logical selections are typed independently of solver variable suffixes.",
        "rationale": "The file contains only _i and _o formatting constants, which are not v5 public model contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/milp_name_mappings.py": {
        "v5_destination": "next/src/claasp_next/semantics; next/src/claasp_next/representations/constraints/milp",
        "prerequisites": [],
        "disposition": "remove",
        "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed semantic descriptors, objectives and result types distinguish mathematical problems from MILP representations.",
        "rationale": "Model dictionary tags, progress messages, decimal-weight precision and variable suffixes are removed; exact component probabilities and explicit objective descriptors own the scientific meaning.",
    },
    "claasp/cipher_modules/models/cp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minizinc.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Optional MiniZinc driver accepts an explicit solver id and executable without requiring a Python MiniZinc or Sage package.",
        "rationale": "Hard-coded command dictionaries, internal/external API duplicates, and assumed installed solver brands are replaced by explicit driver configuration and executable discovery. Proprietary MiniZinc solver ids can be selected optionally, never required by baseline CI.",
    },
    "claasp/cipher_modules/models/milp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/glpk.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "GLPK command driver provides a Sage-independent open MILP baseline; the portable representation and driver protocol do not depend on a proprietary optimizer.",
        "rationale": "The Sage backend registry, cwd captured at import time and solver-brand output regex dictionaries are not migrated APIs. Third-party optimizers can implement the explicit driver protocol without entering the core dependency set; this does not claim a v5 adapter exists for every legacy solver brand.",
    },
    "claasp/cipher_modules/models/sat/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minisat.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "MiniSat and CLI Z3 provide optional open Boolean solving with named assignments and independently verified witnesses.",
        "rationale": "Sage internal solver lists and command-format dictionaries are replaced by explicit driver objects. No installation is inferred from a registry entry. Legacy brand aliases and exact timing/memory log labels are not compatibility contracts; mathematical fixture ownership stays with separate inventoried model tests.",
    },
    "tests/unit/cipher_modules/models/sat/utils/sat_model_utils_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_cnf.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete OR truth-table support and multi-operand XOR intermediate/output witnesses are independently checked.",
        "rationale": "Specific literal-string ordering and intermediate names are replaced by deterministic numeric clauses, typed graph provenance and complete Boolean truth-table tests.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_minizinc_integration.py; next/tests/unit/test_bitwise_transition_semantics.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy Speck-2 exact weight-one count 6 and bounded count 7; toy Speck-4 weight-one UNSAT; identity lookup zero-weight feasibility and positive-weight UNSAT; Speck-5 optimum/fixed weight 9; exact AND DDT are independently preserved.",
        "rationale": "CLI solver drivers and typed independently checked characteristics replace Python MiniZinc API versus external-command duplicates, dictionary model/status tags and arbitrary intermediate component-value formatting. Identity lookup behavior is represented directly by typed Identity; fixed round-key differences are explicit.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_bitwise_transition_semantics.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete toy single-key enumeration retains 12 exact-weight-one and 13 bounded characteristics. Standard Speck-4 optimum and feasible weight 3 and the complete AND LAT are independently checked.",
        "rationale": "Explicit masks, typed results and terminal UNSAT replace legacy fixed-bit string formatters, scaled probability-array declarations, solve-with-API statistics dictionaries, and a hard-coded MiniZinc search annotation. No arbitrary witness or FancyBlockCipher declaration count is a public v5 contract.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py; next/tests/integration/test_minizinc_integration.py; next/tests/integration/test_speck_trail_enumeration.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every fixed AES branch-table row, Midori active-count {3,4}, Speck-3 differential boundaries at weight 6, linear boundaries at weight 5, and boundary comparison SAT/UNSAT are independently preserved.",
        "rationale": "Typed immutable model parts, explicit phase composition and executable drivers replace mutable method-name dictionaries, legacy solver registries, declaration names and time-stat fallbacks. Unknown components fail explicitly rather than silently yielding a nonempty partial model. Intermediate output is not proof-complete evidence. Branch-bound rows remain an abstraction, not concrete MixColumns witnesses.",
    },
    "claasp/cipher_modules/models/algebraic/algebraic_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Typed polynomial lowering and exact Boolean symbolic evaluation retain equation "
            "provenance and independently validate graph evaluations."
        ),
        "rationale": (
            "v5 separates typed graph lowering, polynomial representations, and algebra drivers; "
            "legacy variable strings and a timeout-as-security boolean are not compatibility APIs."
        ),
    },
    "claasp/cipher_modules/models/algebraic/boolean_polynomial_ring.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "The dependency-free BooleanPolynomial type enforces square-free GF(2) arithmetic "
            "without a Sage ring type check."
        ),
        "rationale": "The legacy entry point only identifies Sage's BooleanPolynomialRing type.",
    },
    "claasp/cipher_modules/models/algebraic/constraints.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/polynomial/boolean.py",
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Dependency-free Boolean polynomial constraints preserve equality and exact modular "
            "addition/subtraction semantics, with explicit bit ordering."
        ),
        "rationale": (
            "The Sage polynomial-ring helpers are replaced by the square-free v5 Boolean "
            "polynomial representation."
        ),
    },
    "tests/unit/cipher_modules/models/algebraic/constraints_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_polynomial_constraints.py",
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.8d",
        "acceptance_criterion": (
            "Exhaustive dependency-free tests preserve vector equality and explicit/eliminated "
            "ripple addition and subtraction over complete small domains."
        ),
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/algebraic/algebraic_model_test.py": {
        "v5_destination": (
            "next/tests/unit/test_boolean_symbolic_evaluation.py; "
            "next/tests/unit/test_polynomial.py"
        ),
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Exact Boolean and prime-field graph evaluations satisfy their polynomial semantics; "
            "equation provenance and structural statistics are tested without Sage."
        ),
        "rationale": (
            "FancyBlockCipher-specific variable names and equation counts describe the removed "
            "legacy representation, while its timeout-based security claim is not valid evidence."
        ),
    },
}

_SMT_SOURCE_DESTINATIONS = {
    "claasp/cipher_modules/models/smt/smt_model.py": (
        "next/src/claasp_next/representations/constraints/smt/formula.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_cipher_model.py": (
        "next/src/claasp_next/representations/constraints/smt/lowering.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_deterministic_truncated_xor_differential_model.py": (
        "next/src/claasp_next/semantics/cryptanalysis/truncated.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_xor_differential_model.py": (
        "next/src/claasp_next/representations/constraints/smt/trails.py"
    ),
    "claasp/cipher_modules/models/smt/smt_models/smt_xor_linear_model.py": (
        "next/src/claasp_next/representations/constraints/smt/trails.py"
    ),
    "claasp/cipher_modules/models/smt/solvers.py": ("next/src/claasp_next/drivers/solvers/z3.py"),
    "claasp/cipher_modules/models/smt/utils/constants.py": (
        "next/src/claasp_next/drivers/solvers/z3.py"
    ),
    "claasp/cipher_modules/models/smt/utils/utils.py": (
        "next/src/claasp_next/representations/constraints/smt"
    ),
}
for _path, _destination in _SMT_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": (
            "Backend-neutral SMT representations consume shared semantics, preserve provenance, "
            "and execute through the explicit Z3 driver."
        ),
        "rationale": (
            "v5 replaces backend-shaped model classes, syntax helpers, and solver registries "
            "with shared semantic problems, immutable representations, and separate drivers."
        ),
    }

MIGRATION_OVERRIDES.update(
    {
        "tests/unit/cipher_modules/models/smt/smt_model_test.py": {
            "v5_destination": (
                "next/tests/unit/test_smt.py; next/tests/unit/test_analysis_constraints.py"
            ),
            "prerequisites": [],
            "disposition": "supersede",
            "status": "superseded-in-m10.8d",
            "acceptance_criterion": (
                "Portable SMT serialization and shared fixed-value constraints are deterministic; "
                "solver identity is explicit driver provenance."
            ),
            "rationale": (
                "Legacy solver catalogues and exact backend assertion strings are not v5 contracts."
            ),
        },
        "tests/unit/cipher_modules/models/smt/smt_models/smt_cipher_model_test.py": {
            "v5_destination": "next/tests/integration/test_z3_integration.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.4a",
            "acceptance_criterion": (
                "Z3 recovers the full Speck32/64 designers' ciphertext and graph evaluation "
                "independently verifies the assignment."
            ),
            "rationale": None,
        },
        "tests/unit/cipher_modules/models/smt/smt_models/smt_xor_differential_model_test.py": {
            "v5_destination": "next/tests/integration/test_minizinc_integration.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.8d",
            "acceptance_criterion": (
                "Retain the proven Speck32/64-5 optimum weight 9 and independently reproduce the "
                "legacy count of 28 trails with weights 9 through 10."
            ),
            "rationale": None,
        },
        "tests/unit/cipher_modules/models/smt/smt_models/smt_xor_linear_model_test.py": {
            "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.8d",
            "acceptance_criterion": (
                "Preserve the Speck32/64-4 optimum weight 3, reduced three-round weights 1 and 7, "
                "and the eight Speck8/16 trails of weight at most 2."
            ),
            "rationale": None,
        },
    }
)

# M10.15 owns the remaining mixed serialization/code-generation/evaluator
# surfaces. Existing typed scalar, batch, component, and continuous-analysis
# semantics are reused rather than reimplemented under legacy helper names.
_M10_15_OVERRIDES = {
    "claasp/cipher_modules/code_generator.py": (
        "next/src/claasp_next/representations/source; next/src/claasp_next/drivers/source.py",
        "migrate",
        "Deterministic typed Python and C compilers plus explicit isolated drivers replace mutable legacy generators, shared package-directory artifacts, and implicit compilation.",
    ),
    "claasp/cipher_modules/evaluator.py": (
        "next/src/claasp_next/representations/execution; next/src/claasp_next/drivers/source.py",
        "supersede",
        "The achieved scalar and dependency-free batch engines remain the semantic oracle; only explicit generated-artifact execution is added as a separate driver.",
    ),
    "claasp/cipher_modules/generic_functions.py": (
        "next/src/claasp_next/components; next/src/claasp_next/representations/execution",
        "supersede",
        "Typed components and the registered scalar evaluator already own the mathematical behavior; free-form Sage/bitstring helpers and generated-code string helpers are not duplicated.",
    ),
    "claasp/cipher_modules/generic_functions_continuous_diffusion_analysis.py": (
        "next/src/claasp_next/semantics/cryptanalysis/continuous.py; next/tests/unit/test_continuous_heuristics.py",
        "supersede",
        "M10.6d6 already owns typed continuous heuristic semantics and evidence; the NumPy/Sage helper monolith is closed without reopening that milestone.",
    ),
    "claasp/cipher_modules/generic_functions_vectorized_bit.py": (
        "next/src/claasp_next/representations/execution/batch.py",
        "supersede",
        "The dependency-free transposed batch driver preserves scalar semantics for arbitrary domains without a required NumPy-specific bit API.",
    ),
    "claasp/cipher_modules/generic_functions_vectorized_byte.py": (
        "next/src/claasp_next/representations/execution/batch.py",
        "supersede",
        "Typed logical units and the dependency-free batch driver replace byte-layout heuristics and mandatory NumPy conversion helpers.",
    ),
    "tests/unit/cipher_modules/code_generator_test.py": (
        "next/tests/unit/test_source_generation.py; next/tests/integration/test_native_source_driver.py",
        "supersede",
        "Semantic parity, deterministic source, explicit unsupported diagnostics, safe paths, compiler provenance, and bounded subprocess tests replace generated-line and shared-library side-effect assertions.",
    ),
    "tests/unit/cipher_modules/generic_functions_test.py": (
        "next/tests/unit/test_source_generation.py; next/tests/unit/test_batch_evaluation.py; next/tests/unit/test_feedback_register.py",
        "supersede",
        "Existing typed component/evaluator evidence plus generated-source parity preserves applicable values; expression-string and mutable helper internals are not contracts.",
    ),
    "tests/unit/cipher_modules/generic_functions_continuous_diffusion_analysis_test.py": (
        "next/tests/unit/test_continuous_heuristics.py",
        "supersede",
        "M10.6d6 fixed continuous-analysis evidence already covers the retained heuristic semantics independently of generated evaluator code.",
    ),
    "tests/unit/cipher_modules/generic_functions_vectorized_bit_test.py": (
        "next/tests/unit/test_batch_evaluation.py; next/tests/unit/test_source_generation.py",
        "supersede",
        "Scalar/batch and generated-source parity retain semantic results without NumPy array-shape or debug-print contracts.",
    ),
    "tests/unit/cipher_modules/generic_functions_vectorized_byte_test.py": (
        "next/tests/unit/test_batch_evaluation.py; next/tests/unit/test_source_generation.py",
        "supersede",
        "Typed batch inputs and exact scalar parity replace byte-oriented NumPy packing helpers; fixed-width source boundary cases are tested directly.",
    ),
}
for _path, (_destination, _disposition, _rationale) in _M10_15_OVERRIDES.items():
    MIGRATION_OVERRIDES[_path] = {
        "milestone_owner": "M10.15a",
        "v5_destination": _destination,
        "prerequisites": ["M10.14"],
        "disposition": _disposition,
        "status": (
            ("migrated-in-m10.15f" if _path.startswith("claasp/") else "superseded-in-m10.15f")
            if "code_generator" in _path
            else "superseded-in-m10.15d"
        ),
        "acceptance_criterion": "The M10.15 closure manifest names fixed evidence for every retained behavior, every destination exists, and the complete tooling closure gate passes.",
        "rationale": _rationale,
    }

MIGRATION_OVERRIDES.update(
    {
        "claasp/cipher_modules/continuous_diffusion_analysis.py": {
            "milestone_owner": "M10.6d6",
            "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/continuous.py; next/src/claasp_next/analysis/legacy_evidence.py",
            "prerequisites": ["M10.6d6"],
            "disposition": "supersede",
            "status": "superseded-in-m10.15d-audit",
            "acceptance_criterion": "Typed dependency-free continuous heuristic results preserve fixed one-/two-round Speck evidence, explicit masks, binary64 precision, and tolerances without exact-proof claims.",
            "rationale": "M10.6d6 already replaced the mutable NumPy/Sage orchestration and report coupling. M10.15 closes the stale record but does not reopen continuous-analysis semantics.",
        },
        "tests/unit/cipher_modules/continuous_diffusion_analysis_test.py": {
            "milestone_owner": "M10.6d6",
            "v5_destination": "next/tests/unit/test_continuous_heuristics.py; next/tests/unit/test_presentation_adapters.py",
            "prerequisites": ["M10.6d6", "M10.14"],
            "disposition": "supersede",
            "status": "superseded-in-m10.15d-audit",
            "acceptance_criterion": "Fixed continuous XOR/rotation/addition/Speck evidence and typed presentation pass independently of legacy random orchestration and nested report dictionaries.",
            "rationale": "Exact continuous fixtures were achieved in M10.6d6 and presentation in M10.14; stochastic ranges, component-id parsing, and legacy report shapes are not evaluator contracts.",
        },
    }
)

# M10.14 replaces the mutable catch-all Report and the dedicated NIST report
# writer with immutable presentation artifacts and explicit adapters.  Plotting
# and catalogue-display deferrals remain recorded separately in the M10.14
# obligation manifest so achieved analysis and discovery records are not
# rewritten merely because presentation consumes their typed results.
MIGRATION_OVERRIDES.update(
    {
        "claasp/cipher_modules/report.py": {
            "milestone_owner": "M10.14a",
            "v5_destination": "next/src/claasp_next/presentation",
            "prerequisites": ["M10.11", "M10.12", "M10.13"],
            "disposition": "supersede",
            "status": "superseded-in-m10.14g",
            "acceptance_criterion": "Immutable typed tables, sections, report artifacts, adapters, renderers, exports, citations, reproducibility metadata, and safe file output preserve applicable presentation behavior without accepting legacy nested dictionaries.",
            "rationale": "One mutable object dispatches by test-name substrings, recomputes graph structure from component ids, imports pandas and Plotly eagerly, embeds wall-clock paths, and recursively deletes report directories. Explicit typed adapters and output operations replace that unsafe catch-all API.",
        },
        "tests/unit/cipher_modules/report_test.py": {
            "milestone_owner": "M10.14a",
            "v5_destination": "next/tests/unit/test_presentation_contracts.py; next/tests/unit/test_presentation_tables.py; next/tests/unit/test_presentation_adapters.py; next/tests/unit/test_presentation_exports.py; next/tests/unit/test_presentation_files.py; next/tests/unit/test_presentation_plots.py",
            "prerequisites": ["M10.14a"],
            "disposition": "supersede",
            "status": "superseded-in-m10.14g",
            "acceptance_criterion": "Fixed typed trail, avalanche, component, statistical, neural, continuous, text-export, optional-plot, and safe-file evidence covers every retained report behavior without solver execution or pickle caches.",
            "rationale": "The legacy tests execute analyses while testing presentation, cache mutable result dictionaries with pickle, accept implicit current-directory output, and assert only that plotting methods were called. M10.14 uses fixed typed inputs and structural output assertions.",
        },
        "claasp/cipher_modules/statistical_tests/nist_statistical_tests_report.py": {
            "milestone_owner": "M10.14a",
            "v5_destination": "next/src/claasp_next/presentation; next/src/claasp_next/drivers/renderers",
            "prerequisites": ["M10.12d"],
            "disposition": "supersede",
            "status": "superseded-in-m10.14g",
            "acceptance_criterion": "NIST typed rows retain names, bins, p-values, proportions, unavailable states, dataset identity, and tool provenance in dependency-free tables plus explicitly requested optional plots and safe exports.",
            "rationale": "M10.12 owns parsing and execution. M10.14 supersedes this mutable, Matplotlib-importing, timestamped report generator with typed presentation over NISTFinalReport and StatisticalTestRun.",
        },
        "tests/unit/cipher_modules/statistical_tests/nist_statistical_tests_report_test.py": {
            "milestone_owner": "M10.14a",
            "v5_destination": "next/tests/unit/test_presentation_adapters.py; next/tests/unit/test_presentation_plots.py; next/tests/unit/test_presentation_files.py",
            "prerequisites": ["M10.12d", "M10.14a"],
            "disposition": "supersede",
            "status": "superseded-in-m10.14g",
            "acceptance_criterion": "Committed NIST fixtures and fixed synthetic unavailable rows verify complete table data, deterministic aggregate series, headless figure structure, UTF-8 output, extensions, and overwrite policy.",
            "rationale": "The legacy smoke test checks only that files exist for a two-row mutable dictionary. Typed parser fixtures provide stronger fixed evidence and do not regenerate NIST-format scientific artifacts as a presentation side effect.",
        },
    }
)


_CMS_REPLACEMENTS = {
    "cms_cipher_model": "next/src/claasp_next/representations/constraints/sat/lowering.py",
    "cms_xor_linear_model": "next/src/claasp_next/representations/constraints/smt/speck.py",
    "cms_xor_differential_model": "next/src/claasp_next/representations/constraints/cp/trails.py",
    "cms_bitwise_deterministic_truncated_xor_differential_model": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
}
MIGRATION_OVERRIDES["tests/unit/cipher_modules/models/sat/sat_model_test.py"] = {
    "v5_destination": "next/tests/integration/test_minizinc_integration.py",
    "prerequisites": [],
    "disposition": "supersede",
    "status": "superseded-in-m10.8d",
    "acceptance_criterion": "Retain the zero-key Speck-3 0x00400000 -> 0x8000840A weight-3 witness, equality/inequality SAT/UNSAT boundary scenarios, and exact/truncated mixed-component feasibility; replace incidental names and mutable counter strings with shared invariants.",
    "rationale": "The fixed weight-3 witness and complete differential boundary equality/inequality SAT/UNSAT scenarios are ported through native CP constraints and independent decoding. Typed exact-prefix/truncated-suffix composition replaces the mixed Speck method-name dictionary and independently checks feasibility. Unconstrained TEA/Simon assignment names, counter internals, and mutable solver registries are representation smoke tests, not fixed scientific values; existing typed Boolean/Word witness and real-solver tests replace them while catalogue parity stays owned by M10.9d.",
}
for _module, _destination in _CMS_REPLACEMENTS.items():
    MIGRATION_OVERRIDES[f"claasp/cipher_modules/models/sat/cms_models/{_module}.py"] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared graph semantics and explicit solver drivers replace CMS-specific model subclasses; fixed CMS test evidence is separately retained.",
        "rationale": "Native XOR strings are an encoding optimization, not a distinct cryptanalytic meaning. No CryptoMiniSat execution or full catalogue coverage is claimed by this replacement; reusable missing component semantics remain owned by M10.9c.",
    }

_CMS_TEST_REPLACEMENTS = {
    "cms_cipher_model_test": (
        "migrate",
        "next/tests/integration/test_z3_integration.py",
        "Preserve the complete Speck32/64-22 vector 0x6574694C, 0x1918111009080100 -> 0xA86842F2 with real solving and independent evaluation.",
    ),
    "cms_xor_linear_model_test": (
        "migrate",
        "next/tests/integration/test_speck_trail_enumeration.py",
        "Prove Speck32/64-4 bound 2 UNSAT and bound 3 SAT; independently recount all correlations and wiring.",
    ),
    "cms_xor_differential_model_test": (
        "supersede",
        "next/tests/unit/test_cms_inventory_parity.py",
        "Supported full Speck32/64 differential construction is nonempty; changing the weight bound retains exact round relations and changes the explicit bound.",
    ),
    "cms_deterministic_truncated_xor_differential_model_test": (
        "supersede",
        "next/tests/unit/test_truncated_differences.py",
        "Typed deterministic-truncated modular-add semantics and Speck propagation replace an assertion-free construction smoke test.",
    ),
}
for _module, (_disposition, _destination, _criterion) in _CMS_TEST_REPLACEMENTS.items():
    MIGRATION_OVERRIDES[f"tests/unit/cipher_modules/models/sat/cms_models/{_module}.py"] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": _disposition,
        "status": "migrated-in-m10.8d" if _disposition == "migrate" else "superseded-in-m10.8d",
        "acceptance_criterion": _criterion,
        "rationale": None
        if _disposition == "migrate"
        else "Mutable CMS constraint counts and construction-only smoke tests are replaced by explicit immutable representation and shared-semantic invariants.",
    }


_M10_9C2_SUPERSEDED_SOURCES = {
    "claasp/DTOs/component_state.py": (
        "next/src/claasp_next/graph/port.py",
        "Immutable Port and Selection objects replace mutable component-id/bit-position state.",
    ),
    "claasp/DTOs/power_of_2_word_based_dto.py": (
        "next/src/claasp_next/domains/word.py; next/src/claasp_next/graph/value_type.py",
        "Typed Word domains and ValueType replace a mutable optional word-size probe DTO.",
    ),
    "claasp/component.py": (
        "next/src/claasp_next/graph/component.py; next/src/claasp_next/semantics; next/src/claasp_next/representations/constraints",
        "The immutable component contract is separate from semantic providers and backend representations; legacy backend methods, generated identifiers, and printing are not component behavior.",
    ),
    "claasp/input.py": (
        "next/src/claasp_next/graph/port.py",
        "Validated immutable logical-unit selections replace parallel mutable id-link and bit-position arrays.",
    ),
    "claasp/round.py": (
        "next/src/claasp_next/graph/round.py; next/src/claasp_next/graph/primitive.py",
        "Primitive owns validated append-only graph construction; mutable reordering, removal, printing, and dictionary serialization belong to M10.10/M10.14/M10.15.",
    ),
    "claasp/rounds.py": (
        "next/src/claasp_next/graph/round.py; next/src/claasp_next/graph/primitive.py",
        "Primitive and Round provide typed ownership and deterministic order without legacy mutable graph indexes or serialization helpers.",
    ),
    "claasp/name_mappings.py": (
        "next/src/claasp_next/graph; next/src/claasp_next/primitives; next/src/claasp_next/semantics",
        "Typed classes and the fixed-length taxonomy replace global free-form strings; historical names remain only in inventory evidence.",
    ),
    "claasp/utils/utils.py": (
        "next/src/claasp_next/utils/integers.py; next/src/claasp_next/utils/layouts.py; next/src/claasp_next/utils/sequences.py; next/src/claasp_next/analysis",
        "The mixed Sage/NumPy/presentation module is split into small typed helpers and existing analysis modules. Fixed byte-layout, sign, distance, and exact-integer results are preserved where semantically applicable; random and printing details are not authoring contracts.",
    ),
}
for _path, (_destination, _rationale) in _M10_9C2_SUPERSEDED_SOURCES.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c2",
        "acceptance_criterion": "Typed Sage-independent graph and helper contracts preserve applicable semantic results without legacy mutable state, generated strings, or presentation behavior.",
        "rationale": _rationale,
    }

MIGRATION_OVERRIDES.update(
    {
        "claasp/utils/integer.py": {
            "v5_destination": "next/src/claasp_next/utils/integers.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.9c2",
            "acceptance_criterion": "Dependency-free bitmask and little-endian bit expansion reproduce fixed legacy results with explicit width validation.",
            "rationale": None,
        },
        "claasp/utils/integer_functions.py": {
            "v5_destination": "next/src/claasp_next/utils/integers.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.9c2",
            "acceptance_criterion": "Integer/byte/word conversions and both rotation directions round-trip under explicit widths and byte orders.",
            "rationale": None,
        },
        "claasp/utils/sequence_operations.py": {
            "v5_destination": "next/src/claasp_next/utils/sequences.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.9c2",
            "acceptance_criterion": "List and tuple rotations/shifts preserve the legacy values and concrete sequence type without importing Sage.",
            "rationale": None,
        },
        "claasp/utils/templates.py": {
            "v5_destination": "removed: report templates belong to M10.14 presentation rather than the component-authoring layer",
            "prerequisites": [],
            "disposition": "remove",
            "status": "removed-in-m10.9c2",
            "acceptance_criterion": "The component/authoring package imports no Jinja or report template machinery.",
            "rationale": "The untested mutable builder renders legacy reports and carries no component semantics; typed report presentation is explicitly owned by M10.14.",
        },
        "claasp/utils/sage_scripts.py": {
            "v5_destination": "removed: typed catalogue discovery is owned by M10.9f",
            "prerequisites": [],
            "disposition": "remove",
            "status": "removed-in-m10.9c2",
            "acceptance_criterion": "No filename/class-name heuristic, YAML dependency, or legacy taxonomy is retained in component authoring.",
            "rationale": "Dynamic folder scanning and class-name matching conflict with the committed typed catalogue required by M10.9f; the remaining identifier/scenario strings have no fixed tests or reusable mathematical semantics.",
        },
        "tests/unit/component_test.py": {
            "v5_destination": "next/tests/unit/test_typed_graph.py; next/tests/unit/test_propagation_problem.py",
            "prerequisites": [],
            "disposition": "supersede",
            "status": "superseded-in-m10.9c2",
            "acceptance_criterion": "Typed components validate graph ownership while semantic registries and representations reject unsupported operations explicitly.",
            "rationale": "Backend-method aliases and their exact NotImplementedError strings came from the removed component/backend monolith; v5 tests the separated contracts directly.",
        },
        "tests/unit/utils/integer_test.py": {
            "v5_destination": "next/tests/unit/test_authoring_utilities.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.9c2",
            "acceptance_criterion": "The exact 4-/32-bit masks and 0x67452301 little-endian bit vector are independently checked.",
            "rationale": None,
        },
        "tests/unit/utils/sequence_operations_test.py": {
            "v5_destination": "next/tests/unit/test_authoring_utilities.py",
            "prerequisites": [],
            "disposition": "migrate",
            "status": "migrated-in-m10.9c2",
            "acceptance_criterion": "Legacy list/tuple rotation and boundary shift values pass without Sage; arbitrary fill values cover symbolic-sequence use.",
            "rationale": None,
        },
        "tests/unit/utils/utils_test.py": {
            "v5_destination": "next/tests/unit/test_authoring_utilities.py; next/tests/unit/test_avalanche_analysis.py; next/tests/unit/test_continuous_heuristics.py",
            "prerequisites": [],
            "disposition": "supersede",
            "status": "superseded-in-m10.9c2",
            "acceptance_criterion": "Byte layout and exact-integer fixed results remain executable; analysis semantics retain sign/distance evidence under their achieved owners.",
            "rationale": "Pretty-print/file smoke tests and unseeded random point shapes are presentation or incidental implementation details, while avalanche and continuous evidence already use typed deterministic results.",
        },
    }
)

_M10_9C3_SOURCE_DISPOSITIONS = {
    "claasp/components/constant_component.py": (
        "migrate",
        "next/src/claasp_next/components/structural/constant.py",
        None,
    ),
    "claasp/components/permutation_component.py": (
        "migrate",
        "next/src/claasp_next/components/structural/permutation.py",
        None,
    ),
    "claasp/components/reverse_component.py": (
        "supersede",
        "next/src/claasp_next/components/structural/permutation.py",
        "Reverse is the ordinary domain-neutral permutation with reversed positions; a separate class would duplicate semantics.",
    ),
    "claasp/components/word_permutation_component.py": (
        "supersede",
        "next/src/claasp_next/components/structural/permutation.py",
        "Typed selections already operate on logical words, so the generic permutation carries the complete behavior without a bit-size side channel.",
    ),
    "claasp/components/cipher_output_component.py": (
        "supersede",
        "next/src/claasp_next/graph/primitive.py; next/src/claasp_next/annotations/traces.py",
        "A declared Primitive output is a graph boundary, not an operation with duplicated backend encodings.",
    ),
    "claasp/components/intermediate_output_component.py": (
        "supersede",
        "next/src/claasp_next/annotations/traces.py; next/src/claasp_next/components/structural/identity.py",
        "Every typed component output is directly traceable; Identity provides an explicit stable semantic boundary when an author needs one.",
    ),
}
for _path, (_disposition, _destination, _rationale) in _M10_9C3_SOURCE_DISPOSITIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": _disposition,
        "status": f"{_disposition}d-in-m10.9c3"
        if _disposition == "supersede"
        else "migrated-in-m10.9c3",
        "acceptance_criterion": "Domain-neutral structural evaluation, graph boundaries, and scalar/batch behavior preserve applicable values independently of backend strings.",
        "rationale": _rationale,
    }

_M10_9C3_TEST_DESTINATIONS = {
    "tests/unit/components/constant_component_test.py": "next/tests/unit/test_structural_evaluation.py",
    "tests/unit/components/permutation_component_test.py": "next/tests/unit/test_structural_evaluation.py; next/tests/unit/test_conversion_components.py",
    "tests/unit/components/reverse_component_test.py": "next/tests/unit/test_conversion_components.py",
    "tests/unit/components/word_permutation_component_test.py": "next/tests/unit/test_conversion_components.py",
    "tests/unit/components/cipher_output_component_test.py": "next/tests/unit/test_typed_graph.py; next/tests/unit/test_neural_projections.py",
    "tests/unit/components/intermediate_output_component_test.py": "next/tests/unit/test_neural_projections.py; next/tests/unit/test_structural_evaluation.py",
}
for _path, _destination in _M10_9C3_TEST_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c3",
        "acceptance_criterion": "Typed structural values, validation, graph boundaries, and trace projections preserve semantic assertions with independent scalar/batch checks.",
        "rationale": "Exact SAT/SMT/CP/MILP strings, legacy descriptions, generated identifiers, and mutable wrapper aliases are representation details; shared v5 lowerings consume typed components instead.",
    }

_M10_9C4_SOURCE_DESTINATIONS = {
    "claasp/components/and_component.py": "next/src/claasp_next/components/word/bitwise_and.py; next/src/claasp_next/semantics/cryptanalysis/bitwise.py",
    "claasp/components/not_component.py": "next/src/claasp_next/components/word/bitwise_not.py",
    "claasp/components/or_component.py": "next/src/claasp_next/components/word/bitwise_or.py",
    "claasp/components/sbox_component.py": "next/src/claasp_next/components/substitution; next/src/claasp_next/semantics/cryptanalysis/trails.py",
    "claasp/components/xor_component.py": "next/src/claasp_next/components/word/xor.py",
}
for _path, _destination in _M10_9C4_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.9c4",
        "acceptance_criterion": "Typed logical/substitution components have exhaustive small-domain or fixed lookup checks, scalar/batch parity, and shared semantics where cryptanalytic relations apply.",
        "rationale": None,
    }
MIGRATION_OVERRIDES["claasp/components/multi_input_non_linear_logical_operator_component.py"] = {
    "v5_destination": "next/src/claasp_next/components/word/bitwise_and.py; next/src/claasp_next/components/word/bitwise_or.py",
    "prerequisites": [],
    "disposition": "supersede",
    "status": "superseded-in-m10.9c4",
    "acceptance_criterion": "Explicit immutable AND and OR classes validate homogeneous operands and use shared evaluator/semantic dispatch.",
    "rationale": "A backend-bearing mutable superclass adds no mathematical operation; shared validation plus explicit component types replace its operand-count inference and delegated constraint strings.",
}

_M10_9C4_TEST_DESTINATIONS = {
    "tests/unit/components/and_component_test.py": "next/tests/unit/test_logical_components.py; next/tests/unit/test_bitwise_transition_semantics.py",
    "tests/unit/components/multi_input_non_linear_logical_operator_component_test.py": "next/tests/unit/test_logical_components.py",
    "tests/unit/components/not_component_test.py": "next/tests/unit/test_logical_components.py",
    "tests/unit/components/or_component_test.py": "next/tests/unit/test_logical_components.py",
    "tests/unit/components/sbox_component_test.py": "next/tests/unit/test_sbox.py; next/tests/unit/test_bit_vector_sbox.py; next/tests/unit/test_trail_semantics.py; next/tests/unit/test_sbox_milp_relation.py; next/tests/unit/test_sbox_undisturbed.py",
    "tests/unit/components/xor_component_test.py": "next/tests/unit/test_logical_components.py; next/tests/unit/test_word_components.py; next/tests/unit/test_wordwise_relation_tables.py",
}
for _path, _destination in _M10_9C4_TEST_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c4",
        "acceptance_criterion": "Concrete truth tables, exact S-box DDT/LAT/undisturbed relations, symbolic ANFs, and typed validation preserve all applicable semantic results.",
        "rationale": "Backend variable names, serialized inequalities, mutable probability maps, generated code fragments, and exact constraint ordering are not component semantics and are covered only at their representation owners where applicable.",
    }

_M10_9C5_SOURCE_DESTINATIONS = {
    "claasp/components/idea_modmul_component.py": "next/src/claasp_next/components/word/idea_multiply.py",
    "claasp/components/modadd_component.py": "next/src/claasp_next/components/word/modular_add.py",
    "claasp/components/modmul_component.py": "next/src/claasp_next/components/word/modular_multiply.py",
    "claasp/components/modsub_component.py": "next/src/claasp_next/components/word/modular_subtract.py",
    "claasp/components/rotate_component.py": "next/src/claasp_next/components/word/rotate.py",
    "claasp/components/shift_component.py": "next/src/claasp_next/components/word/shift.py",
    "claasp/components/variable_rotate_component.py": "next/src/claasp_next/components/word/variable_rotate.py",
    "claasp/components/variable_shift_component.py": "next/src/claasp_next/components/word/variable_shift.py",
}
for _path, _destination in _M10_9C5_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "migrate",
        "status": "migrated-in-m10.9c5",
        "acceptance_criterion": "Typed word operations match independently computed exhaustive small-width arithmetic and scalar/transposed-batch evaluation.",
        "rationale": None,
    }
MIGRATION_OVERRIDES["claasp/components/modular_component.py"] = {
    "v5_destination": "next/src/claasp_next/components/word/modular_add.py; next/src/claasp_next/components/word/modular_subtract.py; next/src/claasp_next/components/word/modular_multiply.py",
    "prerequisites": [],
    "disposition": "supersede",
    "status": "superseded-in-m10.9c5",
    "acceptance_criterion": "Explicit immutable operation classes replace string-selected modular behavior and inferred operand counts.",
    "rationale": "The legacy superclass combines backend encodings for distinct arithmetic operations; typed component classes retain the arithmetic and shared validation without generated constraint syntax.",
}

_M10_9C5_TEST_DESTINATIONS = {
    "tests/unit/components/idea_modmul_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/modadd_component_test.py": "next/tests/unit/test_word_arx_components.py; next/tests/unit/test_word_components.py; next/tests/unit/test_arx_trail_search.py",
    "tests/unit/components/modmul_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/modsub_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/modular_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/rotate_component_test.py": "next/tests/unit/test_word_arx_components.py; next/tests/unit/test_word_components.py",
    "tests/unit/components/shift_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/variable_rotate_component_test.py": "next/tests/unit/test_word_arx_components.py",
    "tests/unit/components/variable_shift_component_test.py": "next/tests/unit/test_word_arx_components.py",
}
for _path, _destination in _M10_9C5_TEST_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c5",
        "acceptance_criterion": "Exhaustive three-bit arithmetic, fixed word-motion values, boundary behavior, validation, and scalar/batch parity preserve applicable semantics.",
        "rationale": "Generated backend strings, temporary carry names, component identifiers, mutable sign dictionaries, and generated code fragments are representation or implementation details rather than arithmetic evidence.",
    }

_M10_9C6_SOURCE_DESTINATIONS = {
    "claasp/components/linear_layer_component.py": "next/src/claasp_next/components/algebraic/linear_map.py; next/src/claasp_next/domains",
    "claasp/components/mix_column_component.py": "next/src/claasp_next/components/algebraic/linear_map.py; next/src/claasp_next/domains/binary_extension_field.py; next/src/claasp_next/utils/finite_fields.py",
}
for _path, _destination in _M10_9C6_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c6",
        "acceptance_criterion": "A row-major typed LinearMap evaluates binary and extension-field matrices without Sage and validates every coefficient against its domain.",
        "rationale": "A separate MixColumn operation duplicates linear-map semantics once the field modulus and logical word size are carried by BinaryExtensionField; backend constraints and branch-number analysis belong to representations and analyses.",
    }

_M10_9C6_TEST_DESTINATIONS = {
    "tests/unit/components/linear_layer_component_test.py": "next/tests/unit/test_linear_layer_components.py; next/tests/unit/test_algebraic_evaluation.py",
    "tests/unit/components/mix_column_component_test.py": "next/tests/unit/test_linear_layer_components.py; next/tests/unit/test_aes.py",
}
for _path, _destination in _M10_9C6_TEST_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c6",
        "acceptance_criterion": "Complete binary and GF(2^4) checks, the published AES MixColumns column, typed validation, and scalar/batch parity preserve the mathematical transformation.",
        "rationale": "Sage polynomial rendering, generated backend clauses, variable order, mutable component-analysis caches, and MiniZinc table construction are not reusable linear-layer semantics.",
    }

MIGRATION_OVERRIDES["claasp/components/fsr_component.py"] = {
    "v5_destination": "next/src/claasp_next/components/feedback/feedback_register.py",
    "prerequisites": [],
    "disposition": "migrate",
    "status": "migrated-in-m10.9c7",
    "acceptance_criterion": "Immutable term/register descriptors evaluate binary, clock-controlled, multi-clock, and typed binary-field word feedback without Sage.",
    "rationale": None,
}
MIGRATION_OVERRIDES["tests/unit/components/fsr_component_test.py"] = {
    "v5_destination": "next/tests/unit/test_feedback_register.py",
    "prerequisites": [],
    "disposition": "supersede",
    "status": "superseded-in-m10.9c7",
    "acceptance_criterion": "Complete binary truth tables, conditional-clock behavior, field-word values, iterative clocks, validation, and scalar/batch parity preserve the tested feedback semantics.",
    "rationale": "Exact Sage polynomial variable names and rendering are incidental; exhaustive concrete truth maps independently establish the same binary and field-word transformations.",
}

# M10.11 separates component-property semantics, optional computation drivers,
# and presentation. These are the only two legacy records owned by the
# milestone; solver-shaped wordwise branch-number records retain their closed
# M10.8d disposition.
MIGRATION_OVERRIDES.update(
    {
        "claasp/cipher_modules/component_analysis_tests.py": {
            "milestone_owner": "M10.11a",
            "v5_destination": "next/src/claasp_next/analysis/component_properties.py; next/src/claasp_next/drivers/analysis; M10.14 presentation layer",
            "prerequisites": ["M10.9f6", "M10.10"],
            "disposition": "migrate",
            "status": "migrated-in-m10.11g",
            "acceptance_criterion": "M10.11 returns immutable typed component-property results with explicit applicability and exactness; fixed S-box, Boolean, matrix, branch-number, and feedback evidence passes independently, while Matplotlib presentation remains assigned to M10.14.",
            "rationale": "Typed Sage-independent analysis contracts and explicit optional drivers replace the nested legacy report dictionary, component-id identity, default solver selection, and mutable caches. Plotting is assigned to M10.14.",
        },
        "tests/unit/cipher_modules/component_analysis_tests_test.py": {
            "milestone_owner": "M10.11a",
            "v5_destination": "next/tests/unit/test_component_properties.py; next/tests/integration/test_component_analysis_minizinc.py; M10.14 presentation tests",
            "prerequisites": ["M10.11a", "M10.9f6"],
            "disposition": "supersede",
            "status": "superseded-in-m10.11g",
            "acceptance_criterion": "Independent fixed evidence covers exact S-box, Boolean, matrix, branch-number, feedback, driver, applicability, and exactness contracts; plotting assertions remain assigned to M10.14.",
            "rationale": "Typed v5 tests preserve mathematical evidence. Legacy helper internals and Sage/MiniZinc method-consistency tests become contract and driver tests; the radar-chart assertion belongs to M10.14.",
        },
    }
)

# M10.10 owns immutable primitive-graph transformations. These entries make
# the previously generic planning records concrete before implementation; the
# achieved M10.8 model records that happened to call legacy mutation helpers
# retain their existing owners and destinations.
M10_10_OVERRIDES = {
    "claasp/cipher_modules/graph_generator.py": {
        "milestone_owner": "M10.10a",
        "v5_destination": "next/src/claasp_next/transformations/traversal.py",
        "prerequisites": ["M10.9f6"],
        "rationale": "A standard-library typed dependency index replaces NetworkX graphs and legacy dictionaries while preserving predecessor, descendant, and split-boundary semantics across components and structural bindings.",
        "acceptance_criterion": "Deterministic typed traversal and split-boundary closure match preserved graph-source and edge evidence without importing NetworkX.",
    },
    "tests/unit/cipher_modules/graph_generator_test.py": {
        "milestone_owner": "M10.10a",
        "v5_destination": "next/tests/unit/test_transformation_traversal.py; next/tests/unit/test_graph_slicing.py",
        "prerequisites": ["M10.9f6"],
        "rationale": "Exact legacy node ids and the malformed descendant edge shape are incidental; source membership, dependency direction, closure, and validated slices are preserved.",
        "acceptance_criterion": "Typed predecessor/descendant closures and top/bottom splits preserve the applicable ChaCha and Speck dependency assertions.",
    },
    "claasp/cipher_modules/inverse_cipher.py": {
        "milestone_owner": "M10.10c",
        "v5_destination": "next/src/claasp_next/transformations/inversion.py; next/src/claasp_next/transformations/inverse_rules.py",
        "prerequisites": ["M10.10b"],
        "rationale": "Typed component inverse rules and immutable graph reconstruction replace the Sage-backed mutable bit-equivalence engine; retained auxiliary inputs and partial inverses are explicit contracts.",
        "acceptance_criterion": "Supported complete and partial inversions round-trip under independent scalar evaluation and every stall reports its exact typed reason.",
    },
    "claasp/editor.py": {
        "milestone_owner": "M10.10e",
        "v5_destination": "next/src/claasp_next/transformations/slicing.py; next/src/claasp_next/transformations/editing.py",
        "prerequisites": ["M10.10b", "M10.10d"],
        "rationale": "Validated graph reconstruction replaces deep-copy mutation. Existing v5 authoring already supersedes legacy add-component helpers; M10.10 preserves slicing, round reduction, key-schedule removal, orphan pruning, and reorder-only inlining.",
        "acceptance_criterion": "Every retained editor operation returns a new validated graph, leaves its source unchanged, and preserves independently evaluated semantics at its declared boundaries.",
    },
    "tests/unit/editor_test.py": {
        "milestone_owner": "M10.10e",
        "v5_destination": "next/tests/unit/test_graph_editing.py",
        "prerequisites": ["M10.10b", "M10.10d"],
        "rationale": "Mutable dictionaries, generated component ids, and add-without-round printing are not v5 contracts; key-schedule boundaries and reorder-only semantic equivalence are retained.",
        "acceptance_criterion": "Round/key transformations and reorder inlining have validated graphs, explicit boundaries, unchanged sources, and scalar semantic parity.",
    },
    "claasp/compound_xor_differential_cipher.py": {
        "milestone_owner": "M10.10f",
        "v5_destination": "next/src/claasp_next/transformations/paired.py",
        "prerequisites": ["M10.10e"],
        "rationale": "An immutable typed paired graph plus XOR observations replaces deep-copy mutation and `_pair1`/`_pair2` generated ids; solver lowering remains outside the transformation.",
        "acceptance_criterion": "Paired evaluation and XOR observations equal two independent primitive evaluations for single-key and related-key inputs.",
    },
    "tests/unit/compound_xor_differential_cipher_test.py": {
        "milestone_owner": "M10.10f",
        "v5_destination": "next/tests/unit/test_paired_xor_transformation.py; next/tests/integration/test_paired_constraints.py",
        "prerequisites": ["M10.10e"],
        "rationale": "The fixed compatible/incompatible Speck boundary evidence is retained through typed paired semantics; legacy SAT variable spelling and mutable copied-graph ids are superseded.",
        "acceptance_criterion": "Fixed single-key and related-key Speck observations agree with independent paired evaluation, with solver-facing feasibility checked only in the affected integration group.",
    },
    "claasp/cipher.py": {
        "milestone_owner": "M10.10d",
        "v5_destination": "next/src/claasp_next/graph/primitive.py; next/src/claasp_next/transformations",
        "prerequisites": ["M10.10c"],
        "rationale": "M10.10 owns only the legacy inversion, partial-graph, round-reduction, key-schedule, and paired-transformation entry points. Evaluation, reporting, serialization, code generation, and remaining helpers retain their recorded milestone ownership.",
        "acceptance_criterion": "Concise primitive-oriented transformation entry points return validated immutable graphs and pass their focused public doctests and semantic tests.",
    },
    "tests/unit/cipher_test.py": {
        "milestone_owner": "M10.10d",
        "v5_destination": "next/tests/unit/test_primitive_inversion.py; next/tests/unit/test_graph_slicing.py; next/tests/unit/test_graph_editing.py",
        "prerequisites": ["M10.10c"],
        "rationale": "M10.10 owns the direct primitive inversion and partial-graph assertions in this mixed legacy module. Other test functions remain evidence for their existing analysis, execution, presentation, or compiler milestones.",
        "acceptance_criterion": "Applicable direct inversion and partial-graph tests are preserved by independent scalar round trips, typed boundaries, and dangling-dependency validation.",
    },
}
M10_10_FINAL_DISPOSITIONS = {
    "claasp/cipher_modules/graph_generator.py": ("migrate", "migrated-in-m10.10b"),
    "tests/unit/cipher_modules/graph_generator_test.py": ("supersede", "superseded-in-m10.10b"),
    "claasp/cipher_modules/inverse_cipher.py": ("migrate", "migrated-in-m10.10d"),
    "claasp/editor.py": ("supersede", "superseded-in-m10.10e"),
    "tests/unit/editor_test.py": ("supersede", "superseded-in-m10.10e"),
    "claasp/compound_xor_differential_cipher.py": ("supersede", "superseded-in-m10.10f"),
    "tests/unit/compound_xor_differential_cipher_test.py": ("supersede", "superseded-in-m10.10f"),
    "claasp/cipher.py": ("supersede", "superseded-in-m10.10d"),
    "tests/unit/cipher_test.py": ("supersede", "superseded-in-m10.10d"),
}
for _path, (_disposition, _status) in M10_10_FINAL_DISPOSITIONS.items():
    M10_10_OVERRIDES[_path].update(
        {
            "disposition": _disposition,
            "status": _status,
        }
    )
MIGRATION_OVERRIDES.update(M10_10_OVERRIDES)

_M10_9C8_SOURCE_DESTINATIONS = {
    "claasp/components/shift_rows_component.py": "next/src/claasp_next/components/permutation/layers.py; next/src/claasp_next/components/structural/permutation.py",
    "claasp/components/sigma_component.py": "next/src/claasp_next/components/permutation/layers.py; next/src/claasp_next/components/algebraic/linear_map.py",
    "claasp/components/theta_gaston_component.py": "next/src/claasp_next/components/permutation/layers.py; next/src/claasp_next/components/algebraic/linear_map.py",
    "claasp/components/theta_keccak_component.py": "next/src/claasp_next/components/permutation/layers.py; next/src/claasp_next/components/algebraic/linear_map.py",
    "claasp/components/theta_xoodoo_component.py": "next/src/claasp_next/components/permutation/layers.py; next/src/claasp_next/components/algebraic/linear_map.py",
}
for _path, _destination in _M10_9C8_SOURCE_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c8",
        "acceptance_criterion": "Dependency-free constructors compose typed Permutation or LinearMap components and preserve fixed Sigma/Gaston/Keccak/Xoodoo values.",
        "rationale": "Dedicated backend-bearing subclasses duplicate generic permutation or binary-linear semantics; pure constructors retain published structure without Sage matrices, pickle caches, or operation-specific lowering methods.",
    }

_M10_9C8_TEST_DESTINATIONS = {
    "tests/unit/components/shift_rows_component_test.py": "next/tests/unit/test_permutation_layers.py",
    "tests/unit/components/sigma_component_test.py": "next/tests/unit/test_permutation_layers.py",
    "tests/unit/components/theta_gaston_component_test.py": "next/tests/unit/test_permutation_layers.py",
    "tests/unit/components/theta_keccak_component_test.py": "next/tests/unit/test_permutation_layers.py",
    "tests/unit/components/theta_xoodoo_component_test.py": "next/tests/unit/test_permutation_layers.py",
}
for _path, _destination in _M10_9C8_TEST_DESTINATIONS.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": "supersede",
        "status": "superseded-in-m10.9c8",
        "acceptance_criterion": "Domain-neutral row permutation, legacy Sigma output, independently derived Keccak diffusion, and fixed Xoodoo/Gaston prefixes are executable.",
        "rationale": "Component identifiers, matrix dimensions, generated clauses, and exact constraint ordering do not add semantics beyond the tested permutation and linear maps.",
    }

# M11a resolves the final broad source/test records whose behavior was already
# delivered by focused v5 milestones but whose generated inventory retained a
# provisional destination.  Each row names concrete release evidence instead
# of claiming that an entire directory is its replacement.
_M11A_FINAL_OVERRIDES = {
    "claasp/catalog.py": (
        "next/src/claasp_next/catalogue/catalogue.py; next/src/claasp_next/catalogue/records.py",
        "migrate",
        "Typed immutable catalogue records and dependency-free discovery replace AST scanning, pandas rendering, and eager solver probing.",
    ),
    "claasp/cipher_modules/algebraic_tests.py": (
        "next/src/claasp_next/analysis/algebraic.py; next/src/claasp_next/representations/constraints/polynomial",
        "migrate",
        "Typed algebraic analysis and polynomial representations preserve the supported claims without Sage-bound mutable test objects.",
    ),
    "claasp/cipher_modules/avalanche_tests.py": (
        "next/src/claasp_next/analysis/avalanche.py",
        "migrate",
        "Seeded immutable avalanche analysis replaces NumPy/Matplotlib-coupled mutable reporting while preserving measured criteria.",
    ),
    "claasp/cipher_modules/neural_network_tests.py": (
        "next/src/claasp_next/analysis/neural.py; next/src/claasp_next/analysis/neural_experiments.py",
        "migrate",
        "Framework-neutral experiment contracts and optional drivers replace direct TensorFlow/Keras ownership in the core API.",
    ),
    "claasp/cipher_modules/statistical_tests/dataset_generator.py": (
        "next/src/claasp_next/analysis/datasets.py; next/src/claasp_next/analysis/statistical_datasets.py",
        "migrate",
        "Deterministic typed dataset families replace the mutable NumPy generator and make seeds and sample shapes explicit.",
    ),
    "claasp/cipher_modules/statistical_tests/dieharder_statistical_tests.py": (
        "next/src/claasp_next/drivers/statistical/dieharder.py; next/src/claasp_next/analysis/statistical_results.py",
        "migrate",
        "A bounded external driver and immutable parsed reports separate Dieharder execution from presentation.",
    ),
    "claasp/cipher_modules/statistical_tests/nist_statistical_tests.py": (
        "next/src/claasp_next/drivers/statistical/nist.py; next/src/claasp_next/analysis/statistical_results.py",
        "migrate",
        "A bounded NIST STS driver and immutable report contracts replace cwd writes, timing state, and plotting concerns.",
    ),
    "claasp/cipher_modules/statistical_tests/nist_sts.py": (
        "next/src/claasp_next/drivers/statistical/nist.py",
        "supersede",
        "The partial Python reimplementation is not a release oracle; v5 executes the pinned upstream NIST STS binary behind a typed boundary.",
    ),
    "claasp/cipher_modules/tester.py": (
        "next/src/claasp_next/representations/execution/scalar.py; next/tests/unit/test_legacy_cipher_parity.py",
        "supersede",
        "Public scalar evaluation plus fixed semantic evidence replace random print-oriented helpers and arbitrary reference-code execution.",
    ),
    "tests/benchmark/cipher_test.py": (
        "next/tests/unit/test_batch_evaluation.py; next/tests/unit/test_avalanche_analysis.py; next/tests/unit/test_native_source.py",
        "supersede",
        "Focused scalar, batch, avalanche, and bounded native tests replace timing-sensitive mixed benchmarks.",
    ),
    "tests/benchmark/sat_xor_differential_model_test.py": (
        "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_word_differential_smt.py",
        "supersede",
        "Typed fixed/maximum-weight formula and enumeration evidence replaces mutable SAT helper benchmarks.",
    ),
    "tests/benchmark/statistical_tests_test.py": (
        "next/tests/unit/test_statistical_datasets.py; next/tests/integration/test_nist_integration.py",
        "supersede",
        "Deterministic dataset tests and bounded NIST integration replace environment-sensitive statistical benchmarks.",
    ),
    "tests/unit/catalog_test.py": (
        "next/tests/unit/test_catalogue.py; next/tests/unit/test_catalogue_metadata.py",
        "supersede",
        "Typed catalogue query and metadata closure tests replace legacy AST, dataframe, and display-shape assertions.",
    ),
    "tests/unit/cipher_modules/avalanche_tests_test.py": (
        "next/tests/unit/test_avalanche_analysis.py",
        "supersede",
        "Seeded avalanche vectors and criteria are covered directly through the immutable analysis contract.",
    ),
    "tests/unit/cipher_modules/neural_network_tests_test.py": (
        "next/tests/unit/test_neural_contracts.py; next/tests/unit/test_neural_experiments.py; next/tests/integration/test_neural_driver_integration.py",
        "supersede",
        "Framework-neutral contracts, deterministic experiment plans, and isolated optional-driver integration replace direct Keras tests.",
    ),
    "tests/unit/cipher_modules/statistical_tests/dataset_generator_test.py": (
        "next/tests/unit/test_statistical_datasets.py; next/tests/unit/test_statistical_dataset_families.py",
        "supersede",
        "Seeded typed dataset-family evidence replaces mutable NumPy fixture comparisons.",
    ),
    "tests/unit/cipher_modules/statistical_tests/dieharder_statistical_tests_test.py": (
        "next/tests/unit/test_dieharder_driver.py; next/tests/integration/test_dieharder_integration.py",
        "supersede",
        "Parser diagnostics and isolated executable integration replace filesystem and chart side-effect assertions.",
    ),
    "tests/unit/cipher_modules/statistical_tests/nist_statistical_tests_test.py": (
        "next/tests/unit/test_nist_driver.py; next/tests/integration/test_nist_integration.py",
        "supersede",
        "Typed parser, manifest, timeout, and executable evidence replaces cwd report cleanup and plotting assertions.",
    ),
    "tests/unit/cipher_modules/statistical_tests/nist_sts_kat_test.py": (
        "next/tests/integration/test_nist_integration.py",
        "supersede",
        "The canonical image validates fixed NIST STS executable output rather than a separate partial Python implementation.",
    ),
    "tests/unit/cipher_modules/statistical_tests/nist_sts_test.py": (
        "next/tests/unit/test_nist_driver.py; next/tests/integration/test_nist_integration.py",
        "supersede",
        "Driver parsing and pinned upstream executable integration replace tests of the removed partial Python reimplementation.",
    ),
    "tests/unit/ciphers/toys/cipherfour_block_cipher_tests.py": (
        "next/tests/unit/test_toy_primitive_catalogue.py",
        "supersede",
        "Catalogue-wide construction and evaluation evidence covers CipherFour without stdout-oriented legacy assertions.",
    ),
    "tests/unit/ciphers/toys/heys_block_cipher_tests.py": (
        "next/tests/unit/test_toy_primitive_catalogue.py",
        "supersede",
        "Catalogue-wide construction and deterministic evaluation evidence covers the Heys teaching primitive.",
    ),
    "tests/unit/utils/scip_tpi_test.py": (
        "next/src/claasp_next/drivers/solvers/glpk.py; next/tests/integration/test_glpk_monomial_trails.py",
        "supersede",
        "The unsupported SCIP parallel-shell configuration is removed; the maintained open MILP boundary has typed GLPK execution evidence.",
    ),
}
for _path, (_destination, _disposition, _rationale) in _M11A_FINAL_OVERRIDES.items():
    MIGRATION_OVERRIDES[_path] = {
        "v5_destination": _destination,
        "prerequisites": ["M10.16", "M11.4"],
        "milestone_owner": "M11a",
        "disposition": _disposition,
        "status": f"{'migrated' if _disposition == 'migrate' else 'superseded'}-in-m11a",
        "acceptance_criterion": "Every named destination exists and the final bidirectional audit links the legacy record to shipped v5 behavior or reviewed removal.",
        "rationale": _rationale,
    }


def python_paths() -> list[Path]:
    return sorted(path for root in LEGACY_ROOTS for path in root.rglob("*.py"))


def _parse(path: Path) -> ast.Module:
    with warnings.catch_warnings():
        # Legacy MiniZinc source is embedded in Python strings containing
        # backslashes that are valid MiniZinc but deprecated Python escapes.
        warnings.simplefilter("ignore", (DeprecationWarning, SyntaxWarning))
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _public_entries(tree: ast.Module) -> list[str]:
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    ]


def _dependencies(tree: ast.Module) -> list[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return sorted(names)


def _test_entries(tree: ast.Module) -> list[str]:
    return sorted(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test")
    )


def _official_name(entries: list[str], stem: str) -> str:
    candidate = next((name for name in entries if name[:1].isupper()), "")
    for suffix in ("BlockCipher", "Permutation", "HashFunction", "StreamCipher", "Cipher"):
        if candidate.endswith(suffix):
            candidate = candidate[: -len(suffix)]
            break
    return candidate or "".join(part.capitalize() for part in stem.split("_"))


def _input_roles(tree: ast.Module) -> list[str]:
    """Return declared external input roles without importing legacy CLAASP."""

    roles = set()
    aliases = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            aliases[node.targets[0].id] = {
                value.id.removeprefix("INPUT_").lower()
                for value in ast.walk(node.value)
                if isinstance(value, ast.Name) and value.id.startswith("INPUT_")
            }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg not in {"cipher_inputs", "inputs"}:
                continue
            if isinstance(keyword.value, ast.Name):
                roles.update(aliases.get(keyword.value.id, set()))
            for value in ast.walk(keyword.value):
                if isinstance(value, ast.Name) and value.id.startswith("INPUT_"):
                    roles.add(value.id.removeprefix("INPUT_").lower())
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    roles.add(value.value.removeprefix("input_").lower())
    return sorted(roles)


def _fixed_length_category(directory: str, roles: list[str]) -> str:
    if directory in {"single_component_ciphers", "toys"}:
        return CATEGORY_BY_DIRECTORY[directory]
    if directory == "block_ciphers":
        return "tweakable_block_ciphers" if "tweak" in roles else "block_ciphers"
    if directory == "permutations":
        return "block_ciphers" if "key" in roles else "permutations"
    if directory == "stream_ciphers":
        return "block_functions" if "key" in roles else "functions"
    return CATEGORY_BY_DIRECTORY[directory]


def _proposed_module_stem(stem: str) -> str:
    for suffix in (
        "_block_cipher",
        "_hash_function",
        "_stream_cipher",
        "_permutation",
        "_cipher",
        "_mac",
    ):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def _catalogue_metadata(
    relative: Path, entries: list[str], tree: ast.Module
) -> dict[str, Any] | None:
    parts = relative.parts
    if len(parts) < 3 or parts[0:2] != ("claasp", "ciphers"):
        return None
    directory = parts[2]
    if directory not in CATEGORY_BY_DIRECTORY or relative.name == "__init__.py":
        return None
    path = relative.as_posix()
    roles = _input_roles(tree)
    official_name = OFFICIAL_NAME_OVERRIDES.get(path, _official_name(entries, relative.stem))
    high_level_parent = (
        directory if directory in {"hash_functions", "mac", "stream_ciphers"} else None
    )
    category = (
        "outside_scope"
        if path in CATALOGUE_OUT_OF_SCOPE
        else _fixed_length_category(directory, roles)
    )
    destination_category = category if category != "outside_scope" else "support"
    proposed_stem = PROPOSED_MODULE_STEM_OVERRIDES.get(path, _proposed_module_stem(relative.stem))
    proposed_module = PROPOSED_MODULE_OVERRIDES.get(path, f"{destination_category}.{proposed_stem}")
    bijectivity_obligation, classification_basis = classify_bijectivity(official_name, category)
    return {
        "official_name": official_name,
        "primitive_category": category,
        "proposed_module": f"claasp_next.primitives.{proposed_module}",
        "proposed_class": official_name,
        "higher_level_parent": high_level_parent,
        "input_roles": roles,
        "bijectivity_obligation": bijectivity_obligation,
        "classification_basis": classification_basis,
        "outside_scope_reason": CATALOGUE_OUT_OF_SCOPE.get(path),
    }


def _destination(relative: Path, catalogue: dict[str, Any] | None) -> str:
    if catalogue:
        if catalogue["primitive_category"] == "outside_scope":
            return "inapplicable: " + catalogue["outside_scope_reason"]
        module_path = catalogue["proposed_module"].replace(".", "/")
        package_marker = ROOT / "next/src" / module_path / "__init__.py"
        implementation = ROOT / "next/src" / module_path / "primitive.py"
        if implementation.exists():
            return module_path + "/primitive.py"
        return module_path + ("/__init__.py" if package_marker.exists() else ".py")
    if relative.parts[0] == "tests":
        return "next/tests (mapped to the owning migrated behavior)"
    if relative.name == "__init__.py":
        return "inapplicable: package marker reviewed with its containing module"
    return "next/src/claasp_next (destination finalized by owning migration milestone)"


def _responsibility(path: Path, tree: ast.Module) -> str:
    doc = ast.get_docstring(tree, clean=True)
    if doc:
        return doc.splitlines()[0].strip()
    return path.stem.replace("_", " ")


def record(path: Path) -> dict[str, Any]:
    relative = path.relative_to(ROOT)
    tree = _parse(path)
    entries = _public_entries(tree)
    tests = _test_entries(tree)
    catalogue = _catalogue_metadata(relative, entries, tree)
    is_marker = path.name == "__init__.py" and not entries
    kind = "test" if relative.parts[0] == "tests" else "source"
    item: dict[str, Any] = {
        "path": relative.as_posix(),
        "kind": kind,
        "responsibility": _responsibility(path, tree),
        "public_entry_points": entries,
        "dependencies": _dependencies(tree),
        "tests": tests,
        "fixed_evidence": {
            "test_functions": tests,
            "requires_fixture_review": bool(tests),
        },
        "v5_destination": _destination(relative, catalogue),
        "prerequisites": ["M10.9b"] if catalogue else ["owning migration milestone"],
        "disposition": "inapplicable" if is_marker else "migrate",
        "status": "reviewed-package-marker" if is_marker else "planned-or-partially-migrated",
        "acceptance_criterion": (
            "Containing package is represented by its non-marker entries."
            if is_marker
            else "Owning v5 behavior passes preserved legacy fixed evidence and independent semantic checks."
        ),
        "rationale": (
            "Empty package markers carry no behavior; contained modules are inventoried separately."
            if is_marker
            else None
        ),
    }
    if catalogue:
        item["primitive"] = catalogue
        item["milestone_owner"] = _m10_9d_source_slice(relative.as_posix(), catalogue)
        if catalogue["primitive_category"] == "outside_scope":
            item.update(
                {
                    "prerequisites": [],
                    "disposition": "inapplicable",
                    "status": "classified-outside-scope-in-m10.9b",
                    "acceptance_criterion": "The helper remains outside the primitive catalogue.",
                    "rationale": catalogue["outside_scope_reason"],
                }
            )
    m10_9c_slice = _m10_9c_slice(relative.as_posix())
    if m10_9c_slice:
        item["milestone_owner"] = m10_9c_slice
        item["prerequisites"] = [M10_9C_PREREQUISITE_BY_SLICE[m10_9c_slice]]
    m10_9d_test_slice = _m10_9d_test_slice(relative.as_posix())
    if m10_9d_test_slice:
        item["milestone_owner"] = m10_9d_test_slice
        item["prerequisites"] = ["M10.9c10"]
    item.update(MIGRATION_OVERRIDES.get(relative.as_posix(), {}))
    if item.get("milestone_owner") in M10_9D_COMPLETED_SLICES:
        is_test = item["kind"] == "test"
        item.update(
            {
                "v5_destination": (
                    M10_9D_TEST_DESTINATIONS[item["milestone_owner"]]
                    if is_test
                    else item["v5_destination"]
                ),
                "prerequisites": ["M10.9c10"],
                "disposition": "migrate",
                "status": "migrated-in-" + item["milestone_owner"].lower(),
                "acceptance_criterion": (
                    "Applicable fixed vectors, parameter variants, and independent semantic checks pass "
                    "through the typed v5 primitive graph."
                ),
                "rationale": None,
            }
        )
    return item


def build_inventory() -> dict[str, Any]:
    records = [record(path) for path in python_paths()]
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": ["claasp/**/*.py", "tests/**/*.py"],
        "generated_by": "next/tools/legacy_inventory.py",
        "counts": {
            "total": len(records),
            "source": sum(item["kind"] == "source" for item in records),
            "test": sum(item["kind"] == "test" for item in records),
            "primitive": sum("primitive" in item for item in records),
        },
        "records": records,
    }


def transformation_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Report the exact M10.10 transformation surface and evidence closure."""

    expected = set(M10_10_OVERRIDES)
    records = {item["path"]: item for item in payload["records"] if item["path"] in expected}
    missing = sorted(expected - set(records))
    owner_errors = sorted(
        path for path, item in records.items() if not item["milestone_owner"].startswith("M10.10")
    )
    unresolved = sorted(
        path
        for path, item in records.items()
        if item["status"] == "planned-or-partially-migrated" or item["disposition"] == "defer"
    )
    destination_errors = []
    for path, item in records.items():
        destinations = tuple(
            destination.strip() for destination in item["v5_destination"].split(";")
        )
        if not destinations or any(
            not (ROOT / destination).exists() for destination in destinations
        ):
            destination_errors.append(path)
    tests = tuple(item for item in records.values() if item["kind"] == "test")
    evidence_errors = sorted(
        item["path"]
        for item in tests
        if not item["fixed_evidence"] or not item["acceptance_criterion"]
    )
    return {
        "total": len(records),
        "source": sum(item["kind"] == "source" for item in records.values()),
        "test": len(tests),
        "by_slice": {
            owner: sum(item["milestone_owner"] == owner for item in records.values())
            for owner in sorted({item["milestone_owner"] for item in records.values()})
        },
        "missing": missing,
        "owner_errors": owner_errors,
        "destination_errors": sorted(destination_errors),
        "unresolved": unresolved,
        "evidence_errors": evidence_errors,
        "complete": not any(
            (missing, owner_errors, destination_errors, unresolved, evidence_errors)
        ),
    }


def serialized_inventory() -> str:
    return json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"


def model_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Report unresolved M10.8 model entries without treating deferrals as done."""
    records = [item for item in payload["records"] if "/models/" in item["path"]]
    unresolved = [
        item
        for item in records
        if item["status"] == "planned-or-partially-migrated"
        or item["disposition"] == "defer"
        or "destination finalized" in item["v5_destination"]
    ]
    families = {}
    for item in unresolved:
        family = item["path"].split("/models/", 1)[1].split("/", 1)[0]
        families[family] = families.get(family, 0) + 1
    return {
        "total": len(records),
        "resolved": len(records) - len(unresolved),
        "unresolved": [item["path"] for item in unresolved],
        "deferred": [item["path"] for item in unresolved if item["disposition"] == "defer"],
        "remaining_by_family": dict(sorted(families.items())),
        "complete": not unresolved,
    }


def component_catalogue_audit_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Summarize the explicit M10.9c ownership audit and remaining closure work."""
    expected = set().union(*M10_9C_PATHS_BY_SLICE.values())
    expected.update(M10_9C_PACKAGE_MARKERS)
    records = {item["path"]: item for item in payload["records"] if item["path"] in expected}
    missing = sorted(expected - records.keys())
    unexpected_owners = sorted(
        item["path"]
        for item in payload["records"]
        if str(item.get("milestone_owner", "")).startswith("M10.9c")
        and item["path"] not in expected
    )
    owner_errors = sorted(
        path
        for path in expected - M10_9C_PACKAGE_MARKERS
        if path in records and records[path].get("milestone_owner") != _m10_9c_slice(path)
    )
    by_slice = {
        slice_name: sum(
            path in records and records[path].get("milestone_owner") == slice_name for path in paths
        )
        for slice_name, paths in M10_9C_PATHS_BY_SLICE.items()
    }
    behavioral = [
        records[path] for path in sorted(expected - M10_9C_PACKAGE_MARKERS) if path in records
    ]
    unresolved = [
        item["path"]
        for item in behavioral
        if item["status"] == "planned-or-partially-migrated"
        or item["disposition"] == "defer"
        or "destination finalized" in item["v5_destination"]
        or item["v5_destination"].startswith("next/tests (")
    ]
    destination_errors = []
    for item in behavioral:
        for destination in item["v5_destination"].split(";"):
            destination = destination.strip()
            if destination.startswith(("removed:", "inapplicable:")):
                continue
            if not destination.startswith("next/") or not (ROOT / destination).exists():
                destination_errors.append(f"{item['path']}: {destination}")
    return {
        "total": len(records),
        "source": sum(item["kind"] == "source" for item in records.values()),
        "test": sum(item["kind"] == "test" for item in records.values()),
        "package_markers": sum(path in records for path in M10_9C_PACKAGE_MARKERS),
        "behavioral": len(behavioral),
        "test_functions": sum(len(item["tests"]) for item in behavioral),
        "by_slice": by_slice,
        "missing": missing,
        "unexpected_owners": unexpected_owners,
        "owner_errors": owner_errors,
        "destination_errors": destination_errors,
        "unresolved": unresolved,
        "complete": not missing
        and not unexpected_owners
        and not owner_errors
        and not destination_errors
        and not unresolved,
    }


def catalogue_classification_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate M10.9b category, key/tweak, and bijectivity obligations."""

    records = [item for item in payload["records"] if "primitive" in item]
    errors = []
    invalid_paths = set()
    counts = {}
    destinations = {}

    def fail(path: str, message: str) -> None:
        invalid_paths.add(path)
        errors.append(f"{path}: {message}")

    for item in records:
        metadata = item["primitive"]
        category = metadata["primitive_category"]
        roles = set(metadata["input_roles"])
        counts[category] = counts.get(category, 0) + 1
        if category not in CATALOGUE_CATEGORIES:
            fail(item["path"], f"unknown category {category}")
        if (
            category
            in {
                "block_ciphers",
                "block_functions",
                "tweakable_block_ciphers",
                "tweakable_block_functions",
            }
            and "key" not in roles
        ):
            fail(item["path"], "keyed category lacks key input")
        if (
            category in {"tweakable_block_ciphers", "tweakable_block_functions"}
            and "tweak" not in roles
        ):
            fail(item["path"], "tweakable category lacks tweak input")
        if category in {"permutations", "functions"} and roles & {"key", "tweak"}:
            fail(item["path"], "unkeyed category has key/tweak input")
        expected_bijective, expected_basis = classify_bijectivity(
            metadata["official_name"], category
        )
        if metadata["bijectivity_obligation"] != expected_bijective:
            fail(item["path"], "inconsistent bijectivity obligation")
        if metadata["classification_basis"] != expected_basis:
            fail(item["path"], "inconsistent bijectivity classification basis")
        if category == "outside_scope" and item["disposition"] != "inapplicable":
            fail(item["path"], "outside-scope entry is not inapplicable")
        if not metadata["official_name"] or not metadata["proposed_class"]:
            fail(item["path"], "official module/class name is missing")
        destination = metadata["proposed_module"]
        if not destination.startswith("claasp_next.primitives."):
            fail(item["path"], "destination is outside the v5 primitive catalogue")
        if category not in {"outside_scope", "single_component_primitives"}:
            destinations.setdefault(destination, []).append(item["path"])
            if any(
                part in destination.split(".")
                for part in ("hash_functions", "mac", "stream_ciphers")
            ):
                fail(item["path"], "legacy construction folder leaked into v5 taxonomy")
    for destination, paths in destinations.items():
        if len(paths) > 1:
            for path in paths:
                fail(path, f"duplicate proposed module {destination}")
    return {
        "total": len(records),
        "classified": len(records) - len(invalid_paths),
        "categories": dict(sorted(counts.items())),
        "errors": errors,
        "complete": not errors,
    }


def primitive_catalogue_audit_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Summarize M10.9d source/test ownership without claiming migration parity."""

    sources = [item for item in payload["records"] if "primitive" in item]
    tests = [
        item
        for item in payload["records"]
        if item["path"].startswith("tests/unit/ciphers/") and item["path"].endswith("_test.py")
    ]
    owned = sources + tests
    owner_errors = sorted(
        item["path"]
        for item in owned
        if item.get("milestone_owner") not in M10_9D_COMPLETION_SLICES
    )
    by_slice = {
        slice_name: sum(item.get("milestone_owner") == slice_name for item in owned)
        for slice_name in M10_9D_COMPLETION_SLICES
    }
    outside_scope = [
        item for item in sources if item["primitive"]["primitive_category"] == "outside_scope"
    ]

    def destination_exists(module_name: str) -> bool:
        path = ROOT / "next" / "src" / module_name.replace(".", "/")
        module_file = Path(str(path) + ".py")
        return module_file.exists() or (path / "__init__.py").exists()

    unresolved = [
        item["path"]
        for item in sources
        if item["primitive"]["primitive_category"] != "outside_scope"
        and (
            item["status"] == "planned-or-partially-migrated"
            or item["disposition"] == "defer"
            or not destination_exists(item["primitive"]["proposed_module"])
        )
    ]
    evidence_unresolved = [
        item["path"]
        for item in tests
        if item.get("milestone_owner") in M10_9D_COMPLETED_SLICES
        and (
            item["status"] != f"migrated-in-{item['milestone_owner'].lower()}"
            or not item.get("v5_destination")
            or any(
                not (ROOT / destination.strip()).exists()
                for destination in item.get("v5_destination", "").split(";")
                if destination.strip()
            )
        )
    ]
    intermediate_frozen_graphs = []
    for item in sources:
        if item["primitive"]["primitive_category"] == "outside_scope":
            continue
        path = ROOT / "next/src" / item["primitive"]["proposed_module"].replace(".", "/")
        implementation = path / "primitive.py" if path.is_dir() else Path(str(path) + ".py")
        if implementation.exists() and "CatalogueGraphPrimitive" in implementation.read_text(
            encoding="utf-8"
        ):
            intermediate_frozen_graphs.append(item["path"])
    primitive_root = ROOT / "next/src/claasp_next/primitives"
    runtime_frozen_graph_artifacts = sorted(
        str(path.relative_to(ROOT))
        for path in (
            list(primitive_root.glob("**/data/index.json"))
            + list(primitive_root.glob("**/*.json.gz"))
            + (
                [primitive_root / "_catalogue_graph.py"]
                if (primitive_root / "_catalogue_graph.py").exists()
                else []
            )
        )
    )
    return {
        "source": len(sources),
        "test": len(tests),
        "behavioral_sources": len(sources) - len(outside_scope),
        "outside_scope": len(outside_scope),
        "test_functions": sum(len(item["tests"]) for item in tests),
        "by_slice": by_slice,
        "owner_errors": owner_errors,
        "unresolved": unresolved,
        "evidence_unresolved": evidence_unresolved,
        "intermediate_frozen_graphs": sorted(intermediate_frozen_graphs),
        "runtime_frozen_graph_artifacts": runtime_frozen_graph_artifacts,
        "audit_complete": not owner_errors,
        "closure_complete": (
            not owner_errors
            and not unresolved
            and not evidence_unresolved
            and not intermediate_frozen_graphs
            and not runtime_frozen_graph_artifacts
        ),
    }


def component_analysis_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify M10.11 ownership without reopening M10.8d solver records."""

    owned_paths = {
        "claasp/cipher_modules/component_analysis_tests.py",
        "tests/unit/cipher_modules/component_analysis_tests_test.py",
    }
    records = {item["path"]: item for item in payload["records"]}
    errors = []
    for path in sorted(owned_paths):
        item = records[path]
        if item.get("milestone_owner") != "M10.11a":
            errors.append(f"{path}: missing explicit M10.11 ownership")
        if item["status"] not in {
            "migrated-in-m10.11g",
            "superseded-in-m10.11g",
        }:
            errors.append(f"{path}: component-analysis disposition is not final")
        if not item.get("acceptance_criterion") or not item.get("rationale"):
            errors.append(f"{path}: rationale or fixed-evidence criterion is missing")
        for destination in item.get("v5_destination", "").split(";"):
            destination = destination.strip()
            if destination.startswith("next/") and not (ROOT / destination).exists():
                errors.append(f"{path}: missing destination {destination}")
    wordwise_paths = {
        "claasp/cipher_modules/models/milp/milp_models/milp_wordwise_branch_number_number_of_active_sboxes_model.py",
        "tests/unit/cipher_modules/models/milp/milp_models/milp_wordwise_branch_number_number_of_active_sboxes_model_test.py",
    }
    for path in sorted(wordwise_paths):
        if records[path]["status"] != "superseded-in-m10.8d":
            errors.append(f"{path}: M10.8d closure was reopened")
    return {
        "records": len(owned_paths),
        "final": len(owned_paths) - sum("disposition is not final" in error for error in errors),
        "wordwise_m10_8d_retained": all(
            records[path]["status"] == "superseded-in-m10.8d" for path in wordwise_paths
        ),
        "errors": errors,
        "complete": not errors,
    }


def presentation_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify M10.14 report records and deferred presentation obligations."""

    owned_paths = {
        "claasp/cipher_modules/report.py",
        "tests/unit/cipher_modules/report_test.py",
        "claasp/cipher_modules/statistical_tests/nist_statistical_tests_report.py",
        "tests/unit/cipher_modules/statistical_tests/nist_statistical_tests_report_test.py",
    }
    records = {item["path"]: item for item in payload["records"]}
    errors = []
    for path in sorted(owned_paths):
        item = records[path]
        if item.get("milestone_owner") != "M10.14a":
            errors.append(f"{path}: missing explicit M10.14 ownership")
        if item.get("status") != "superseded-in-m10.14g":
            errors.append(f"{path}: report disposition is not final")
        if not item.get("acceptance_criterion") or not item.get("rationale"):
            errors.append(f"{path}: rationale or fixed-evidence criterion is missing")
        for destination in item.get("v5_destination", "").split(";"):
            destination = destination.strip()
            if destination.startswith("next/") and not (ROOT / destination).exists():
                errors.append(f"{path}: missing destination {destination}")

    manifest_path = ROOT / "next/migration/m10_14_presentation_obligations.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    obligations = manifest.get("obligations", ())
    for item in obligations:
        if not str(item.get("owner", "")).startswith("M10.14"):
            errors.append(f"{item.get('id')}: presentation owner is missing")
        if item.get("status") != "achieved":
            errors.append(f"{item.get('id')}: presentation obligation is not achieved")
        if not item.get("rationale") or not item.get("fixed_evidence"):
            errors.append(f"{item.get('id')}: rationale or fixed evidence is missing")
        for destination in item.get("destinations", ()):
            if not (ROOT / destination).exists():
                errors.append(f"{item.get('id')}: missing destination {destination}")
    return {
        "records": len(owned_paths),
        "obligations": len(obligations),
        "final_records": sum(
            records[path].get("status") == "superseded-in-m10.14g" for path in owned_paths
        ),
        "achieved_obligations": sum(item.get("status") == "achieved" for item in obligations),
        "errors": errors,
        "complete": not errors,
    }


def tooling_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Verify M10.15 records, native dispositions, diagrams, and fixed evidence."""

    records = {item["path"]: item for item in payload["records"]}
    owned = {path: records[path] for path in _M10_15_OVERRIDES}
    errors = []
    final_statuses = {
        "migrated-in-m10.15f",
        "superseded-in-m10.15d",
        "superseded-in-m10.15f",
    }
    for path, item in sorted(owned.items()):
        if item.get("milestone_owner") != "M10.15a":
            errors.append(f"{path}: missing explicit M10.15 ownership")
        if item.get("status") not in final_statuses:
            errors.append(f"{path}: tooling disposition is not final")
        if not item.get("acceptance_criterion") or not item.get("rationale"):
            errors.append(f"{path}: rationale or acceptance criterion is missing")
        for destination in item.get("v5_destination", "").split(";"):
            destination = destination.strip()
            if destination.startswith("next/") and not (ROOT / destination).exists():
                errors.append(f"{path}: missing destination {destination}")

    continuous_paths = {
        "claasp/cipher_modules/continuous_diffusion_analysis.py",
        "tests/unit/cipher_modules/continuous_diffusion_analysis_test.py",
    }
    for path in sorted(continuous_paths):
        item = records[path]
        if (
            item.get("milestone_owner") != "M10.6d6"
            or item.get("status") != "superseded-in-m10.15d-audit"
        ):
            errors.append(f"{path}: achieved M10.6d6 ownership was reopened")

    manifest_path = ROOT / "next/migration/m10_15_tooling_obligations.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "achieved":
        errors.append("M10.15 manifest is not achieved")
    obligations = [
        *manifest.get("native_artifacts", ()),
        *manifest.get("mixed_module_surfaces", ()),
        manifest.get("diagram_audit", {}),
    ]
    for item in obligations:
        label = item.get("path", "diagram_audit")
        if not item.get("rationale") or not item.get("fixed_evidence"):
            errors.append(f"{label}: rationale or fixed evidence is missing")
        destinations = item.get("destinations", ())
        if item.get("destination"):
            destinations = (*destinations, item["destination"])
        for destination in destinations:
            if not (ROOT / destination).exists():
                errors.append(f"{label}: missing destination {destination}")
        for evidence in item.get("fixed_evidence", ()):
            if not (ROOT / evidence).exists():
                errors.append(f"{label}: missing fixed evidence {evidence}")

    return {
        "records": len(owned),
        "final_records": sum(item.get("status") in final_statuses for item in owned.values()),
        "native_artifacts": len(manifest.get("native_artifacts", ())),
        "mixed_surfaces": len(manifest.get("mixed_module_surfaces", ())),
        "continuous_m10_6d6_retained": all(
            records[path].get("milestone_owner") == "M10.6d6" for path in continuous_paths
        ),
        "errors": errors,
        "complete": not errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="fail if the checked-in inventory is stale"
    )
    parser.add_argument(
        "--model-status",
        action="store_true",
        help="report remaining M10.8 model work without rewriting the inventory",
    )
    parser.add_argument(
        "--check-model-closure",
        action="store_true",
        help="fail until all M10.8 model entries are resolved, including deferrals",
    )
    parser.add_argument(
        "--catalogue-status",
        action="store_true",
        help="report M10.9b fixed-length catalogue classification",
    )
    parser.add_argument(
        "--check-catalogue-classification",
        action="store_true",
        help="fail until every catalogue entry satisfies M10.9b invariants",
    )
    parser.add_argument(
        "--component-status",
        action="store_true",
        help="report M10.9c reusable component catalogue closure",
    )
    parser.add_argument(
        "--check-component-closure",
        action="store_true",
        help="fail until every M10.9c component entry has a concrete final disposition",
    )
    parser.add_argument(
        "--primitive-status",
        action="store_true",
        help="report M10.9d primitive catalogue ownership and closure",
    )
    parser.add_argument(
        "--check-primitive-audit",
        action="store_true",
        help="fail until every M10.9d source and test has a slice owner",
    )
    parser.add_argument(
        "--check-primitive-closure",
        action="store_true",
        help="fail until every in-scope M10.9d primitive has a concrete v5 destination",
    )
    parser.add_argument(
        "--transformation-status",
        action="store_true",
        help="report M10.10 transformation and evidence closure",
    )
    parser.add_argument(
        "--check-transformation-closure",
        action="store_true",
        help="fail until every M10.10 record has final evidence and an existing destination",
    )
    parser.add_argument(
        "--component-analysis-status",
        action="store_true",
        help="report M10.11 component-analysis ownership and closure",
    )
    parser.add_argument(
        "--check-component-analysis-closure",
        action="store_true",
        help="fail until M10.11 evidence is final without reopening M10.8d",
    )
    parser.add_argument(
        "--presentation-status",
        action="store_true",
        help="report M10.14 report and deferred-presentation closure",
    )
    parser.add_argument(
        "--check-presentation-closure",
        action="store_true",
        help="fail until all M10.14 report and presentation evidence is final",
    )
    parser.add_argument(
        "--tooling-status",
        action="store_true",
        help="report M10.15 serialization, source, native, and diagram closure",
    )
    parser.add_argument(
        "--check-tooling-closure",
        action="store_true",
        help="fail until every M10.15 tooling obligation has final evidence",
    )
    args = parser.parse_args()
    if args.model_status or args.check_model_closure:
        status = model_closure_status(build_inventory())
        print(
            json.dumps(
                {key: value for key, value in status.items() if key != "unresolved"}, indent=2
            )
        )
        return int(args.check_model_closure and not status["complete"])
    if args.catalogue_status or args.check_catalogue_classification:
        status = catalogue_classification_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_catalogue_classification and not status["complete"])
    if args.component_status or args.check_component_closure:
        status = component_catalogue_audit_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_component_closure and not status["complete"])
    if args.primitive_status or args.check_primitive_audit or args.check_primitive_closure:
        status = primitive_catalogue_audit_status(build_inventory())
        print(json.dumps(status, indent=2))
        if args.check_primitive_audit:
            return int(not status["audit_complete"])
        return int(args.check_primitive_closure and not status["closure_complete"])
    if args.transformation_status or args.check_transformation_closure:
        status = transformation_closure_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_transformation_closure and not status["complete"])
    if args.component_analysis_status or args.check_component_analysis_closure:
        status = component_analysis_closure_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_component_analysis_closure and not status["complete"])
    if args.presentation_status or args.check_presentation_closure:
        status = presentation_closure_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_presentation_closure and not status["complete"])
    if args.tooling_status or args.check_tooling_closure:
        status = tooling_closure_status(build_inventory())
        print(json.dumps(status, indent=2))
        return int(args.check_tooling_closure and not status["complete"])
    expected = serialized_inventory()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"legacy inventory is stale; run: python {Path(__file__).name}")
            return 1
        print(f"legacy inventory covers {build_inventory()['counts']['total']} Python files")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
