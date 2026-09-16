#!/usr/bin/env python3
"""Build and verify the exhaustive CLAASP 4 Python migration inventory.

The output is deterministic and intentionally uses only the Python standard
library. Run from ``next/`` with ``python tools/legacy_inventory.py --check``.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any
import warnings


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

MIGRATION_OVERRIDES = {
    "claasp/cipher_modules/models/milp/milp_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp; next/src/claasp_next/drivers/solvers/glpk.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Portable immutable linear models, typed constraints/objectives and explicit GLPK results replace Sage mixed-integer state and solver registries.",
        "rationale": "Variable-name dictionaries, Sage backend selection, mutable constraint lists and result parsing are split across representation, analysis and driver layers. Scientific subclasses are inventoried separately.",
    },
    "tests/unit/cipher_modules/models/milp/milp_model_test.py": {
        "v5_destination": "next/tests/unit/test_milp_representation.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed equal/not-equal/nonzero constraints, deterministic LP export and real GLPK SAT/UNSAT/assignment decoding are covered.",
        "rationale": "Sage variable names, list positions and installed solver-brand catalogues are not v5 contracts. Backend provenance and status are explicit driver results.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_bitwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed strongest three-valued propagation preserves fixed Speck boundaries; exact finite relations provide a portable MILP baseline where solving is required.",
        "rationale": "Integer sentinel encodings, Sage constraints and minimization of unknown indicators are representation choices. They do not define a different primitive graph or execution engine.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_bitwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_finite_relation_milp.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Both fixed Speck outputs are retained and exact finite-relation MILP decoding is exhaustively checked.",
        "rationale": "The 62,624 generated constraints, Sage variable indices and arbitrary minimum unknown count 14 are encoding/search artifacts, not fixed primitive evidence.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_bitwise_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed forward/backward propagation preserves the fixed Simon-11 middle patterns and contradiction with real solver confirmation.",
        "rationale": "A second Sage encoding of the same impossible-boundary semantics adds no public capability. Generated constraint order and arbitrary Ascon witnesses are discarded.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_bitwise_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Simon input/output and both fixed middle patterns preserve their bit-23 incompatibility independently of backend.",
        "rationale": "Internal/external duplicate tests, 2,400-line counts and solver-selected Ascon components do not add scientific evidence beyond the shared typed boundary.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_wordwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed word activity/value domains and exact finite relations replace sentinel-coded Sage variables.",
        "rationale": "The legacy model exposes encoding-specific integer pairs and mutable cache-derived inequalities. v5 retains the wordwise transfer semantics independently of backend.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_wordwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every wordwise XOR/MDS row and typed AES singleton diffusion is checked exhaustively.",
        "rationale": "The test's 19,768 constraints, first/last Sage expressions and arbitrary feasible/minimum-count statuses are not fixed cryptanalytic results.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact differential relations support fixed/bounded/optimal/complete enumeration with independent graph and weight decoding.",
        "rationale": "Sage probability variables and solver modes are replaced by portable MILP for S-box graphs and generic word-SMT composition for ARX graphs, sharing one semantic contract.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy Speck counts 6/7, optima 1/4, and fixed feasible weights 5/15 are retained by generic independently checked graph models.",
        "rationale": "Arbitrary first witnesses and solver metadata are removed; all exact numeric assertions are preserved by shared representations.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_differential_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Branch-number and exact DDT reasoning derive reduced AES active-S-box minima and distinguish necessary activity bounds from concrete trails.",
        "rationale": "A Sage objective over activity flags is a coarse search abstraction. v5 exposes the bound as semantic evidence and never relabels it an exact differential probability.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_differential_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Reduced AES activity minima and the trivial one-active-S-box first-round bound are derived independently.",
        "rationale": "Building time, Sage solver name and model tag are not scientific results. uBlock's one-round value follows directly from a required nonzero input and one bijective S-box layer; broader uBlock evidence is audited separately.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/trails.py; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Signed exact correlations support complete enumeration, optima and fixed weights through shared graph semantics.",
        "rationale": "Sage variables, solver/license branches and probability-array conventions are replaced by portable representation/driver boundaries and exact Walsh decoders.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Toy counts 12/13, standard optimum 3 and feasible weights 1/7 retain exact signs and independent decoding.",
        "rationale": "The 12,371-expression layout, fixed Sage indices and proprietary solver error branches are not v5 API contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/milp_truncated_utils.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed truncated domains and exact finite relations replace Sage inequality helper mutation.",
        "rationale": "Variable-index allocation and in-place constraint assembly belong to the representation. The semantic transition tables are now immutable and exhaustively tested.",
    },
    "claasp/cipher_modules/models/milp/utils/mzn_predicates.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "MiniZinc predicates live in the CP representation and are derived from shared semantic providers.",
        "rationale": "A MiniZinc source template in the MILP package violates the v5 representation boundary and duplicates the reviewed CP lowering.",
    },
    "claasp/cipher_modules/models/milp/utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp; next/src/claasp_next/semantics/cryptanalysis",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed semantic registries, immutable linear expressions and exact decoders replace Sage variable/constraint helper dictionaries.",
        "rationale": "Backend variable factories, decimal precision constants and component-method name maps are representation internals, not public semantic APIs.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/composed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed composition separates exact differential, connector and linear terms from seeded empirical correlations for fixed Speck and ChaCha pairs.",
        "rationale": "A heterogeneous list of component method names, guessed unknown counts and one CNF objective do not define a distinct semantic model. v5 preserves reproducible fixed evidence and does not give sampled or approximate results SAT-proof status.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_differential_linear_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed Speck weight decomposition, zero-key empirical bound and fixed ChaCha 6/8-half-round pairs are retained with deterministic sample counts.",
        "rationale": "Unfixed existence checks for Speck, ChaCha and Aradi return arbitrary witnesses; their requested upper bounds are search parameters, not proven optima. Fixed result-bearing pairs are retained. Aradi primitive evaluation evidence remains owned by its catalogue migration rather than this removed SAT wrapper.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_probabilistic_xor_truncated_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact prefixes and typed probabilistic/deterministic truncated suffixes compose explicitly and preserve all fixed Speck boundary patterns.",
        "rationale": "Per-component string dispatch and heterogeneous SAT encodings are replaced by explicit phase composition. Empirical probability estimates remain labelled observations, not model weights or solver proofs.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_probabilistic_xor_truncated_differential_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed four-/five-round Speck outputs and modular-add probability costs are independently retained; invalid ternary values are rejected by typed constructors.",
        "rationale": "Monte Carlo ranges are empirical and backend-independent; the Aradi/ChaCha searches fix no complete solver witness. Exact boundary literals and result-bearing weights are preserved by shared semantics, while catalogue-specific empirical vectors belong with their primitives.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_semi_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed partial differences preserve fixed Speck/ChaCha boundary values without exposing unknown-run counters as semantics.",
        "rationale": "Unknown-window limits are optional pruning constraints, not probabilities. Direct strongest propagation owns deterministic claims; probabilistic transitions carry independently checked costs.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_semi_deterministic_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Both fixed three-round Speck outputs and the fixed reduced-ChaCha empirical evidence remain executable with explicit claim types.",
        "rationale": "SAT/UNSAT caused solely by caller-selected unknown-run caps characterizes a heuristic configuration, not primitive infeasibility. The fixed semantic boundaries are retained; mutable counter configuration is removed.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/composed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared-input-difference experiments use explicit fixed differences, deterministic sampling and empirical result types.",
        "rationale": "Four graph copies and equality clauses are an experimental construction, not a new propagation meaning. v5 keeps permutation execution separate from the statistical observation.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Reduced ChaCha fixed-difference empirical evidence is represented without claiming an exact probability or SAT proof.",
        "rationale": "The legacy checker has no seed and the assertion only bounds one stochastic run; solver status plus sampled weight cannot establish a cryptanalytic proof. The fixed ChaCha family is covered by deterministic composed experiments.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/composed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Backward composed evidence is represented as explicit permutation execution plus an empirical observation, never as an exact trail probability.",
        "rationale": "Graph inversion, prefix mutation, pickled cache files and four-copy CNF construction conflate graph editing, representation and experiment. Those concerns are separated in v5.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_shared_difference_paired_input_differential_linear_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Fixed reduced-ChaCha composed observations retain empirical provenance without generated inverse-graph cache state.",
        "rationale": "The legacy test mutates/pickles a graph, uses only 256 unseeded samples and asserts a broad bound. It is not reproducible proof evidence; deterministic fixed-pair experiments supersede it.",
    },
    "claasp/cipher_modules/models/sat/utils/mzn_predicates.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/transitions.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact word-operation relations are derived from shared semantics by each representation rather than embedded as cross-backend MiniZinc strings.",
        "rationale": "Despite its SAT location this file is a large MiniZinc source template. Typed CP and SMT lowerings replace copied predicate text and fixed search annotations.",
    },
    "claasp/cipher_modules/models/sat/utils/n_window_heuristic_helper.py": {
        "v5_destination": "next/src/claasp_next/analysis",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Exact trail models remain complete without window pruning; optional search strategies cannot change decoded transition validity.",
        "rationale": "Full-window counters constrain solver search and may deliberately discard valid trails. They are neither primitive semantics nor probability evidence and are not part of the simple v5 public API.",
    },
    "claasp/cipher_modules/models/sat/utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/semantics/cryptanalysis",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Component semantics selection, phase composition and CNF helpers use typed registries/models and fail explicitly for unsupported operations.",
        "rationale": "Method-name dictionaries and in-place component-list rewrites conflate semantic selection with backend dispatch. v5 uses immutable propagation problems and explicit phase boundaries.",
    },
    "claasp/cipher_modules/models/sat/sat_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat/model.py; next/src/claasp_next/drivers/solvers/minisat.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Immutable CNF, typed constraints and explicit MiniSat/Z3 drivers cover construction, solving, status and named assignment decoding.",
        "rationale": "Mutable variable-name clauses, solver registries, subprocess parsing and mixed semantic/search methods are split across v5 representations, drivers and analysis problems. Result-bearing subclasses are inventoried separately.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_bitwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed universal three-valued propagation preserves both fixed reduced-Speck output patterns.",
        "rationale": "Two Boolean variables per ternary bit, generated clause ordering and a solver-specific minimization loop are representation details. The strongest sound output is computed directly and checked independently.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_bitwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck fixed inputs preserve round-one output ????100000000000????100000000011 and round-three output ???????????????0????????????????.",
        "rationale": "The 28,761-clause count, literal spelling/order and an unfixed SAT status are not v5 contracts; both fixed semantic results are retained directly.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_bitwise_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed directional propagation retains the exact Simon-11 fixed patterns and contradiction position, with executable solver confirmation.",
        "rationale": "Forward/backward SAT variable suffixes and graph-copy mutation are replaced by explicit impossible boundaries. Component-local Ascon arbitrary witnesses are not stable public results.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_bitwise_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Simon input 000...001 and output 000000?0?... preserve both exact middle patterns and their bit-23 incompatibility.",
        "rationale": "Generated clause counts and solver-selected Ascon intermediate values are arbitrary witnesses. The fully fixed Simon evidence is preserved and independently checked.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact, deterministic and probabilistic truncated meanings use separate typed result classes and validation rules.",
        "rationale": "The legacy base mixes encodings and result parsing through inheritance. v5 makes the claim kind explicit and shares no mutable SAT model state between them.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Generic graph differential composition retains fixed/bounded/optimal/complete enumeration and independently checked exact weights.",
        "rationale": "CNF counter layouts, window-search clauses and solver parsing are not semantic APIs. Shared transition semantics and complete graph enumeration preserve the exact results across open backends.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_word_differential.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck-5 optimum/count, fixed weights, Speck-9 27-trail aggregate 29.47 and all exact graph transitions are retained.",
        "rationale": "Window constraints are optional search heuristics over otherwise exact trails; requested-weight existence does not make literal counter placement a contract. File-output formatting and arbitrary witnesses are removed. The separate uBlock aggregate remains owned by the typed-primitive prerequisite audit.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Signed Walsh semantics and graph composition preserve complete counts, optima, feasible weights and fixed masks.",
        "rationale": "Branch literal naming, CNF ordering, sequential counters and solver dictionaries are replaced by typed masks, exact correlations and independent decoding.",
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_xor_linear_model_test.py": {
        "v5_destination": "next/tests/integration/test_speck_trail_enumeration.py; next/tests/unit/test_word_linear_smt.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck count 73, optimum 3, feasible weight 7, fixed masks and empirical-correlation bound are preserved.",
        "rationale": "CNF literal order and generated fixed-value strings are representation details. Complete semantic assignments exclude auxiliary-counter multiplicity and retain signed correlations.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "AES branch-number reasoning and exact DDT/MixColumns enumeration derive the minimum five active S-boxes and weight 30 without heuristic XOR augmentation.",
        "rationale": "The first-step Boolean activity search and repeated synthesized XOR components are a search heuristic. v5 records the proven branch property and independently derives the exact result-bearing second-step evidence.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact AES evidence derives the active-S-box lower bound; no mutable helper-list cardinality is exposed.",
        "rationale": "The sole assertion, 188 synthesized XOR components, measures one repetition of an internal redundancy heuristic and carries no mathematical result.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/activity.py; next/src/claasp_next/semantics/cryptanalysis/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The two-round reduced AES minimum 30, 255 exact trails per selected minimum activity pattern and feasible all-ff weight 224 are independently derived from DDT and MixColumns semantics.",
        "rationale": "Two sequential solver models, retries, generated tables and warning behavior are an optimization strategy rather than a distinct graph realization. Exact semantic enumeration retains its fixed results without binding the public API to the heuristic.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_trail_search_fixing_number_of_active_sboxes_model_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_activity.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Independent enumeration preserves minimum weight 30, count 255 for each of four minimum column patterns, and the all-ff weight-224 characteristic.",
        "rationale": "Solver metadata, arbitrary witnesses, retry mocks and generated component names are removed. The three exact numeric scientific assertions are retained and strengthened by derivation over all four symmetric activity patterns.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/usefulfunctions.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact modular-add differential relations and explicit weight bounds are emitted by typed CP representations and independently decoded.",
        "rationale": "The embedded MiniZinc word-operation text, search annotations and fixed scale constants are representation internals. Typed model parts now derive the relation from shared semantics and keep exact versus scaled weights explicit.",
    },
    "claasp/cipher_modules/models/cp/mzn_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/model.py; next/src/claasp_next/drivers/solvers/minizinc.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Immutable MiniZinc IR, explicit solver configuration and typed result/status decoding cover model assembly, fixed constraints, enumeration and weight bounds.",
        "rationale": "Mutable declarations, generated variable-name parsing, subprocess command dictionaries and mixed model/driver state are replaced by the representation/driver boundary. Scientific helper tables and result fixtures are inventoried separately.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Three-valued deterministic propagation is typed, graph-derived and independently checked, including the fixed Speck round boundary.",
        "rationale": "Generated declarations, model-line counts and arbitrary first witnesses are not public contracts. Shared truncated semantics and native CP projection replace component method-name dispatch.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The ARX subset uses the same checked deterministic truncated semantics without a distinct public graph model.",
        "rationale": "The legacy test is assertion-free construction. A separate optimized class would conflate graph realization with execution/search strategy; v5 keeps the semantic problem shared and solver selection explicit.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The fixed Speck deterministic boundary and real MiniZinc projection are independently preserved.",
        "rationale": "The count four is enumeration of unconstrained symmetric unknown patterns and the remaining checks are generated names, line counts, metadata and arbitrary witnesses. v5 tests the fixed mathematical boundary rather than serialization accidents.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_deterministic_truncated_xor_differential_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "The shared deterministic ARX semantics has executable fixed-vector coverage.",
        "rationale": "The legacy test calls a builder and contains no assertion.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_semi_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Probabilistic-truncated modular addition retains independently checked scaled costs 309/700 and multi-round Speck patterns/weights 1.0/0.0.",
        "rationale": None,
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_semi_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py; next/tests/unit/test_truncated_differences.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed modular-add costs and Speck output/weight fixtures are solved and independently checked.",
        "rationale": "Unfixed one-solution/optimization metadata and Monte Carlo ChaCha smoke checks have no stable oracle. Fixed result-bearing CP fixtures are retained; empirical composed ChaCha evidence is owned by the separately seeded differential-linear audit.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_wordwise_deterministic_truncated_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed zero/known/nonzero/unknown word domains propagate through graph-derived AES diffusion and native CP projection.",
        "rationale": "Activity integers, negative value sentinels and generated declaration counts are replaced by explicit typed domains. Exact and coarse abstractions are labelled separately.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_wordwise_deterministic_truncated_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "A fixed one-byte AES input difference becomes four guaranteed nonzero column bytes and projects losslessly through MiniZinc.",
        "rationale": "The legacy test checks only mutable line counts and declarations. The v5 fixed diffusion fixture provides stronger semantic coverage without exposing sentinel encodings.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed forward/backward boundaries, Speck-7 UNSAT and the exact Simon-11 middle contradiction are independently preserved through CP.",
        "rationale": "Cipher graph mutation, inverse-name correspondence, generated-line cleanup and arbitrary low-complexity witnesses are replaced by explicit directional dataflows and contradiction positions.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The seven-round Speck split is proven UNSAT and Simon-11 fixed external/middle patterns preserve the bit-23 contradiction.",
        "rationale": "Generated counts, solver labels and unfixed arbitrary witnesses are not stable evidence. The fully automatic Simon literals and the result-bearing Speck infeasibility are retained with independent semantic checks.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_hybrid_impossible_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/cp/trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact local incompatibility and typed multi-round forward/backward contradiction composition replace mixed sentinel domains.",
        "rationale": "The legacy LBlock tests fix no input/output difference and assert counts of six placeholder-only solutions, solver metadata and arbitrary weights. They establish no reproducible cryptanalytic result beyond the shared incompatibility semantics.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_hybrid_impossible_xor_differential_model_test.py": {
        "v5_destination": "next/tests/unit/test_truncated_differences.py; next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Possible and impossible middle boundaries receive real CP SAT/UNSAT checks and independent contradiction decoding.",
        "rationale": "Six all-unknown LBlock outputs, generated declarations and a first arbitrary weight in {2,3} are not fixed scientific vectors. Exact typed boundary tests supersede them.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_differential_linear_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/composed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed differential/connector/linear composition preserves the fixed Speck p=1,r=7,q=3 fixture and seeded ChaCha differential-linear evidence with explicit claim kinds.",
        "rationale": "Mutable component partitions, mixed approximate/exact objectives and solver-shaped dictionaries are replaced by typed composition. Search weight, exact composed weight and sampled correlation are never conflated.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_differential_linear_model_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck's fixed weight-14 decomposition and all three fixed ChaCha input/mask empirical bounds are retained with deterministic samples.",
        "rationale": "Ballet/SipHash and golden-search cases assert only existence of an unfixed solver witness. Generated component names and arbitrary intermediate formatting are not contracts; all fixed boundaries, objective terms and empirical threshold fixtures are preserved.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Generic word-graph composition, explicit bounds/enumeration and independent transition decoding retain all fixed Speck optimum/count fixtures.",
        "rationale": "Search annotations, mutable probability arrays and permutation/key-schedule variable-name partitions are optimizer details. Exact semantics are shared across CP and SMT rather than exposed as a separate graph realization.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py; next/tests/integration/test_word_differential.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Speck-5 optimum 9, short optimum 5, min-max 5 and fixed-weight/count evidence are independently solved and checked.",
        "rationale": "Assertions on nSolutions>1, arbitrary weights>1 and internal probability-variable names are not scientific fixtures. Every exact numeric result is retained by generic graph models.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_differential_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_differential.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared exact differential semantics support fixed/bounded/optimal/enumerated trails with independently validated graph wiring.",
        "rationale": "The legacy model duplicates search modes, parsing and component dispatch. v5 separates one semantic problem from CP/SMT representations and explicit solver drivers.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_xor_linear_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/trails.py; next/src/claasp_next/representations/constraints/smt/word_linear.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Shared signed-correlation semantics support fixed/bounded/optimal/enumerated graph trails and preserve every fixed Speck result.",
        "rationale": "Generated declarations, probability arrays, mutable dispatch and result dictionaries are backend internals. v5 retains masks, exact Walsh counts/signs and complete enumeration independently of the solver encoding.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/mzn_bct_predicates.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact S-box and modular-add boomerang connectivity is counted independently, including the fixed 16-bit Speck switch entry.",
        "rationale": "The fixed four-worker MiniZinc table is an optimization-specific restricted switch predicate. v5 exposes exact BCT semantics and a scalable carry/borrow automaton instead of treating that table or its unweighted acceptance as the mathematical contract.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_boomerang_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/composed.py; next/src/claasp_next/analysis/boomerang.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed upper/switch/lower composition retains explicit weights and exact switch counts; the fixed Speck32/64-8 distinguisher is reproducibly evaluated.",
        "rationale": "Graph splitting, generated filenames, mutable model concatenation and solver-output parsing are representation details. Exact switch semantics and separately labelled seeded empirical evidence replace an optimizer-specific builder; an observed rate is never presented as a proof probability.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_boomerang_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/unit/test_composed_trails.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "The Speck32/64-8 differences 28000010 and 8000840A retain a seeded positive empirical rate; exact BCT and modular-add switch counts are independently checked.",
        "rationale": "The legacy Speck assertion depends on random os.urandom samples and does not fix the solver-selected boundaries; the ChaCha case only checks temporary-file creation and self-consistent parsing. v5 retains the scientific distinguisher as deterministic empirical evidence and replaces construction smoke checks with typed composition tests.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/mzn_continuous_predicates.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/continuous.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Equations 3--5 for continuous XOR, modular addition and rotations preserve the fixed one- and two-round Speck vectors within the legacy tolerance.",
        "rationale": None,
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_differential_linear_continuous_model.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/continuous.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Continuous propagation and fixed-mask correlation retain numeric provenance and tolerance while never claiming feasibility, optimality or exact probability.",
        "rationale": "The legacy floating SCIP search uses a piecewise approximation and labels numerical candidates SATISFIED. v5 preserves the underlying heuristic equations and fixed evidence but deliberately removes proof-shaped status from continuous results.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_differential_linear_continuous_model_test.py": {
        "v5_destination": "next/tests/unit/test_continuous_heuristics.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed component, one-/two-round and mask-correlation values are preserved with the stated tolerances and explicitly heuristic result type.",
        "rationale": "The unconstrained lowest-correlation test asserts only that SCIP returned an in-range nonzero float and supplies no fixed oracle. Typed dependency-free equations preserve every fixed literal while removing solver and generated-variable incidental contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_and_operation_2_input_bits.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/bitwise.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact independent-bit AND DDT/LAT counts and weights are retained; finite binary relations provide an exact open extended formulation.",
        "rationale": "Sage convex-hull construction and greedy/minimum-facet selection tune an encoding, not cryptanalytic semantics. The exact baseline replaces these algorithms without promising identical facets, inequality counts or Sage object types.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_large_sboxes.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/sbox.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact full DDT and signed Walsh relations support small and eight-bit tables, including nonzero probability-one transitions, with independently checked weights and signs.",
        "rationale": "Espresso product-of-sum minimization, PLA formatting and mutable pickled caches are replaced by an exact one-hot baseline. Full Walsh counts are explicit rather than silently mixing half-Walsh LAT scales. Encoding minimization is not a scientific fixture contract.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_sbox_inequalities_for_trail_search.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/sbox.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Full probability-class support is retained, and the legacy PRESENT probability-2/16 facet is independently valid on every corresponding row.",
        "rationale": "The module itself calls the small-S-box convex-hull code a comparison-only alternative to large-S-box Espresso generation. v5 uses the same exact finite-relation baseline for both; greedy/minimum-facet algorithms, Sage polyhedra and pickled caches are not public APIs.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_sbox_inequalities_for_trail_search_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_milp_relation.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every supported PRESENT DDT/LAT entry and exact objective/sign is checked; the fixed legacy facet holds for all probability-2/16 entries.",
        "rationale": "A particular Sage inequality's position and printed object representation are not v5 contracts; its mathematical validity is preserved explicitly.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_undisturbed_bits_inequalities_for_sboxes.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/trails.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All 81 PRESENT truncated inputs and four undisturbed transitions match the fixed evidence; exact finite relations replace single-output-bit minimization.",
        "rationale": "Typed strongest bitwise derivative joins retain semantics without Espresso, Sage SBox objects, mutable pickle caches or a fixed chosen cube ordering. Unknown bits remain sound abstractions, not probability-bearing joint witnesses.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_undisturbed_bits_inequalities_for_sboxes_test.py": {
        "v5_destination": "next/tests/unit/test_sbox_undisturbed.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All 81 rows, four fixed undisturbed transitions and the five legacy projected forbidden cubes are independently checked.",
        "rationale": "Global cache deletion/repopulation and a particular Espresso output sequence are replaced by immutable in-memory exact relations.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_mds_matrices.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed dense-layer activity reproduces every one of the 256 model-5 rows; the caller must prove nonzero coefficients and no exact joint field witness is claimed.",
        "rationale": "The coarse domain transfer, not Espresso output or a wordsize-keyed mutable cache, owns the mathematics. This abstraction is distinct from the separate 94-row branch-number table and from exact field-matrix support.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_mds_matrix_test.py": {
        "v5_destination": "next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "All 256 rows match the isolated dependency-free legacy generator, including its four fixed first/last row values.", "rationale": None,
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits.py": {
        "v5_destination": "next/src/claasp_next/semantics/cryptanalysis/truncated.py; next/src/claasp_next/representations/constraints/milp/relations.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed word domains and n-ary XOR reproduce all 18 input/324 binary-XOR rows and all 1000 three-input width-three rows, including recovery of a lone nonzero term after known cancellation.",
        "rationale": "Direct semantic transfer and exact finite relations replace Espresso and mutable arity/matrix-indexed pickle caches. Unknown and nonzero words have no fabricated concrete sentinel values.",
    },
    "tests/unit/cipher_modules/models/milp/utils/generate_inequalities_for_wordwise_truncated_xor_with_n_input_bits_test.py": {
        "v5_destination": "next/tests/unit/test_wordwise_relation_tables.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "All fixed counts/rows and full generators match; the seven fixed input cubes define exactly the same domain, and four fixed three-input XOR cubes reject no valid row.",
        "rationale": "Exact semantic rows supersede pickle-cache updates and deterministic choices of minimized Espresso cubes; no minimum-cube count is claimed.",
    },
    "claasp/cipher_modules/models/milp/utils/generate_inequalities_for_xor_with_n_input_bits.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/sat/lowering.py; next/src/claasp_next/representations/constraints/milp/boolean.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete multi-operand XOR truth tables and exact binary clause inequalities retain parity without external dependencies.",
        "rationale": "Parity clauses are compiled directly from graph wiring. LSB-first point-string enumeration, matrix-arity cache population and pickled global dictionaries are obsolete representation details.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed analysis constraints compile graph execution and projections; MiniZinc independently reproduces the full Speck-22 fixed output A86842F2.",
        "rationale": "The mutable legacy component-method factory, generated declarations and output directives are replaced by shared Boolean graph lowering and explicit projections. Unsupported components fail rather than printing and retaining stale constraints; per-component catalogue coverage is separately inventoried.",
    },
    "claasp/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete Speck-22 execution is compiled and checked through the shared Boolean-to-CP representation.",
        "rationale": "The legacy optimized builder accepts only ROTATE, SHIFT and XOR and silently omits MODADD; its smoke test establishes no nonlinear correctness. v5 uses complete execution lowering with explicit unsupported-component errors, not an incomplete model labelled optimized.",
    },
    "claasp/cipher_modules/models/sat/sat_models/sat_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/analysis/boolean.py; next/src/claasp_next/representations/constraints/sat/lowering.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Typed fixed/equal/unequal/nonzero constraints and graph projections retain execution witnesses, including full Speck-22 output A86842F2 and Simon AND recovery.",
        "rationale": "Per-component method-name dictionaries, compact-graph mutation, solver registries and result-string parsing are replaced by immutable typed graph lowering and optional drivers. Shared exact/truncated phase composition is explicit, not hidden in a method-name factory.",
    },
    "claasp/cipher_modules/models/milp/milp_models/milp_cipher_model.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/milp/boolean.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Every Boolean execution clause is translated exactly to a binary inequality; full Speck-22 scalar and GLPK witnesses reproduce A86842F2.",
        "rationale": "The legacy builder omits nonlinear operations and even documents that execution cannot be represented with inequalities. Binary clause inequalities do represent them exactly; the incomplete Sage model and its incidental 9296-constraint count are not retained.",
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "MiniZinc reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.", "rationale": None,
    },
    "tests/unit/cipher_modules/models/sat/sat_models/sat_cipher_model_test.py": {
        "v5_destination": "next/tests/integration/test_z3_integration.py",
        "prerequisites": [], "disposition": "migrate", "status": "migrated-in-m10.8d",
        "acceptance_criterion": "Boolean CLI solving reproduces the fixed full Speck-22 output A86842F2 and independent scalar execution confirms it.", "rationale": None,
    },
    "tests/unit/cipher_modules/models/cp/mzn_models/mzn_cipher_model_arx_optimized_test.py": {
        "v5_destination": "next/tests/integration/test_minizinc_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Complete full-round execution is solved and independently validated rather than merely constructed.",
        "rationale": "The assertion-free legacy construction smoke test accepts a builder that skips modular addition; a checked complete execution witness supersedes it.",
    },
    "tests/unit/cipher_modules/models/milp/milp_models/milp_cipher_model_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_graph_milp.py; next/tests/integration/test_glpk_integration.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Exact binary-linear clauses match complete truth tables and full Speck-22 graph witnesses, including modular additions omitted by the legacy builder.",
        "rationale": "Legacy Sage variable names, first/last wiring inequalities and the count 9296 describe an incomplete encoding, not a fixed scientific result.",
    },
    "claasp/cipher_modules/models/cp/minizinc_utils/utils.py": {
        "v5_destination": "next/src/claasp_next/representations/constraints/cp/model.py",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed model declarations retain explicit identities; no variable groups are inferred by parsing declaration strings.",
        "rationale": "The only helpers filter declaration strings and infer groups from legacy _y names. Typed graph ports and immutable MiniZinc model parts remove this formatting-dependent responsibility.",
    },
    "claasp/cipher_modules/models/sat/utils/constants.py": {
        "v5_destination": "next/src/claasp_next/graph",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Input/output port identities and logical selections are typed independently of solver variable suffixes.",
        "rationale": "The file contains only _i and _o formatting constants, which are not v5 public model contracts.",
    },
    "claasp/cipher_modules/models/milp/utils/milp_name_mappings.py": {
        "v5_destination": "next/src/claasp_next/semantics; next/src/claasp_next/representations/constraints/milp",
        "prerequisites": [], "disposition": "remove", "status": "removed-in-m10.8d",
        "acceptance_criterion": "Typed semantic descriptors, objectives and result types distinguish mathematical problems from MILP representations.",
        "rationale": "Model dictionary tags, progress messages, decimal-weight precision and variable suffixes are removed; exact component probabilities and explicit objective descriptors own the scientific meaning.",
    },
    "claasp/cipher_modules/models/cp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minizinc.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "Optional MiniZinc driver accepts an explicit solver id and executable without requiring a Python MiniZinc or Sage package.",
        "rationale": "Hard-coded command dictionaries, internal/external API duplicates, and assumed installed solver brands are replaced by explicit driver configuration and executable discovery. Proprietary MiniZinc solver ids can be selected optionally, never required by baseline CI.",
    },
    "claasp/cipher_modules/models/milp/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/glpk.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "GLPK command driver provides a Sage-independent open MILP baseline; the portable representation and driver protocol do not depend on a proprietary optimizer.",
        "rationale": "The Sage backend registry, cwd captured at import time and solver-brand output regex dictionaries are not migrated APIs. Third-party optimizers can implement the explicit driver protocol without entering the core dependency set; this does not claim a v5 adapter exists for every legacy solver brand.",
    },
    "claasp/cipher_modules/models/sat/solvers.py": {
        "v5_destination": "next/src/claasp_next/drivers/solvers/minisat.py; next/src/claasp_next/drivers/base.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
        "acceptance_criterion": "MiniSat and CLI Z3 provide optional open Boolean solving with named assignments and independently verified witnesses.",
        "rationale": "Sage internal solver lists and command-format dictionaries are replaced by explicit driver objects. No installation is inferred from a registry entry. Legacy brand aliases and exact timing/memory log labels are not compatibility contracts; mathematical fixture ownership stays with separate inventoried model tests.",
    },
    "tests/unit/cipher_modules/models/sat/utils/sat_model_utils_test.py": {
        "v5_destination": "next/tests/unit/test_boolean_cnf.py",
        "prerequisites": [], "disposition": "supersede", "status": "superseded-in-m10.8d",
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
    "claasp/cipher_modules/models/smt/solvers.py": (
        "next/src/claasp_next/drivers/solvers/z3.py"
    ),
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

MIGRATION_OVERRIDES.update({
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
})


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
    "cms_cipher_model_test": ("migrate", "next/tests/integration/test_z3_integration.py", "Preserve the complete Speck32/64-22 vector 0x6574694C, 0x1918111009080100 -> 0xA86842F2 with real solving and independent evaluation."),
    "cms_xor_linear_model_test": ("migrate", "next/tests/integration/test_speck_trail_enumeration.py", "Prove Speck32/64-4 bound 2 UNSAT and bound 3 SAT; independently recount all correlations and wiring."),
    "cms_xor_differential_model_test": ("supersede", "next/tests/unit/test_cms_inventory_parity.py", "Supported full Speck32/64 differential construction is nonempty; changing the weight bound retains exact round relations and changes the explicit bound."),
    "cms_deterministic_truncated_xor_differential_model_test": ("supersede", "next/tests/unit/test_truncated_differences.py", "Typed deterministic-truncated modular-add semantics and Speck propagation replace an assertion-free construction smoke test."),
}
for _module, (_disposition, _destination, _criterion) in _CMS_TEST_REPLACEMENTS.items():
    MIGRATION_OVERRIDES[f"tests/unit/cipher_modules/models/sat/cms_models/{_module}.py"] = {
        "v5_destination": _destination,
        "prerequisites": [],
        "disposition": _disposition,
        "status": "migrated-in-m10.8d" if _disposition == "migrate" else "superseded-in-m10.8d",
        "acceptance_criterion": _criterion,
        "rationale": None if _disposition == "migrate" else "Mutable CMS constraint counts and construction-only smoke tests are replaced by explicit immutable representation and shared-semantic invariants.",
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


def _catalogue_metadata(relative: Path, entries: list[str]) -> dict[str, Any] | None:
    parts = relative.parts
    if len(parts) < 3 or parts[0:2] != ("claasp", "ciphers"):
        return None
    directory = parts[2]
    if directory not in CATEGORY_BY_DIRECTORY or relative.name == "__init__.py":
        return None
    official_name = _official_name(entries, relative.stem)
    high_level_parent = directory if directory in {"hash_functions", "mac", "stream_ciphers"} else None
    category = CATEGORY_BY_DIRECTORY[directory]
    return {
        "official_name": official_name,
        "primitive_category": category,
        "proposed_module": f"claasp_next.primitives.{category}.{relative.stem}",
        "proposed_class": official_name,
        "higher_level_parent": high_level_parent,
        "classification_basis": (
            "provisional fixed-length core classification; confirm bijectivity and interface during M10.9b"
            if high_level_parent
            else "legacy catalogue semantics; validate category invariant during M10.9b"
        ),
    }


def _destination(relative: Path, catalogue: dict[str, Any] | None) -> str:
    if catalogue:
        return catalogue["proposed_module"].replace(".", "/") + ".py"
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
    catalogue = _catalogue_metadata(relative, entries)
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
    item.update(MIGRATION_OVERRIDES.get(relative.as_posix(), {}))
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


def serialized_inventory() -> str:
    return json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"


def model_closure_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Report unresolved M10.8 model entries without treating deferrals as done."""
    records = [item for item in payload["records"] if "/models/" in item["path"]]
    unresolved = [item for item in records
                  if item["status"] == "planned-or-partially-migrated"
                  or item["disposition"] == "defer"
                  or "destination finalized" in item["v5_destination"]]
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the checked-in inventory is stale")
    parser.add_argument("--model-status", action="store_true", help="report remaining M10.8 model work without rewriting the inventory")
    parser.add_argument("--check-model-closure", action="store_true", help="fail until all M10.8 model entries are resolved, including deferrals")
    args = parser.parse_args()
    if args.model_status or args.check_model_closure:
        status = model_closure_status(build_inventory())
        print(json.dumps({key: value for key, value in status.items() if key != "unresolved"}, indent=2))
        return int(args.check_model_closure and not status["complete"])
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
