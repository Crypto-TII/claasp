"""Cross-backend import compatibility for the normalized model layout."""

from claasp.primitives.block_ciphers.present import PRESENT_SBOX
from claasp.representations.constraints.cp import SBoxXorDifferentialCPModel
from claasp.representations.constraints.cp.components import SBoxDifferenceCPModel
from claasp.representations.constraints.cp.trails import SBoxDifferenceCPModel as LegacyCPModel
from claasp.representations.constraints.milp import (
    SBoxTransitionMILPModel,
    SBoxXorDifferentialMILPModel,
    SBoxXorLinearMILPModel,
)
from claasp.representations.constraints.milp.components import (
    SBoxTransitionMILPModel as ComponentMILPModel,
)
from claasp.representations.constraints.milp.sbox import SBoxTransitionMILPModel as LegacyMILPModel
from claasp.representations.constraints.sat import CNFFormula, SBoxFunctionalSATModel
from claasp.representations.constraints.sat.cnf import CNFFormula as LegacyCNFFormula
from claasp.representations.constraints.sat.components import (
    SBoxFunctionalSATModel as ComponentSATModel,
)
from claasp.representations.constraints.sat.model import CNFFormula as SATModelFormula
from claasp.representations.constraints.smt import (
    SBoxTransitionSMTModel,
    SBoxXorDifferentialSMTModel,
    SBoxXorLinearSMTModel,
    SMTFormula,
)
from claasp.representations.constraints.smt.components import (
    SBoxTransitionSMTModel as ComponentSMTModel,
)
from claasp.representations.constraints.smt.formula import SMTFormula as LegacySMTFormula
from claasp.representations.constraints.smt.model import SMTFormula as SMTModelFormula
from claasp.representations.constraints.smt.transitions import (
    SBoxTransitionSMTModel as LegacySMTModel,
)
from claasp.semantics.cryptanalysis import TrailKind


def test_sat_model_and_component_authorities_preserve_legacy_imports():
    assert CNFFormula is SATModelFormula is LegacyCNFFormula
    assert SBoxFunctionalSATModel is ComponentSATModel


def test_smt_explicit_sbox_models_match_the_legacy_selector():
    assert SMTFormula is SMTModelFormula is LegacySMTFormula
    assert SBoxTransitionSMTModel is ComponentSMTModel is LegacySMTModel
    assert (
        SBoxXorDifferentialSMTModel(PRESENT_SBOX).smt_formula()
        == SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_DIFFERENTIAL).smt_formula()
    )
    assert (
        SBoxXorLinearSMTModel(PRESENT_SBOX).smt_formula()
        == SBoxTransitionSMTModel(PRESENT_SBOX, TrailKind.XOR_LINEAR).smt_formula()
    )


def test_milp_explicit_sbox_models_match_the_legacy_selector():
    assert SBoxTransitionMILPModel is ComponentMILPModel is LegacyMILPModel
    assert (
        SBoxXorDifferentialMILPModel(PRESENT_SBOX).milp_model()
        == SBoxTransitionMILPModel(PRESENT_SBOX, TrailKind.XOR_DIFFERENTIAL).milp_model()
    )
    assert (
        SBoxXorLinearMILPModel(PRESENT_SBOX).milp_model()
        == SBoxTransitionMILPModel(PRESENT_SBOX, TrailKind.XOR_LINEAR).milp_model()
    )


def test_cp_explicit_sbox_name_preserves_the_previous_import():
    assert SBoxXorDifferentialCPModel is SBoxDifferenceCPModel is LegacyCPModel
