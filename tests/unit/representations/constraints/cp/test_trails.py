"""Complete CP trail assembly."""

from claasp.primitives import ToySpeck
from claasp.representations.constraints.cp import (
    WordDeterministicTruncatedCPModel,
    WordDifferentialCPModel,
    WordLinearCPModel,
)


def test_deterministic_truncated_cp_assembles_complete_word_graph():
    model = WordDeterministicTruncatedCPModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
        output_pattern="???0????",
    )
    query = model.cp_model()
    assert len(query.declarations) == 200
    assert len(query.constraints) == 829
    assert query.constraint_models[0].model == model.model_provenance


def test_differential_cp_assembles_complete_word_graph():
    model = WordDifferentialCPModel(
        ToySpeck(2),
        fixed_weight=1,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (187, 501)
    assert query.constraint_models[0].model == model.model_provenance


def test_linear_cp_assembles_complete_word_graph():
    model = WordLinearCPModel(
        ToySpeck(3), maximum_weight=1, fixed_inputs={"key": 0}, nonzero_input="plaintext"
    )
    query = model.cp_model()
    assert (len(query.declarations), len(query.constraints)) == (296, 706)
    assert query.constraint_models[0].model == model.model_provenance
