"""Complete CP trail assembly."""

from claasp.primitives import ToySpeck
from claasp.representations.constraints.cp import WordDeterministicTruncatedCPModel


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
