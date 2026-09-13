from claasp_next.representations.execution import ScalarEvaluator
from claasp_next.parameters import poseidon_bn254_width3


def test_bn254_width3_parameters_match_pinned_reference_vector():
    parameters = poseidon_bn254_width3()

    result = ScalarEvaluator().evaluate(
        parameters.permutation(),
        {"state": parameters.reference_input},
    )

    assert parameters.width == 3
    assert len(parameters.round_constants) == 65
    assert result.output[parameters.reference_output_position] == parameters.reference_output


def test_bn254_width3_parameter_provenance_is_pinned():
    parameters = poseidon_bn254_width3()

    assert parameters.schema_version == 1
    assert parameters.source_license == "MIT"
    assert parameters.source_commit == "5194eadce26b3fe4b1c4fe2a5ca9f6436f3b0e3d"
