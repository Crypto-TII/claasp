import pytest

from claasp import Bit, Primitive, ValueType, compile_source
from claasp.components import FeedbackRegister, FeedbackRegisterSpec, FeedbackTerm
from claasp.drivers.native import NativeCompilationStatus, compile_native
from claasp.primitives import AES, Present, Speck
from claasp.representations.source import SourceStatus


def test_c_source_is_deterministic_for_bit_and_word_graphs():
    for primitive in (Present(number_of_rounds=1), Speck(32, 64, number_of_rounds=2)):
        first = compile_source(primitive, target="c")
        second = compile_source(primitive, target="c")
        assert first == second
        assert first.status is SourceStatus.READY
        assert first.artifact.filename == "primitive_evaluator.c"
        assert first.artifact.source.startswith("#include <inttypes.h>\n")
        assert "shell=True" not in first.artifact.source


def test_c_source_reports_unsupported_field_components_honestly():
    result = compile_source(AES(number_of_rounds=1), target="c")
    assert result.status is SourceStatus.UNSUPPORTED
    assert result.diagnostic.code == "unsupported_domain"
    primitive = Primitive("feedback", {"state": ValueType(Bit(), (4,))})
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        FeedbackRegister(
            primitive.graph.input("state"),
            (FeedbackRegisterSpec(4, (FeedbackTerm(0), FeedbackTerm(1))),),
        )
    )
    primitive._builder.set_output(output)
    result = compile_source(primitive, target="c")
    assert result.diagnostic.code == "unsupported_component"
    assert result.diagnostic.component_id == "feedback_register_0_0"


def test_missing_compiler_is_unavailable_and_options_are_allowlisted():
    artifact = compile_source(Speck(32, 64, number_of_rounds=1), target="c").artifact
    result = compile_native(artifact, compiler="claasp-compiler-that-does-not-exist")
    assert result.status is NativeCompilationStatus.UNAVAILABLE
    assert result.artifact is None
    assert result.command == ()
    with pytest.raises(ValueError, match="compiler options"):
        compile_native(artifact, options=("-o", "/tmp/escape"))
    with pytest.raises(ValueError, match="basename"):
        compile_native(artifact, compiler="../../cc")
