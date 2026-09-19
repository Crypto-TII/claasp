import shutil
from dataclasses import replace
from hashlib import sha256

import pytest

from claasp_next import compile_source
from claasp_next.drivers.native import (
    NativeCompilationStatus, NativeExecutionStatus, compile_native, run_compiled,
)
from claasp_next.primitives import Present, Speck


pytestmark = pytest.mark.external


def _compiler():
    for name in ("cc", "clang", "gcc"):
        if shutil.which(name):
            return name
    pytest.skip("no C compiler is available")


@pytest.mark.parametrize(
    ("primitive", "inputs"),
    [
        (Speck(32, 64, number_of_rounds=2), {"plaintext": 0x6574694C, "key": 0x1918111009080100}),
        (Present(number_of_rounds=1), {"plaintext": 0, "key": 0}),
    ],
)
def test_generated_c_compiles_and_matches_scalar_evaluation(primitive, inputs):
    source = compile_source(primitive, target="c").artifact
    compilation = compile_native(source, compiler=_compiler(), options=("-O2", "-Wall"))
    assert compilation.status is NativeCompilationStatus.SUCCESS, compilation.stderr
    assert compilation.artifact.compiler_version
    assert compilation.artifact.source_digest == source.source_digest
    assert compilation.artifact.command == compilation.command
    result = run_compiled(compilation.artifact, primitive, inputs)
    scalar = primitive.evaluate_with_trace(inputs)
    assert result.status is NativeExecutionStatus.SUCCESS, result.stderr
    assert result.output == scalar.output
    assert result.compiler_version == compilation.compiler_version
    assert result.compiler_options == ("-O2", "-Wall")
    assert result.return_code == 0
    assert result.provenance.realization == primitive.realization


def test_compiled_artifact_rejects_a_different_graph():
    first = Speck(32, 64, number_of_rounds=1)
    source = compile_source(first, target="c").artifact
    compilation = compile_native(source, compiler=_compiler())
    assert compilation.status is NativeCompilationStatus.SUCCESS, compilation.stderr
    with pytest.raises(ValueError, match="different primitive"):
        run_compiled(
            compilation.artifact, Speck(32, 64, number_of_rounds=2),
            {"plaintext": 0, "key": 0},
        )


def test_compilation_failure_is_reported_without_an_artifact():
    primitive = Speck(32, 64, number_of_rounds=1)
    source = compile_source(primitive, target="c").artifact
    invalid = "this is not C source\n"
    source = replace(source, source=invalid, source_digest=sha256(invalid.encode()).hexdigest())
    compilation = compile_native(source, compiler=_compiler())
    assert compilation.status is NativeCompilationStatus.FAILED
    assert compilation.artifact is None
    assert compilation.return_code != 0
    assert compilation.stderr
