import shutil
from dataclasses import replace
from hashlib import sha256

import pytest

from claasp import compile_source
from claasp.drivers.native import (
    NativeCompilationStatus,
    NativeExecutionStatus,
    compile_native,
    run_compiled,
)
from claasp.primitives import Present, Speck

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
            compilation.artifact,
            Speck(32, 64, number_of_rounds=2),
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


@pytest.mark.parametrize("permutation", [(0, 1), (1, 0)])
def test_generated_c_shares_pack_permute_unpack_and_fanout_wiring(permutation):
    from claasp import Primitive, UnitArrayType
    from claasp.components import Identity, Permutation, Xor
    from claasp.unit_types import Bit

    primitive = Primitive("binding_codegen", {"input": UnitArrayType(Bit(), (4,))})
    b = primitive._builder
    b.add_round()
    original = primitive.graph.input("input")
    packed = b.pack_bits(original, 2)
    moved = b.add_component(Permutation(packed, permutation))
    selected = b.unpack_bits(moved)
    out = b.add_component(Xor((original, selected)))
    b.add_component(Identity(selected))  # The declared output is not the last node.
    b.set_output(out)
    source = compile_source(primitive, target="c").artifact
    compiled = compile_native(source, compiler=_compiler(), options=("-O2",))
    assert compiled.status is NativeCompilationStatus.SUCCESS, compiled.stderr
    assert compiled.artifact is not None
    for x in range(16):
        result = run_compiled(compiled.artifact, primitive, {"input": x})
        expected = x ^ (((x & 3) << 2) | (x >> 2)) if permutation == (1, 0) else 0
        assert result.status is NativeExecutionStatus.SUCCESS, result.stderr
        assert result.output == tuple((expected >> bit) & 1 for bit in reversed(range(4)))
