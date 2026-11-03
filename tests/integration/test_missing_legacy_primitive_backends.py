"""Native and batch evaluation for the primitives missed by the frozen inventory."""

import shutil

import pytest

from claasp import compile_source
from claasp.drivers.native import (
    NativeCompilationStatus,
    NativeExecutionStatus,
    compile_native,
    run_compiled,
)
from claasp.primitives import CRAX, RC6, Alzette, Blowfish


@pytest.mark.external
@pytest.mark.parametrize(
    "primitive,inputs,expected",
    [
        (Blowfish(key_bit_size=64), {"plaintext": 0}, 0x4EF997456198DD78),
        (CRAX(), {"plaintext": 0, "key": 0}, 0x72EDFAC9453F5F4C),
        (
            RC6(),
            {
                "plaintext": 0x02132435465768798A9BACBDCEDFE0F1,
                "key": 0x0123456789ABCDEF0112233445566778,
            },
            0x524E192F4715C6231F51F6367EA43F18,
        ),
        (Alzette(), {"plaintext": 0}, 0x44DD4DE9E5581F2D),
    ],
)
def test_native_evaluation_preserves_reference_vector(primitive, inputs, expected):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable")
    source = compile_source(primitive, target="c").artifact
    compilation = compile_native(source, compiler="cc")
    assert compilation.status is NativeCompilationStatus.SUCCESS, compilation.stderr
    assert compilation.artifact is not None
    result = run_compiled(compilation.artifact, primitive, inputs)
    assert result.status is NativeExecutionStatus.SUCCESS, result.stderr
    assert primitive._encode_boundary(result.output, primitive.graph.output.array_type) == expected


@pytest.mark.parametrize(
    "primitive,inputs",
    [
        (Alzette(), {"plaintext": [0, 0xDEADBEEFCAFEBABE]}),
        (CRAX(number_of_rounds=2), {"plaintext": [0, 1], "key": [0, 1]}),
        (RC6(number_of_rounds=2), {"plaintext": [0, 1], "key": [0, 1]}),
        (Blowfish(), {"plaintext": [0, 1]}),
    ],
)
def test_batch_matches_scalar(primitive, inputs):
    assert primitive.evaluate_many(**inputs) == tuple(
        primitive.evaluate(**dict(zip(inputs, values))) for values in zip(*inputs.values())
    )
