from dataclasses import replace
from pathlib import Path

import pytest

from claasp import compile_source, run_python_source, write_source
from claasp.drivers.source import SourceExecutionStatus
from claasp.primitives import Present, Speck
from claasp.representations.source import SourceStatus


def test_python_source_is_byte_stable_and_contains_no_host_or_temporary_paths():
    first = compile_source(Speck(32, 64, number_of_rounds=2), target="python")
    second = compile_source(Speck(32, 64, number_of_rounds=2), target="python")
    assert first == second
    assert first.status is SourceStatus.READY
    assert first.artifact.source.endswith("\n")
    assert str(Path.cwd()) not in first.artifact.source
    assert "/tmp/" not in first.artifact.source
    assert "datetime" not in first.artifact.source
    assert first.artifact.compiler.kind.value == "compiler"


def test_generated_python_executes_in_isolation_with_scalar_and_trace_order_parity():
    primitive = Speck(32, 64, number_of_rounds=2)
    inputs = {"plaintext": 0x6574694C, "key": 0x1918111009080100}
    artifact = compile_source(primitive).artifact
    generated = run_python_source(artifact, primitive, inputs)
    scalar = primitive.evaluate_with_trace(inputs)
    assert generated.status is SourceExecutionStatus.SUCCESS
    assert generated.output == scalar.output
    assert tuple(name for name, _ in generated.values) == tuple(scalar.values)
    assert generated.command[:3] == (generated.command[0], "-I", "-c")
    assert generated.return_code == 0
    assert generated.source_digest == artifact.source_digest
    assert generated.provenance.realization == primitive.realization
    assert generated.provenance.driver.name == "python_generated_source"


def test_generated_python_handles_bit_graphs_and_rejects_mismatched_artifacts():
    primitive = Present(number_of_rounds=1)
    artifact = compile_source(primitive).artifact
    generated = run_python_source(artifact, primitive, {"plaintext": 0, "key": 0})
    assert generated.output == primitive.evaluate_with_trace(0, 0).output
    with pytest.raises(ValueError, match="different primitive"):
        run_python_source(artifact, Present(number_of_rounds=2), {"plaintext": 0, "key": 0})


def test_source_writing_requires_explicit_extension_and_overwrite(tmp_path):
    artifact = compile_source(Present(number_of_rounds=1)).artifact
    destination = tmp_path / "evaluator.py"
    assert write_source(artifact, destination) == destination
    assert destination.read_text(encoding="utf-8") == artifact.source
    with pytest.raises(FileExistsError):
        write_source(artifact, destination)
    write_source(artifact, destination, overwrite=True)
    with pytest.raises(ValueError, match="end in .py"):
        write_source(artifact, tmp_path / "evaluator.c")
    with pytest.raises(ValueError, match="parent directory"):
        write_source(artifact, tmp_path / "missing" / "evaluator.py")
    with pytest.raises(ValueError, match="safe basename"):
        replace(artifact, filename="../escape.py")
    with pytest.raises(ValueError, match="digest"):
        replace(artifact, source_digest="0" * 64)


def test_unknown_language_is_an_explicit_unsupported_result():
    result = compile_source(Present(number_of_rounds=1), target="cuda")
    assert result.status is SourceStatus.UNSUPPORTED
    assert result.diagnostic.code == "unsupported_language"
