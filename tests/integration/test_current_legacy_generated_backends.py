"""Generated backends checked against current-legacy outputs, not just v5 scalar."""

import enum
import importlib
import inspect
import json
from pathlib import Path

import pytest

from claasp import compile_source, run_python_source
from claasp.drivers.native import (
    NativeCompilationStatus,
    NativeExecutionStatus,
    compile_native,
    run_compiled,
)
from claasp.drivers.source import SourceExecutionStatus

CASES = json.loads(Path("tests/fixtures/legacy_parity/round_traces.json").read_text())["cases"]


ARX = {"Speck", "Simon", "RC5", "TEA", "XTEA", "LEA", "HIGHT"}
CONFIGURATIONS = [pytest.param("python", case, id="python-" + case["class"]) for case in CASES]
CONFIGURATIONS += [
    pytest.param("c", case, marks=pytest.mark.external, id="c-" + case["class"])
    for case in CASES
    if case["class"] in ARX
]


@pytest.mark.parametrize("target,case", CONFIGURATIONS)
def test_generated_backend_matches_pinned_legacy_evaluation(target, case):
    cls = getattr(importlib.import_module(case["module"]), case["class"])
    options = dict(case["parameters"])
    for name, parameter in inspect.signature(cls).parameters.items():
        if isinstance(parameter.default, enum.Enum) and name in options:
            options[name] = type(parameter.default)[options[name]]
    primitive = cls(**options)
    inputs = dict(zip(primitive.graph.input_arrays, case["inputs"]))
    source = compile_source(primitive, target=target).artifact
    assert source is not None
    if target == "python":
        generated = run_python_source(source, primitive, inputs)
        assert generated.status is SourceExecutionStatus.SUCCESS, generated.stderr
        output = generated.output
    else:
        compilation = compile_native(source, compiler="cc")
        assert compilation.status is NativeCompilationStatus.SUCCESS, compilation.stderr
        assert compilation.artifact is not None
        executed = run_compiled(compilation.artifact, primitive, inputs)
        assert executed.status is NativeExecutionStatus.SUCCESS, executed.stderr
        output = executed.output
    assert primitive.graph.output is not None
    assert primitive._encode_boundary(output, primitive.graph.output.array_type) == case["output"]
