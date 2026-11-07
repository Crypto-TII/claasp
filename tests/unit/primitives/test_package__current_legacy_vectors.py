"""Paired evaluations pinned to current legacy, independent of v5 expectations."""

import enum
import inspect
import json
from functools import lru_cache
from importlib import import_module
from pathlib import Path

import pytest

DATA = json.loads(Path("tests/fixtures/legacy_parity/primitive_vectors.json").read_text())


@lru_cache(maxsize=None)
def _primitive(module, name, parameters):
    cls = getattr(import_module(module), name)
    options = json.loads(parameters)
    signature = inspect.signature(cls)
    for key, value in options.items():
        default = signature.parameters[key].default
        if isinstance(default, enum.Enum) and isinstance(value, str):
            options[key] = type(default)[value]
    return cls(**options)


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda case: case["id"])
def test_current_legacy_scalar_evaluation(case):
    primitive = _primitive(
        case["new_module"], case["class"], json.dumps(case["parameters"], sort_keys=True)
    )
    assert primitive.evaluate(*case["inputs"]) == case["expected"]
