import pytest

from claasp_next.drivers.solvers.minizinc import CPStatus, _parse_output
from claasp_next.representations.constraints.cp import MiniZincModel


def test_minizinc_model_serializes_sections_in_language_order():
    model = MiniZincModel(
        includes=('include "alldifferent.mzn";',),
        declarations=("var 0..3: x;",),
        constraints=("constraint x = 2;",),
        solve="solve minimize x;",
        outputs=('output ["x=", show(x)];',),
        provenance=("unit fixture",),
    )

    assert model.source() == (
        'include "alldifferent.mzn";\n'
        "var 0..3: x;\n"
        "constraint x = 2;\n"
        "solve minimize x;\n"
        'output ["x=", show(x)];\n'
    )


def test_minizinc_json_and_terminal_statuses_are_backend_neutral():
    assert _parse_output('{\n  "x": 2, "bits": [0, 1]\n}\n----------\n') == (
        CPStatus.SATISFIED,
        {"x": 2, "bits": [0, 1]},
    )
    assert _parse_output("=====UNSATISFIABLE=====\n") == (CPStatus.UNSATISFIABLE, None)
    assert _parse_output("=====UNKNOWN=====\n") == (CPStatus.UNKNOWN, None)


def test_minizinc_model_and_driver_validate_public_boundaries():
    with pytest.raises(ValueError, match="solve item"):
        MiniZincModel((), (), "satisfy;")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        _parse_output("not-json\n----------\n")
