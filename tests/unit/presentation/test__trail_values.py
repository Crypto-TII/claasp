"""Exact trail notations preserve declared widths and evidence in every view."""

from importlib import import_module
from io import StringIO

import pytest

from claasp.presentation._trail_values import _format_trail_value
from claasp.semantics.cryptanalysis import (
    Trail,
    TrailKind,
    TrailSearchMetadata,
    TrailSearchResult,
    TrailStep,
    Transition,
    XorDifference,
    XorMask,
)


@pytest.mark.parametrize("details", (False, True))
@pytest.mark.parametrize("kind", ("Linear", "Differential"))
@pytest.mark.parametrize(
    "notation,expected", (("hex", "0x1"), ("binary", "0b00000001"), ("underscore_one", "_______1"))
)
def test_characteristic_and_enumeration_values_use_one_notation(kind, details, notation, expected):
    module = import_module(f"claasp.representations.constraints.smt.word_xor_{kind.lower()}")
    characteristic = getattr(module, f"WordXor{kind}Characteristic")
    enumeration = getattr(module, f"WordXor{kind}Enumeration")
    pattern = XorMask if kind == "Linear" else XorDifference
    trail_kind = TrailKind.XOR_LINEAR if kind == "Linear" else TrailKind.XOR_DIFFERENTIAL
    transition = Transition(
        trail_kind, pattern(1, 8), pattern(2, 8), 1, 2, -1 if kind == "Linear" else 1
    )
    args = ((("plaintext", 1), ("key", 0)), 2, (TrailStep("sbox", transition),))
    trail = (
        characteristic(*args, -1, (), (("plaintext", 8), ("key", 16)), 8)
        if kind == "Linear"
        else characteristic(*args, (), (("plaintext", 8), ("key", 16)), 8)
    )
    for result in (trail, enumeration((trail,), False, 0.25)):
        output = StringIO()
        result.to_terminal(details=details, value_format=notation, file=output)
        text = output.getvalue()
        assert expected in text
        if notation != "hex":
            assert "0x" not in text
            assert ("0b0000000000000000" if notation == "binary" else "_" * 16) in text
        assert ("sbox" in text) == details
        assert trail.total_weight == 1
    if notation != "hex" and details:
        assert ("0b00000010" if notation == "binary" else "______1_") in text


@pytest.mark.parametrize("details", (False, True))
@pytest.mark.parametrize("linear", (False, True))
def test_common_trails_and_optimized_results_include_named_inputs(details, linear):
    pattern = XorMask if linear else XorDifference
    kind = TrailKind.XOR_LINEAR if linear else TrailKind.XOR_DIFFERENTIAL
    transition = Transition(kind, pattern(1, 8), pattern(2, 8), 1, 2)
    trail = Trail(kind, pattern(1, 8), pattern(2, 8), (TrailStep("sbox", transition),))
    result = TrailSearchResult(
        trail, 1.0, TrailSearchMetadata("example"), input_patterns=(("key", pattern(0, 16)),)
    )
    for item in (trail, result):
        output = StringIO()
        item.to_terminal(details=details, value_format="binary", file=output)
        assert "0b00000001" in output.getvalue() and "0b00000010" in output.getvalue()
        assert "0x" not in output.getvalue()
    assert "key" in output.getvalue() and "0b0000000000000000" in output.getvalue()


@pytest.mark.parametrize("value,width", ((-1, 8), (256, 8), (1, 0), (True, 1)))
def test_invalid_values_or_widths_are_rejected(value, width):
    with pytest.raises(ValueError):
        _format_trail_value(value, width, value_format="binary")


def test_bad_notation_rejected_even_for_an_empty_enumeration():
    from claasp.representations.constraints.smt.word_xor_linear import WordXorLinearEnumeration

    with pytest.raises(ValueError, match="value_format"):
        WordXorLinearEnumeration((), True, 0).to_terminal(value_format="octal")
    assert _format_trail_value(0, value_format="binary") == "0b0"
    assert _format_trail_value(0, value_format="underscore_one") == "_"


@pytest.mark.parametrize("kind", ("linear", "differential"))
def test_model_decoding_retains_widths_even_for_all_zero_values(kind):
    from claasp import Primitive, UnitArrayType
    from claasp.unit_types import Bit

    module = import_module(f"claasp.representations.constraints.smt.word_xor_{kind}")
    model_type = getattr(module, f"WordXor{kind.title()}SMTModel")
    primitive = Primitive("identity", {"plaintext": UnitArrayType(Bit(), (8,))})
    primitive._builder.add_round()
    primitive._builder.set_output(primitive.graph.input("plaintext"))
    model = model_type(primitive, nonzero_input=None)
    formula = model.smt_formula()
    trail = model.decode_characteristic(dict.fromkeys(formula.variables, 0))
    assert trail.input_widths == (("plaintext", 8),) and trail.output_width == 8
    output = StringIO()
    trail.to_terminal(value_format="binary", file=output)
    assert output.getvalue().count("0b00000000") == 2


def test_exact_trails_keep_their_existing_hexadecimal_default():
    trail = Trail(TrailKind.XOR_DIFFERENTIAL, XorDifference(1, 8), XorDifference(2, 8), ())
    output = StringIO()
    trail.to_terminal(file=output)
    assert "0x01" in output.getvalue() and "0x02" in output.getvalue()
    assert "0b" not in output.getvalue()
