from io import StringIO

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import Xor
from claasp.primitives import Present, Simon
from claasp.unit_types import Bit


def test_exact_anf_coefficients_degrees_and_superpoly():
    result = Simon(number_of_rounds=1).analysis.anf(output_bit=0)
    assert result.degrees == (2,)
    assert result.coefficient(("p1", "p8")) == (1,)
    assert result.coefficient(("p1",)) == (0,)
    assert result.degree_in(("k48",)) == (1,)
    coefficient = result.superpoly(("p1",))
    assert coefficient.degrees == (1,)
    assert coefficient.coefficient(("p8",)) == (1,)
    output = StringIO()
    coefficient.to_terminal(details=True, file=output)
    assert "p8" in output.getvalue()
    with pytest.raises(ValueError):
        result.coefficient(("unknown",))
    with pytest.raises(ValueError):
        result.superpoly(("p1",), fixed_variables={"p1": 1})


def test_fixed_inputs_are_substituted_before_expansion_and_budget_is_reset():
    primitive = Simon(number_of_rounds=2)
    with pytest.raises(RuntimeError, match="maximum_"):
        primitive.analysis.anf(maximum_terms=1)
    assert (
        primitive.analysis.anf(fixed_inputs={"plaintext": 0, "key": 0}, maximum_terms=1).degrees
        == (-1,) * 32
    )
    assert primitive.analysis.anf(output_bit=0).complete
    with pytest.raises(RuntimeError, match="maximum_operations"):
        primitive.analysis.anf(maximum_operations=1)


def test_full_input_prefixes_do_not_merge_unrelated_variables():
    primitive = Primitive(
        "prefixes", {"alpha": UnitArrayType(Bit(), (1,)), "apple": UnitArrayType(Bit(), (1,))}
    )
    primitive._builder.add_round()
    out = primitive._builder.add_component(
        Xor((primitive.graph.input("alpha"), primitive.graph.input("apple")))
    )
    primitive._builder.set_output(out)
    result = primitive.analysis.anf()
    assert result.degrees == (1,)
    assert set(result.variables) == {"alpha_0", "apple_0"}


def test_lookup_and_bit_add_symbolic_outputs_match_present_evaluation():
    primitive = Present(number_of_rounds=1)
    result = primitive.analysis.anf(fixed_inputs={"key": 0})
    for plaintext in (0, 1, 0x123456789ABCDEF, (1 << 64) - 1):
        assignment = {f"p{i}": (plaintext >> (63 - i)) & 1 for i in range(64)}
        value = sum(
            poly.evaluate(assignment) << (63 - i) for i, poly in enumerate(result.polynomials)
        )
        assert value == primitive.evaluate(plaintext=plaintext, key=0)
