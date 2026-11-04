"""Generic primitive facade, explicit fixed inputs and statistical contracts."""

from fractions import Fraction

import pytest

from claasp import Primitive, UnitArrayType
from claasp.analysis.circle_linear import CircleLinearAnalysis
from claasp.components import Power
from claasp.primitives import BitVectorSBox, Craft
from claasp.primitives.single_component_primitives import ModularAdd
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.unit_types import PrimeField


def test_full_primitive_correlation_and_endpoint_optimization_match_direct_oracle():
    table = (0, 3, 1, 2)
    primitive = BitVectorSBox(2, table)
    analysis = primitive.analysis.circle_linear(input_name="input")
    coefficients = {}
    for a in range(4):
        for b in range(4):
            expected = Fraction(
                sum(
                    (-1) ** (((a & x).bit_count() + (b & table[x]).bit_count()) & 1)
                    for x in range(4)
                ),
                4,
            )
            coefficients[a, b] = expected
            assert analysis.correlation(a, b) == expected
            assert analysis.lookup_layer().coefficient(a, b) == expected
    best = analysis.best_approximation()
    assert abs(best.coefficient) == max(abs(c) for (a, b), c in coefficients.items() if a and b)
    assert best.complete


def test_arithmetic_primitive_uses_fixed_operand_instead_of_key_average():
    primitive = ModularAdd(word_bit_size=4)
    names = tuple(primitive.graph.input_arrays)
    analysis = primitive.analysis.circle_linear(input_name=names[0], bibrace=BinaryBibrace.craft())
    for fixed in (0, 1, 7):
        expected = Fraction(
            sum(
                (-1)
                ** (
                    BinaryBibrace.craft().character(9, x)
                    ^ BinaryBibrace.craft().character(9, (x + fixed) & 15)
                )
                for x in range(16)
            ),
            16,
        )
        assert analysis.correlation(9, 9, fixed_inputs={names[1]: fixed}) == expected
    with pytest.raises(ValueError, match="fixed_inputs"):
        analysis.correlation(1, 1)


def test_binary_field_power_and_fixed_variable_rotation_are_measurable():
    from claasp.primitives.single_component_primitives import Power, VariableRotate
    from claasp.unit_types import BinaryExtensionField

    power = Power(exponent=7, unit_type=BinaryExtensionField(4, 0x13))
    analysis = power.analysis.circle_linear(input_name="input", bibrace=BinaryBibrace.craft())
    direct = Fraction(
        sum(
            (-1)
            ** (
                BinaryBibrace.craft().character(9, x)
                ^ BinaryBibrace.craft().character(7, power.evaluate(x))
            )
            for x in range(16)
        ),
        16,
    )
    assert analysis.correlation(9, 7) == direct
    rotation = VariableRotate(bit_size=4, amount_bit_size=2)
    ordinary = rotation.analysis.circle_linear(input_name="input")
    assert ordinary.correlation(1, 8, fixed_inputs={"amount": 1}) == 1


def test_actual_circle_basis_not_ordinary_xor_masks():
    from claasp.primitives.block_ciphers.craft import CRAFT_SBOX

    p = BitVectorSBox(4, CRAFT_SBOX)
    circle = p.analysis.circle_linear(input_name="input", bibrace=BinaryBibrace.craft())
    ordinary = p.analysis.circle_linear(input_name="input")
    assert circle.correlation(9, 9) == 1
    assert ordinary.correlation(9, 9) != 1


def test_seeded_estimation_interval_and_small_exact_oracle():
    p = BitVectorSBox(3, (0, 1, 2, 3, 4, 5, 7, 6))
    analysis = p.analysis.circle_linear(input_name="input")
    first = analysis.estimate_correlation(1, 1, samples=4096, seed=123)
    assert first == analysis.estimate_correlation(1, 1, samples=4096, seed=123)
    exact = float(analysis.correlation(1, 1))
    assert first.lower <= exact <= first.upper
    assert not first.complete and first.standard_error > 0
    identity = BitVectorSBox(1, (0, 1)).analysis.circle_linear(input_name="input")
    certain = identity.estimate_correlation(1, 1, samples=8)
    assert certain.standard_error == 0 and certain.lower < 1


def test_large_craft_domain_is_rejected_before_any_evaluation(monkeypatch):
    p = Craft(number_of_rounds=8)
    monkeypatch.setattr(
        p, "evaluate", lambda *a, **k: pytest.fail("budget must be checked before evaluation")
    )
    analysis = p.analysis.circle_linear(bibrace=BinaryBibrace.craft())
    for call in (
        lambda: analysis.correlation(1, 1),
        lambda: analysis.lookup_layer(),
        lambda: analysis.best_approximation(),
    ):
        with pytest.raises(ValueError, match="exceeds"):
            call()


def test_prime_field_rejection_is_explicit():
    p = Primitive("prime", {"x": UnitArrayType(PrimeField(17), (1,))})
    p._builder.add_round()
    p._builder.set_output(p._builder.add_component(Power(p.graph.input("x"), 3)))
    with pytest.raises(NotImplementedError, match="odd-prime"):
        p.analysis.circle_linear(input_name="x")


def test_explicit_layout_validation_and_fixed_input_contracts():
    p = BitVectorSBox(4, tuple(range(16)))
    basis = CircleBasis((BinaryBibrace(2),) * 2)
    assert (
        CircleLinearAnalysis(
            p, input_name="input", input_basis=basis, output_basis=basis
        ).correlation(3, 3)
        == 1
    )
    for kwargs in (
        {"input_name": "missing"},
        {"input_name": "input", "bibrace": BinaryBibrace(3)},
        {"input_name": "input", "bibrace": BinaryBibrace(4), "input_basis": basis},
    ):
        with pytest.raises(ValueError):
            CircleLinearAnalysis(p, **kwargs)
    a = p.analysis.circle_linear(input_name="input")
    with pytest.raises(ValueError):
        a.correlation(1, 1, fixed_inputs={"extra": 0})
    for sampling_options in ({"samples": 0}, {"samples": True}, {"confidence": 1}, {"seed": True}):
        with pytest.raises(ValueError):
            a.estimate_correlation(1, 1, **sampling_options)


def test_basic_guides_downloadable_examples_return_reportable_results():
    import runpy
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for name, expected in (
        ("basic_circle_linear.py", 8),
        ("basic_circle_linear_correlations.py", -1),
    ):
        example = runpy.run_path(str(root / "docs" / "examples" / name))
        result = example["run_example"]()
        assert callable(result.to_terminal) and callable(result.plot)
        assert (result.cost if hasattr(result, "cost") else result.coefficient) == expected
