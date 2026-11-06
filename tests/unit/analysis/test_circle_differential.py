"""Actual circle-difference pairs, published regressions, budgets and traces."""

from collections import Counter
from dataclasses import replace
from fractions import Fraction
from itertools import product

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import SBox, Xor
from claasp.primitives import BitVectorSBox, Craft
from claasp.semantics.cryptanalysis.bibrace import BinaryBibrace, CircleBasis
from claasp.semantics.cryptanalysis.circle_differential import CircleDifferentialTransitionSemantics
from claasp.unit_types import Word

# Calderini–Civino–Invernizzi, JMC 18 (2024), §3.1, Figures 2–5.
# https://doi.org/10.1515/jmc-2023-0030
SBOX = (0, 14, 11, 1, 7, 12, 9, 6, 13, 3, 4, 15, 2, 8, 10, 5)
OPERATION = BinaryBibrace(4, ((0, 0, 8, 4),), (1,))
BASIS = CircleBasis((OPERATION,))


def _circle(x, y):
    # Independent formula, not theta or the implementation under test.
    return x ^ y ^ ((((x >> 3) & 1) * ((y >> 2) & 1)) ^ (((x >> 2) & 1) * ((y >> 3) & 1)))


def _spn(table=SBOX, *, publish=True):
    t = UnitArrayType(Word(4), (1,))
    p = Primitive("circle_test_spn", {"plaintext": t, "key": t})
    builder = p._builder
    state = p.graph.input("plaintext")
    selections = []
    for _ in range(3):
        builder.add_round()
        state = builder.add_component(SBox(state, table))
        state = builder.add_component(Xor((state, p.graph.input("key"))))
        selections.append(state.select_all())
        if publish:
            builder.set_round_output(state)
    builder.set_output(state)
    return p, tuple(selections)


def _direct_path(x, a, key, table=SBOX):
    y = _circle(x, a)
    result = [a]
    for _ in range(3):
        x, y = table[x] ^ key, table[y] ^ key
        result.append(_circle(x, y))
    return tuple(result)


def test_published_sbox_regression_and_every_ddt_entry_against_independent_formula():
    p = BitVectorSBox(4, SBOX)
    analysis = p.analysis.circle_differential(bibrace=OPERATION, input_name="input")
    semantics = analysis.lookup_semantics()
    ddt = semantics.difference_distribution_table()
    xor_ddt = (
        p.analysis.circle_differential(input_name="input")
        .lookup_semantics()
        .difference_distribution_table()
    )
    assert max(max(row) for row in xor_ddt[1:]) == 4
    assert max(max(row) for row in ddt[1:]) == 16
    assert ddt[7][6] == 16
    assert analysis.probability(7, 6).probability == 1
    assert all(sum(row) == 16 for row in ddt)
    for a, b in product(range(16), repeat=2):
        count = sum(_circle(SBOX[x], SBOX[_circle(x, a)]) == b for x in range(16))
        assert ddt[a][b] == count
        assert semantics.probability(a, b) == Fraction(count, 16)
    best = analysis.best_differential()
    assert best.probability == 1 and best.complete
    assert (best.input_difference, best.output_difference) == min(
        (a, b) for a in range(1, 16) for b in range(16) if ddt[a][b] == 16
    )


def test_fixed_xor_key_addition_has_key_dependent_circle_difference():
    from claasp.primitives.single_component_primitives import Xor

    primitive = Xor(word_bit_size=4)
    names = tuple(primitive.graph.input_arrays)
    analysis = primitive.analysis.circle_differential(bibrace=OPERATION, input_name=names[0])
    # Equation (1) of the same paper: delta' = delta XOR (k dot delta).
    for key, a in product(range(16), repeat=2):
        expected = a ^ (key ^ a ^ _circle(key, a))
        assert analysis.probability(a, expected, fixed_inputs={names[1]: key}).probability == 1
    with pytest.raises(ValueError, match="fixed_inputs"):
        analysis.probability(1, 1)


def test_concrete_round_trail_search_matches_independent_histories_and_prefix_counts():
    p, selections = _spn()
    a = p.analysis.circle_differential(bibrace=OPERATION)
    for key, alpha in product((0, 1, 4, 15), (1, 4, 7, 13)):
        histogram = Counter(_direct_path(x, alpha, key) for x in range(16))
        best = max(sorted(histogram), key=histogram.__getitem__)
        result = a.best_trail(alpha, fixed_inputs={"key": key})
        assert result.differences == best
        assert result.probability == Fraction(histogram[best], 16)
        assert result.boundary_labels == ("input", "round 1", "round 2", "output")
        assert result.prefix_counts == tuple(
            sum(c for path, c in histogram.items() if path[:i] == best[:i]) for i in range(1, 5)
        )
        probability = Fraction(1)
        for conditional in result.conditional_probabilities:
            probability *= conditional
        assert probability == result.probability
        assert _direct_path(result.witness[0], alpha, key) == best
        assert (
            a.trail_probability(best, fixed_inputs={"key": key}).prefix_counts
            == result.prefix_counts
        )
        for output in range(16):
            endpoint = a.probability(alpha, output, fixed_inputs={"key": key})
            assert endpoint.probability == sum(
                (Fraction(c, 16) for path, c in histogram.items() if path[-1] == output), Fraction()
            )
        constrained = a.best_trail(alpha, best[-1], fixed_inputs={"key": key})
        assert constrained.differences == best
    # Explicit selections use the same trace and structural-binding resolver.
    custom = a.best_trail(7, fixed_inputs={"key": 1}, boundaries=selections[:2])
    assert custom.differences == a.best_trail(7, fixed_inputs={"key": 1}).differences


def test_joint_concrete_trail_probability_is_not_product_of_unconditioned_ddts():
    # This invertible nonlinear S-box creates dependent successive events.
    table = (0, 1, 2, 3, 4, 5, 7, 6, 8, 9, 10, 11, 12, 13, 15, 14)
    p, _ = _spn(table)
    analysis = p.analysis.circle_differential(bibrace=OPERATION)
    local = CircleDifferentialTransitionSemantics(BASIS, BASIS, table)
    discrepancies = []
    for alpha in range(1, 16):
        histories = Counter(_direct_path(x, alpha, 0, table) for x in range(16))
        for path, count in histories.items():
            naive = Fraction(1)
            for left, right in zip(path, path[1:]):
                naive *= local.probability(left, right)
            if naive != Fraction(count, 16):
                actual = analysis.trail_probability(path, fixed_inputs={"key": 0})
                assert actual.probability == Fraction(count, 16)
                discrepancies.append((naive, actual.probability))
    assert discrepancies


def test_uniform_sampling_is_seeded_and_intervals_cover_nontrivial_oracle():
    analysis = BitVectorSBox(4, SBOX).analysis.circle_differential(input_name="input")
    result = analysis.estimate_probability(1, 10, samples=4096, seed=9)
    assert result == analysis.estimate_probability(1, 10, samples=4096, seed=9)
    assert result.lower <= float(analysis.probability(1, 10).probability) <= result.upper
    assert result.standard_error > 0 and not result.complete
    impossible = analysis.estimate_probability(1, 0, samples=8)
    assert impossible.hits == 0 and impossible.upper > 0
    p, _ = _spn()
    a = p.analysis.circle_differential(bibrace=OPERATION)
    trail = a.best_trail(4, fixed_inputs={"key": 3})
    sampled = a.trail_probability(trail.differences, fixed_inputs={"key": 3}, samples=1000, seed=10)
    assert sampled == a.trail_probability(
        trail.differences, fixed_inputs={"key": 3}, samples=1000, seed=10
    )
    assert sampled.evidence.lower <= float(trail.probability) <= sampled.evidence.upper
    assert not sampled.searched and not sampled.evidence.complete


def test_impossible_event_has_zero_prefix_no_witness_and_undefined_later_conditionals():
    p, _ = _spn()
    a = p.analysis.circle_differential(bibrace=OPERATION)
    result = a.trail_probability((7, 0, 0, 0), fixed_inputs={"key": 0})
    assert result.prefix_counts == (16, 0, 0, 0)
    assert result.conditional_probabilities == (0, None, None)
    assert result.witness is None and result.probability == 0
    assert a.best_trail(7, 0, fixed_inputs={"key": 0}) is None


def test_rectangular_nonpermutation_and_mixed_boundary_layouts():
    input_basis = CircleBasis((OPERATION, BinaryBibrace(1)))
    output_basis = CircleBasis((BinaryBibrace(2),))
    table = tuple((x ^ (x >> 3)) & 3 for x in range(32))
    # Low-level semantics allow rectangular functions; compare a direct oracle.
    s = CircleDifferentialTransitionSemantics(input_basis, output_basis, table)
    ddt = s.difference_distribution_table(maximum_entries=1024)
    for a, b in product(range(32), range(4)):
        assert ddt[a][b] == sum(
            (table[x] ^ table[input_basis.circle(x, a)]) == b for x in range(32)
        )
    constant = BitVectorSBox(2, (0, 0, 0, 0)).analysis.circle_differential(input_name="input")
    best = constant.best_differential()
    assert (best.input_difference, best.output_difference, best.probability) == (1, 0, 1)


def test_large_graph_sampling_and_preflight_budgets_do_not_claim_optimality(monkeypatch):
    p = Craft(number_of_rounds=2)
    a = p.analysis.circle_differential(bibrace=OPERATION)
    r = a.estimate_probability(0, 0, fixed_inputs={"key": 0, "tweak": 0}, samples=2, seed=5)
    assert r.probability == 1 and not r.complete

    def forbidden(*args, **kwargs):
        raise AssertionError("evaluation happened before budget validation")

    monkeypatch.setattr(p, "evaluate", forbidden)
    monkeypatch.setattr(p, "evaluate_with_trace", forbidden)
    for operation in (
        lambda: a.probability(1, 1, fixed_inputs={"key": 0, "tweak": 0}),
        lambda: a.best_trail(1, fixed_inputs={"key": 0, "tweak": 0}),
        lambda: a.best_differential(fixed_inputs={"key": 0, "tweak": 0}),
        lambda: a.lookup_semantics(fixed_inputs={"key": 0, "tweak": 0}),
        lambda: a.trail_probability((1, 1, 1), fixed_inputs={"key": 0, "tweak": 0}),
    ):
        with pytest.raises(ValueError, match="maximum_"):
            operation()


@pytest.mark.parametrize(
    "samples,seed,confidence",
    [(0, 1, 0.95), (True, 1, 0.95), (2, True, 0.95), (2, 0, 1), (2, 0, float("nan"))],
)
def test_invalid_sampling_parameters(samples, seed, confidence):
    a = BitVectorSBox(1, (0, 1)).analysis.circle_differential(input_name="input")
    with pytest.raises(ValueError):
        a.estimate_probability(1, 1, samples=samples, seed=seed, confidence=confidence)


def test_invalid_inputs_layouts_and_retained_results():
    p, selections = _spn()
    a = p.analysis.circle_differential(bibrace=OPERATION)
    with pytest.raises(ValueError, match="nonzero"):
        a.best_trail(0)
    with pytest.raises(ValueError, match="boundary basis"):
        a.best_trail(1, fixed_inputs={"key": 0}, boundary_bases=())
    with pytest.raises(ValueError, match="packed width"):
        a.best_trail(
            1,
            fixed_inputs={"key": 0},
            boundaries=selections[:1],
            boundary_bases=(CircleBasis((BinaryBibrace(1),)),),
        )
    with pytest.raises(ValueError, match="every retained boundary"):
        a.trail_probability((1, 1), fixed_inputs={"key": 0})
    with pytest.raises(ValueError, match="exactly"):
        a.probability(1, 1, fixed_inputs={"key": 0, "unknown": 0})
    trail = a.best_trail(7, fixed_inputs={"key": 0})
    with pytest.raises(ValueError, match="prefix counts"):
        replace(trail, prefix_counts=(16, 1, 2, 1))
    with pytest.raises(ValueError, match="witness"):
        replace(trail, witness=None)
    with pytest.raises(ValueError, match="domain"):
        replace(trail.evidence, trials=15)
    with pytest.raises(ValueError, match="input difference"):
        a.probability(16, 0, fixed_inputs={"key": 0})


def test_binary_arithmetic_and_odd_prime_rejection_share_linear_context():
    from claasp.primitives.single_component_primitives import ModularAdd, Power, VariableRotate
    from claasp.unit_types import BinaryExtensionField, PrimeField

    for p, name, fixed in [
        (ModularAdd(word_bit_size=4), "input_0", {"input_1": 7}),
        (VariableRotate(bit_size=4, amount_bit_size=2), "input", {"amount": 1}),
        (Power(exponent=7, unit_type=BinaryExtensionField(4, 0x13)), "input", {}),
    ]:
        # ModularAdd's operand names are discovered from the graph.
        if isinstance(p, ModularAdd):
            first, second = p.graph.input_arrays
            name, fixed = first, {second: 7}
        a = p.analysis.circle_differential(input_name=name, bibrace=OPERATION)
        expected = sum(
            _circle(p.evaluate({**fixed, name: x}), p.evaluate({**fixed, name: _circle(x, 4)})) == 3
            for x in range(16)
        )
        assert a.probability(4, 3, fixed_inputs=fixed).probability == Fraction(expected, 16)
    with pytest.raises(NotImplementedError, match="odd-prime"):
        Power(exponent=3, unit_type=PrimeField(17)).analysis.circle_differential(input_name="input")


def test_all_circle_execution_paths_use_the_common_graph_propagation_runner(monkeypatch):
    from claasp.graph.propagation import GraphPropagation

    p = BitVectorSBox(2, (0, 1, 3, 2))
    calls = []
    original = GraphPropagation.run

    def recorded(self, *args, **kwargs):
        calls.append(self.primitive)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(GraphPropagation, "run", recorded)
    p.analysis.circle_differential(input_name="input").probability(1, 1)
    assert calls == [p] * 8
    calls.clear()
    p.analysis.circle_differential(input_name="input").best_trail(1)
    assert calls == [p] * 8
    calls.clear()
    p.analysis.circle_linear(input_name="input").correlation(1, 1)
    assert calls == [p] * 4


def test_circle_ddt_reuses_the_xor_ddt_provider_and_refuses_work_budget(monkeypatch):
    from claasp.semantics.cryptanalysis.trails import SBoxTransitionSemantics

    s = CircleDifferentialTransitionSemantics(BASIS, BASIS, SBOX)
    original = SBoxTransitionSemantics.difference_distribution_table
    calls = []

    def recorded(self):
        calls.append(self.table)
        return original(self)

    monkeypatch.setattr(SBoxTransitionSemantics, "difference_distribution_table", recorded)
    s.difference_distribution_table()
    assert len(calls) == 1
    calls.clear()
    with pytest.raises(ValueError, match="maximum_entries"):
        s.difference_distribution_table(maximum_entries=255)
    assert calls == []
    # A narrow output does not hide quadratic input-pair work.
    narrow = CircleDifferentialTransitionSemantics(
        CircleBasis((BinaryBibrace(8),)), CircleBasis((BinaryBibrace(1),)), (0,) * 256
    )
    with pytest.raises(ValueError, match="maximum_entries"):
        narrow.difference_distribution_table(maximum_entries=512)


def test_output_constraint_and_custom_partial_observations_are_retained():
    p, selections = _spn()
    a = p.analysis.circle_differential(bibrace=OPERATION)
    full = a.best_trail(7, fixed_inputs={"key": 1})
    constrained = a.best_trail(7, full.differences[-1], fixed_inputs={"key": 1})
    assert full.search_output_difference is None
    assert constrained.search_output_difference == full.differences[-1]
    with pytest.raises(ValueError, match="endpoint constraint"):
        replace(constrained, search_output_difference=0)
    # Regroup a 4-bit round value into two XOR cells explicitly.
    mixed = CircleBasis((BinaryBibrace(2), BinaryBibrace(2)))
    custom = a.best_trail(
        7, fixed_inputs={"key": 1}, boundaries=selections[:1], boundary_bases=(mixed,)
    )
    checked = a.trail_probability(
        custom.differences,
        fixed_inputs={"key": 1},
        boundaries=selections[:1],
        boundary_bases=(mixed,),
    )
    assert custom.bases[1] == mixed and custom.prefix_counts == checked.prefix_counts
    endpoint_only = a.best_trail(7, fixed_inputs={"key": 1}, boundaries=())
    assert len(endpoint_only.differences) == 2
    assert endpoint_only.probability >= full.probability


def test_missing_published_round_outputs_uses_only_endpoint_histories():
    p, _ = _spn(publish=False)
    a = p.analysis.circle_differential(bibrace=OPERATION)
    result = a.best_trail(7, fixed_inputs={"key": 1})
    assert result.boundary_labels == ("input", "output")
    assert (
        result.probability
        == a.probability(7, result.differences[-1], fixed_inputs={"key": 1}).probability
    )
