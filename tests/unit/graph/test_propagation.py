"""Shared traversal tested through independent executable and relational meanings."""

from itertools import product

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import Identity, Permutation, Xor
from claasp.graph import GraphPropagation
from claasp.representations.execution import (
    BooleanSymbolicEvaluator,
    ContinuousExecutionDriver,
    ScalarExecutionDriver,
    TransposedBatchExecutionDriver,
)
from claasp.unit_types import Bit


def _wired(permutation=(1, 0)):
    primitive = Primitive("shared_wiring", {"input": UnitArrayType(Bit(), (4,))})
    b = primitive._builder
    b.add_round()
    state = primitive.graph.input("input")
    words = b.pack_bits(state, 2)
    moved = b.add_component(Permutation(words, permutation))
    bits = b.unpack_bits(moved)
    # Shared sources, a repeated selection and a non-terminal output exercise
    # fanout, ordering and output selection independently of operation rules.
    out = b.add_component(Xor((bits, state)))
    b.add_component(Identity(bits))
    b.set_round_output(out)
    b.set_output(out)
    return primitive


@pytest.mark.parametrize("permutation", [(0, 1), (1, 0)])
def test_every_executable_meaning_observes_the_same_binding_and_wiring_edit(permutation):
    primitive = _wired(permutation)
    scalar = ScalarExecutionDriver()
    continuous = ContinuousExecutionDriver()
    symbolic = BooleanSymbolicEvaluator().evaluate(primitive)
    samples = tuple(product((0, 1), repeat=4))
    batch = TransposedBatchExecutionDriver().evaluate(primitive, {"input": samples})
    for sample, observed in zip(samples, batch.outputs):
        selected = tuple(sample[2 * i + b] for i in permutation for b in range(2))
        expected = tuple(a ^ b for a, b in zip(selected, sample))
        assert scalar.evaluate(primitive, {"input": sample}).output == expected == observed
        correlations = tuple(1.0 if bit else -1.0 for bit in sample)
        assert continuous.evaluate(primitive, {"input": correlations}).output == tuple(
            1.0 if bit else -1.0 for bit in expected
        )
        assignment = {f"input_{i}": bit for i, bit in enumerate(sample)}
        assert (
            tuple(polynomial.evaluate(assignment) for polynomial in symbolic.output_anfs)
            == expected
        )


def test_forward_and_consumer_edge_wiring_share_source_bits_without_assuming_fanout_law():
    primitive = _wired()
    plan = GraphPropagation(primitive)
    source_names = lambda name, vt: tuple(f"{name}:{i}" for i in range(vt.encoded_bit_size))
    sources, direct, output, _ = plan.bit_wiring(str, source_names=source_names)
    separate_sources, edges, separate_output, consumers = plan.bit_wiring(
        str,
        source_names=source_names,
        edge_names=lambda c, i, s: tuple(
            f"{c.component_id}:{i}:{b}" for b in range(s.array_type.encoded_bit_size)
        ),
        output_names=lambda vt: tuple(f"output:{b}" for b in range(vt.encoded_bit_size)),
    )
    assert sources == separate_sources
    xor = next(c for c in plan.components if isinstance(c, Xor))
    assert direct[xor.component_id][1] == sources["input"]
    # Distinct consumer variables refer back to the same canonical source bits.
    for c in plan.components:
        for selected, allocated, selection in zip(
            direct[c.component_id], edges[c.component_id], c.inputs
        ):
            for original, edge, (name, bit) in zip(
                selected, allocated, plan.bit_sources(selection)
            ):
                assert original == sources[name][bit]
                assert edge in consumers[name][bit]
    assert output == sources[xor.component_id]
    assert separate_output == tuple(f"output:{i}" for i in range(4))
    assert all(separate_output[i] in consumers[xor.component_id][i] for i in range(4))


def test_numeric_sample_parallel_execution_uses_the_same_conversion_wiring():
    np = pytest.importorskip("numpy")
    from claasp.representations.execution._numpy import _evaluate_samples

    for permutation in ((0, 1), (1, 0)):
        primitive = _wired(permutation)
        values, _ = _evaluate_samples(
            primitive, {"input": tuple(range(16))}, [(primitive.graph.output,)]
        )
        expected = [
            x ^ (((x & 3) << 2) | (x >> 2)) if permutation == (1, 0) else 0 for x in range(16)
        ]
        assert np.array_equal(
            values[0], [[(x >> b) & 1 for x in expected] for b in reversed(range(4))]
        )


def test_input_validation_and_local_output_validation_are_shared():
    plan = GraphPropagation(_wired())
    with pytest.raises(ValueError, match="missing=.*input"):
        plan.run({}, lambda c, operands: ())
    with pytest.raises(ValueError, match="unexpected=.*other"):
        plan.run({"input": (0,) * 4, "other": ()}, lambda c, operands: ())
    checked = []

    def validate(name, value, array_type):
        checked.append(name)
        if len(value) != array_type.unit_count:
            raise ValueError("bad local width")

    with pytest.raises(ValueError, match="bad local width"):
        plan.run({"input": (0,) * 4}, lambda c, operands: (), validate=validate)
    assert checked[0] == "input" and len(checked) == 2


def test_wordwise_semantics_explicitly_reject_unsupported_conversions():
    plan = GraphPropagation(_wired())
    sources = {name: tuple(object() for _ in range(vt.unit_count)) for name, vt in plan.sources}

    def reject(*args):
        raise NotImplementedError("wordwise encoding conversion")

    with pytest.raises(NotImplementedError, match="wordwise encoding conversion"):
        plan.unit_wiring(sources, pack=reject, unpack=reject)


def test_forward_rule_is_independent_of_numeric_unit_type():
    # A custom abstract unit reaches the same arbitrary-size prime-field graph.
    from claasp.primitives import MiMC

    primitive = MiMC(17, 3, (1,))
    plan = GraphPropagation(primitive)
    visited = []

    def dependencies(component, operands):
        visited.append(component.component_id)
        labels = frozenset().union(*(unit for operand in operands for unit in operand))
        return (labels,) * component.output_type.unit_count

    result = plan.run({"state": (frozenset({"state"}),)}, dependencies)
    assert result.output == (frozenset({"state"}),)
    assert visited == [component.component_id for component in primitive.graph.components]


def test_word_models_have_one_canonical_implementation():
    from claasp.representations.constraints.smt import (
        trails,
        word_xor_differential,
        word_xor_linear,
    )

    assert trails.WordXorDifferentialSMTModel is word_xor_differential.WordXorDifferentialSMTModel
    assert trails.WordXorLinearSMTModel is word_xor_linear.WordXorLinearSMTModel
    assert (
        trails.WordXorDifferentialCharacteristic
        is word_xor_differential.WordXorDifferentialCharacteristic
    )
    assert trails.WordXorLinearCharacteristic is word_xor_linear.WordXorLinearCharacteristic


def test_batch_execution_reuses_registered_scalar_rules():
    from claasp.components.word import BitwiseNot as NotComponent
    from claasp.primitives.single_component_primitives import BitwiseNot

    primitive = BitwiseNot(2)
    scalar = ScalarExecutionDriver()
    scalar.register(NotComponent, lambda component, operands: operands[0])
    batch = TransposedBatchExecutionDriver(scalar)
    assert scalar.evaluate(primitive, {"input": (1,)}).output == (1,)
    assert batch.evaluate(primitive, {"input": ((1,), (2,))}).outputs == ((1,), (2,))
