"""Capability and dispatch contracts that do not execute an external solver."""

import pytest

from claasp.analysis.facade import TrailSearchBackend
from claasp.analysis.trail_search import require_word_sat_capability
from claasp.primitives import (
    AES,
    CHAM,
    SPARX,
    Ascon,
    ChaChaPermutation,
    Present,
    SalsaPermutation,
    Simeck,
    Simon,
    Speck,
    Threefish,
    VariableShift,
)
from claasp.representations.constraints.sat import (
    WordXorDifferentialSATModel,
    WordXorLinearSATModel,
)
from claasp.semantics.cryptanalysis import TrailKind


@pytest.mark.parametrize(
    "primitive",
    (
        Simon(number_of_rounds=1),
        Simeck(number_of_rounds=1),
        CHAM(number_of_rounds=1),
        Speck(number_of_rounds=1),
        SPARX(number_of_rounds=1),
        Threefish(number_of_rounds=1),
        ChaChaPermutation(number_of_rounds=1),
        SalsaPermutation(number_of_rounds=1),
    ),
)
@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_confirmed_word_catalogue_graphs_construct_for_both_kinds(primitive, kind):
    require_word_sat_capability(primitive, kind)
    model = (
        WordXorDifferentialSATModel(primitive)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordXorLinearSATModel(primitive, maximum_weight=None)
    )
    assert model.cnf_formula().variable_count


def test_bit_and_binary_field_graphs_construct_exact_differential_models():
    for primitive in (Ascon(number_of_rounds=1), AES(number_of_rounds=1)):
        require_word_sat_capability(primitive, TrailKind.XOR_DIFFERENTIAL)
        assert WordXorDifferentialSATModel(primitive).cnf_formula().variable_count


def test_unsupported_error_names_actual_primitive_kind_backend_and_component():
    with pytest.raises(NotImplementedError) as error:
        VariableShift().analysis.find_optimal_trail(backend="sat")
    message = str(error.value)
    assert "variable_shift" in message
    assert "xor_differential" in message
    assert "backend 'sat'" in message
    assert "VariableShift" in message
    assert "present" not in message.lower()
    assert "speck" not in message.lower()

    with pytest.raises(NotImplementedError, match="backend 'smt'.*VariableShift"):
        VariableShift().analysis.find_optimal_trail(kind="xor_linear", backend="smt")


def test_dependency_free_never_falls_back_to_an_unrelated_validator():
    with pytest.raises(NotImplementedError, match="simon.*xor_differential.*dependency_free"):
        Simon(number_of_rounds=3).analysis.find_optimal_trail(backend="dependency_free")


def test_public_enums_and_default_kind_are_exposed():
    assert {item.value for item in TrailSearchBackend} == {
        "auto",
        "sat",
        "smt",
        "milp",
        "cp",
        "dependency_free",
    }
    assert (
        Present(number_of_rounds=2)
        .analysis.find_optimal_trail(backend="dependency_free")
        .trail.kind
        is TrailKind.XOR_DIFFERENTIAL
    )


@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_fractional_sbox_capability_builds_both_exact_graph_relations(kind):
    from claasp.primitives import Heys

    primitive = Heys(number_of_rounds=1)
    require_word_sat_capability(primitive, kind)
    model = (
        WordXorDifferentialSATModel(primitive)
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordXorLinearSATModel(primitive, maximum_weight=None)
    )
    formula = model.cnf_formula()
    assert "exact_lookup_numerator" in formula.provenance
    assert model._shared._probability_denominator > 1


def test_fractional_optimizer_does_not_turn_unknown_into_an_optimal_result():
    from claasp.drivers.solvers import CPResult, CPStatus
    from claasp.primitives import Heys

    class Solver:
        def solve(self, formula):
            return CPResult(CPStatus.UNKNOWN, None, 0, "test", "", "")

    with pytest.raises(RuntimeError, match="did not complete exact probability"):
        Heys(number_of_rounds=1).analysis.find_optimal_trail(kind="xor_linear", solver=Solver())


def test_fractional_optimizer_rejects_a_solver_witness_outside_its_bound():
    from claasp.drivers.solvers import SatResult, SatStatus
    from claasp.primitives import Heys

    class Solver:
        def solve(self, formula):
            return SatResult(SatStatus.SATISFIABLE, dict.fromkeys(formula.variables, 0), 0, "", "")

    with pytest.raises(RuntimeError, match="invalid probability-bound witness"):
        Heys(number_of_rounds=1).analysis.find_optimal_trail(kind="xor_linear", solver=Solver())


def test_active_input_may_be_fixed_to_a_nonzero_mask_or_difference():
    from claasp.analysis.trail_search import resolve_input_policy
    from claasp.primitives import Heys

    primitive = Heys(number_of_rounds=1)
    for single_key in (False, True):
        policy = resolve_input_policy(
            primitive,
            "plaintext",
            {"plaintext": 1},
            add_key_tweak_defaults=single_key,
        )
        assert policy.fixed_patterns["plaintext"] == 1
        assert policy.nonzero_input == "plaintext"
        with pytest.raises(ValueError, match="cannot be fixed to zero"):
            resolve_input_policy(primitive, "plaintext", {"plaintext": 0})


def test_fractional_support_preserves_the_dense_walsh_table_capability_limit():
    from claasp.primitives import BitVectorSBox

    primitive = BitVectorSBox(11, tuple(range(2048)))
    with pytest.raises(NotImplementedError, match="dense Walsh-table materialization"):
        primitive.analysis.find_optimal_trail(kind="xor_linear")


@pytest.mark.parametrize("kind", tuple(TrailKind))
def test_round_evidence_uses_complete_published_speck_states(kind):
    from types import SimpleNamespace

    from claasp.analysis.trail_search import _evidence

    primitive = Speck(number_of_rounds=2)
    model = (
        WordXorDifferentialSATModel(primitive, fixed_input_differences={"key": 0})
        if kind is TrailKind.XOR_DIFFERENTIAL
        else WordXorLinearSATModel(primitive, maximum_weight=None, fixed_inputs={"key": 0})
    )
    formula = model.cnf_formula()
    shared = model._shared
    assignment = dict.fromkeys(formula.variables, 0)

    def assign(names, value):
        for bit, name in enumerate(reversed(names)):
            assignment[name] = (value >> bit) & 1

    first = primitive.graph.rounds[0].components
    second = primitive.graph.rounds[1].components
    first_ids = [str(component.component_id) for component in first]
    second_ids = [str(component.component_id) for component in second]
    if kind is TrailKind.XOR_DIFFERENTIAL:
        assign(shared._unit_arrays[first_ids[2]], 0x1234)
        assign(shared._unit_arrays[first_ids[4]], 0x5678)
        assign(shared._unit_arrays[second_ids[2]], 0x9ABC)
        assign(shared._unit_arrays[second_ids[4]], 0xDEF0)
    else:
        from claasp.representations.constraints.smt.word_xor_linear import WordXorLinearSMTModel

        assert isinstance(shared, WordXorLinearSMTModel)
        # Deliberately different source masks catch accidental inclusion of
        # consumers inside the round (x also feeds the round's final XOR).
        assign(shared._unit_arrays[first_ids[2]], 0xFFFF)
        assign(shared._edges[second_ids[0]][0], 0x1234)
        assign(shared._edges[second_ids[1]][1], 0x5600)
        assign(shared._edges[second_ids[3]][0], 0x0078)
        assign(shared._output, 0x9ABCDEF0)
    characteristic = SimpleNamespace(semantic_assignment=tuple(assignment.items()), steps=())
    components, rounds = _evidence(primitive, kind, shared, characteristic)

    assert [item.output_pattern.width for item in rounds] == [32, 32]
    assert [item.output_pattern.value for item in rounds] == [0x12345678, 0x9ABCDEF0]
    assert [item.round_number for item in rounds] == [0, 1]
    assert all(item.numerator == item.denominator == 1 for item in rounds)
    if kind is TrailKind.XOR_DIFFERENTIAL:
        evidence = {item.component_id: item.output_pattern.value for item in components}
        assert rounds[0].output_pattern.value == (
            evidence[first_ids[2]] << 16 | evidence[first_ids[4]]
        )


def test_round_evidence_preserves_sparse_publications_and_final_output_order():
    from types import SimpleNamespace

    from claasp.analysis.trail_search import _evidence
    from claasp.components import Identity
    from claasp.graph import Primitive, UnitArrayType, as_selection
    from claasp.unit_types import Word

    primitive = Primitive("sparse_boundaries", {"state": UnitArrayType(Word(4), (2,))})
    x, y = primitive.graph.input("state")[0], primitive.graph.input("state")[1]
    for number in range(3):
        primitive._builder.add_round()
        x = as_selection(primitive._builder.add_component(Identity(x)))
        if number == 1:
            primitive._builder.set_round_output(y, x)
    primitive._builder.set_output((y, x))
    model = WordXorDifferentialSATModel(primitive)
    formula = model.cnf_formula()
    assignment = dict.fromkeys(formula.variables, 0)
    for source_id, value in (
        ("state", 0x0A),
        *(
            (component.component_id, number + 1)
            for number, component in enumerate(primitive.graph.components)
        ),
    ):
        for bit, name in enumerate(reversed(model._shared._unit_arrays[source_id])):
            assignment[name] = (value >> bit) & 1
    characteristic = SimpleNamespace(semantic_assignment=tuple(assignment.items()), steps=())
    _, rounds = _evidence(primitive, TrailKind.XOR_DIFFERENTIAL, model._shared, characteristic)

    assert [(item.output_pattern.value, item.output_pattern.width) for item in rounds] == [
        (0x1, 4),
        (0xA2, 8),
        (0xA3, 8),
    ]
