"""Whole-graph SAT trail assembly and independent witness checks."""

import shutil
from dataclasses import replace

import pytest

from claasp import Primitive, UnitArrayType
from claasp.components import BitwiseAnd, ModularAdd, Xor
from claasp.primitives import Speck, ToySpeck
from claasp.representations.constraints import ConstraintBackend
from claasp.representations.constraints.sat import (
    NWindowSATStrategy,
    SharedDifferencePairedWordXorDifferentialLinearSATModel,
    SharedDifferencePairedWordXorDifferentialSATModel,
    SpeckImpossibleSATModel,
    SpeckProbabilisticTruncatedSATModel,
    SpeckSemiDeterministicTruncatedSATModel,
    WordDeterministicTruncatedSATModel,
    WordDeterministicXorDifferentialLinearSATModel,
    WordImpossibleSATModel,
    WordSemiDeterministicXorDifferentialLinearSATModel,
    WordXorDifferentialSATModel,
    WordXorLinearSATModel,
    find_word_impossible_sat,
)
from claasp.representations.constraints.smt import (
    WordXorDifferentialSMTModel,
    WordXorLinearSMTModel,
)
from claasp.semantics.cryptanalysis import TruncatedXorDifference
from claasp.unit_types import Word


def _primitive(component, width=2):
    primitive = Primitive(
        "boolean_word",
        {"left": UnitArrayType(Word(width), (1,)), "key": UnitArrayType(Word(width), (1,))},
    )
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        component((primitive.graph.input("left"), primitive.graph.input("key")))
    )
    primitive._builder.set_output(output)
    return primitive


def test_differential_sat_assembly_matches_shared_boolean_formula():
    primitive = _primitive(BitwiseAnd)
    sat = WordXorDifferentialSATModel(primitive, fixed_weight=2)
    smt = WordXorDifferentialSMTModel(primitive, fixed_weight=2)
    formula, shared = sat.cnf_formula(), smt.smt_formula()
    assert (formula.variables, formula.clauses, formula.provenance) == (
        shared.variables,
        shared.assertions,
        shared.provenance,
    )
    assert {item.model.backend for item in formula.constraint_models} == {ConstraintBackend.SAT}
    assignment = dict.fromkeys(formula.variables, 1)
    for name in formula.variables:
        if name.startswith("weight_complement"):
            assignment[name] = 0
    trail = sat.decode_characteristic(assignment)
    assert trail.total_weight == 2 and sat.check_characteristic(trail)
    assert not sat.check_characteristic(replace(trail, output_difference=0))


def test_shared_difference_paired_sat_recovers_modadd_exclusion_and_weight_bound():
    model = SharedDifferencePairedWordXorDifferentialSATModel(
        ToySpeck(2),
        maximum_total_weight=2,
        fixed_input_differences={"key": 0},
        nonzero_input="plaintext",
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        230,
        788,
        2645,
    )
    assert formula.provenance.count("paired_modadd_output_exclusion") == 12
    assert formula.provenance.count("paired_shared_input_difference") == 48


def test_shared_difference_paired_sat_validates_total_weight_configuration():
    with pytest.raises(ValueError, match="choose"):
        SharedDifferencePairedWordXorDifferentialSATModel(
            ToySpeck(2), maximum_total_weight=1, fixed_total_weight=1
        )
    with pytest.raises(ValueError, match="nonnegative"):
        SharedDifferencePairedWordXorDifferentialSATModel(ToySpeck(2), maximum_total_weight=True)


def test_shared_difference_paired_differential_linear_sat_assembles_both_boundaries():
    model = SharedDifferencePairedWordXorDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=2,
        paired_differential_maximum_weight=32,
        linear_maximum_weight=16,
        fixed_total_weight=8,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        13608,
        29492,
        77847,
    )
    assert formula.provenance.count("paired_differential_linear_boundary") == 64


def test_shared_difference_paired_differential_linear_sat_validates_configuration():
    with pytest.raises(ValueError, match="both be nonempty"):
        SharedDifferencePairedWordXorDifferentialLinearSATModel(
            Speck(number_of_rounds=3),
            prefix_rounds=3,
            paired_differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="choose"):
        SharedDifferencePairedWordXorDifferentialLinearSATModel(
            Speck(number_of_rounds=3),
            prefix_rounds=2,
            paired_differential_maximum_weight=1,
            linear_maximum_weight=1,
            maximum_total_weight=1,
            fixed_total_weight=1,
        )


def test_linear_sat_assembly_matches_shared_boolean_formula():
    primitive = _primitive(Xor)
    sat = WordXorLinearSATModel(primitive, maximum_weight=0, nonzero_input="key")
    smt = WordXorLinearSMTModel(primitive, maximum_weight=0, nonzero_input="key")
    formula, shared = sat.cnf_formula(), smt.smt_formula()
    assert (formula.variables, formula.clauses, formula.provenance) == (
        shared.variables,
        shared.assertions,
        shared.provenance,
    )
    assert {item.model.backend for item in formula.constraint_models} == {ConstraintBackend.SAT}
    trail = sat.decode_characteristic(dict.fromkeys(formula.variables, 1))
    assert dict(trail.input_masks) == {"left": 3, "key": 3}
    assert trail.output_mask == 3 and sat.check_characteristic(trail)


@pytest.mark.parametrize("model_type", [WordXorDifferentialSATModel, WordXorLinearSATModel])
def test_sat_enumeration_rejects_nonpositive_or_boolean_limits(model_type):
    primitive = _primitive(Xor)
    options = (
        {"maximum_weight": 0}
        if model_type is WordXorDifferentialSATModel
        else {"maximum_weight": 0}
    )
    model = model_type(primitive, **options)
    with pytest.raises(ValueError, match="positive integer"):
        model.enumerate_trails(object(), limit=True)


def test_n_window_strategy_is_opt_in_and_supports_legacy_selectors():
    primitive = ToySpeck(2)
    exact = WordXorDifferentialSATModel(primitive, fixed_weight=1).cnf_formula()
    uniform = WordXorDifferentialSATModel(
        primitive, fixed_weight=1, n_window=NWindowSATStrategy(2)
    ).cnf_formula()
    by_round = WordXorDifferentialSATModel(
        primitive,
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_round=(2, 2)),
    ).cnf_formula()
    component_windows = {
        component.component_id: 2
        for component in primitive.graph.components
        if isinstance(component, ModularAdd)
    }
    by_component = WordXorDifferentialSATModel(
        primitive,
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_component=component_windows),
    ).cnf_formula()
    assert "n_window_run_bound" not in exact.provenance
    assert uniform.clauses == by_round.clauses == by_component.clauses
    assert any(
        item.model.encoding_name == "direct carry-difference run bound"
        for item in uniform.constraint_models
    )


def test_n_window_strategy_rejects_incomplete_component_configuration():
    model = WordXorDifferentialSATModel(
        ToySpeck(2),
        fixed_weight=1,
        n_window=NWindowSATStrategy(by_component={"unknown": 2}),
    )
    with pytest.raises(ValueError, match="every modular-add component"):
        model.cnf_formula()


def test_deterministic_truncated_sat_assembles_and_independently_checks_toy_speck():
    model = WordDeterministicTruncatedSATModel(
        ToySpeck(2),
        fixed_input_patterns={"plaintext": "00000001", "key": "0" * 16},
    )
    formula = model.cnf_formula()
    assert formula.variable_count == 200
    assert formula.clause_count == 813
    assert any(item.model == model.model_provenance for item in formula.constraint_models)
    assert any(
        item.model.encoding_name == "legacy two-bit paired-carry clauses"
        for item in formula.constraint_models
    )


def test_deterministic_truncated_sat_restriction_validation():
    primitive = ToySpeck(2)
    with pytest.raises(ValueError, match="unknown fixed input"):
        WordDeterministicTruncatedSATModel(primitive, fixed_input_patterns={"missing": "0"})
    with pytest.raises(ValueError, match="contain 8 bits"):
        WordDeterministicTruncatedSATModel(primitive, fixed_input_patterns={"plaintext": "0"})
    model = WordDeterministicTruncatedSATModel(
        primitive,
        fixed_input_patterns={
            "plaintext": TruncatedXorDifference.parse("00000001"),
            "key": "0" * 16,
        },
        output_pattern="???0????",
    )
    assert "truncated_fixed_output" in model.cnf_formula().provenance


def test_speck_impossible_sat_composes_transformed_directional_graphs():
    model = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1)
    formula = model.cnf_formula()
    assert formula.variable_count == 1568
    assert formula.clause_count == 5674
    assert "truncated_incompatibility_exists" in formula.provenance
    assert any(item.model == model.model_provenance for item in formula.constraint_models)
    assert any(
        item.model.component_model == "ModularSubtractDeterministicTruncatedSATModel"
        for item in formula.constraint_models
    )


def test_generic_word_impossible_sat_matches_reviewed_speck_composition():
    generic = WordImpossibleSATModel(
        Speck(number_of_rounds=3),
        middle_round=1,
        active_input="plaintext",
        zero_difference_inputs=("key",),
    ).cnf_formula()
    specialized = SpeckImpossibleSATModel(Speck(number_of_rounds=3), middle_round=1).cnf_formula()
    assert generic.variables == specialized.variables
    assert generic.clauses == specialized.clauses


def test_speck_impossible_sat_validates_supported_slice_and_patterns():
    primitive = Speck(number_of_rounds=3)
    with pytest.raises(ValueError, match="inside the primitive"):
        SpeckImpossibleSATModel(primitive, middle_round=0)
    with pytest.raises(TypeError, match="integer"):
        SpeckImpossibleSATModel(primitive, middle_round=True)
    with pytest.raises(ValueError, match="contain 32 bits"):
        SpeckImpossibleSATModel(primitive, middle_round=1, input_pattern="0")


def test_automatic_impossible_search_validates_explicit_split_order():
    with pytest.raises(ValueError, match="unique internal"):
        find_word_impossible_sat(
            Speck(number_of_rounds=3),
            object(),
            active_input="plaintext",
            zero_difference_inputs=("key",),
            split_order=(1, 1),
        )


def test_speck_probabilistic_sat_assembles_local_round_relations():
    model = SpeckProbabilisticTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
    )
    formula = model.cnf_formula()
    assert formula.variable_count == 1182
    assert formula.clause_count == 215309
    assert len(model._round_models) == 2
    assert all(item.model.backend is ConstraintBackend.SAT for item in formula.constraint_models)


def test_speck_probabilistic_sat_validates_boundaries_and_weight_bound():
    primitive = Speck(number_of_rounds=2)
    with pytest.raises(ValueError, match="32 bits"):
        SpeckProbabilisticTruncatedSATModel(primitive, "0", "0" * 32)
    with pytest.raises(ValueError, match="nonnegative integer"):
        SpeckProbabilisticTruncatedSATModel(
            primitive, "0" * 32, "0" * 32, maximum_scaled_weight=True
        )


def test_speck_semi_deterministic_sat_reuses_graph_assembly_compactly():
    portable = SpeckProbabilisticTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
        maximum_scaled_weight=100,
    ).cnf_formula()
    model = SpeckSemiDeterministicTruncatedSATModel(
        Speck(number_of_rounds=2),
        "00000000011111001110000000000000",
        "???????????????1???????????????1",
        maximum_scaled_weight=100,
    )
    formula = model.cnf_formula()
    assert formula.variable_count > 0
    assert formula.clause_count < portable.clause_count
    assert len(model._round_models) == 2
    assert any(item.model == model.model_provenance for item in formula.constraint_models)
    assert any(
        item.model.component_model == "ModularAddSemiDeterministicTruncatedSATModel"
        and item.model.reference_status.value == "TBD"
        for item in formula.constraint_models
    )


def test_deterministic_differential_linear_sat_assembles_three_round_slices():
    model = WordDeterministicXorDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        linear_maximum_weight=16,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        2543,
        7151,
        23144,
    )
    assert "differential_to_truncated_exact" in formula.provenance
    assert "truncated_to_linear_compatibility" in formula.provenance
    assert "nonzero_differential_linear_output_mask" in formula.provenance


def test_deterministic_differential_linear_sat_validates_partition_and_bounds():
    primitive = Speck(number_of_rounds=3)
    with pytest.raises(ValueError, match="positive"):
        WordDeterministicXorDifferentialLinearSATModel(
            primitive,
            prefix_rounds=0,
            middle_rounds=1,
            differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="all be nonempty"):
        WordDeterministicXorDifferentialLinearSATModel(
            primitive,
            prefix_rounds=1,
            middle_rounds=2,
            differential_maximum_weight=1,
            linear_maximum_weight=1,
        )
    with pytest.raises(ValueError, match="nonnegative"):
        WordDeterministicXorDifferentialLinearSATModel(
            primitive,
            prefix_rounds=1,
            middle_rounds=1,
            differential_maximum_weight=-1,
            linear_maximum_weight=1,
        )


def test_semi_deterministic_differential_linear_sat_assembles_recovered_middle():
    model = WordSemiDeterministicXorDifferentialLinearSATModel(
        Speck(number_of_rounds=3),
        prefix_rounds=1,
        middle_rounds=1,
        differential_maximum_weight=16,
        middle_maximum_scaled_weight=None,
        linear_maximum_weight=16,
    )
    formula = model.cnf_formula()
    assert (formula.variable_count, formula.clause_count, formula.literal_count) == (
        2303,
        6599,
        22737,
    )
    assert "semi_deterministic_weight_code" in formula.provenance
    assert formula.provenance.count("differential_to_truncated_exact") == 96
    assert formula.provenance.count("truncated_to_linear_compatibility") == 32
    assert any(
        item.model.component_model == "ModularAddSemiDeterministicTruncatedSATModel"
        and item.model.reference_status.value == "TBD"
        for item in formula.constraint_models
    )


def test_semi_deterministic_differential_linear_sat_validates_configuration():
    with pytest.raises(NotImplementedError, match="supports Speck"):
        WordSemiDeterministicXorDifferentialLinearSATModel(
            ToySpeck(3),
            prefix_rounds=1,
            middle_rounds=1,
            differential_maximum_weight=1,
            middle_maximum_scaled_weight=None,
            linear_maximum_weight=1,
        )


def _sparse_binary_field_primitive(matrix=((1, 0), (1, 1))):
    from claasp.components import LinearMap
    from claasp.unit_types import BinaryExtensionField

    p = Primitive("sparse_field", {"input": UnitArrayType(BinaryExtensionField(2, 0b111), (2,))})
    p._builder.add_round()
    output = p._builder.add_component(LinearMap(p.graph.input("input"), matrix))
    p._builder.set_round_output(output)
    p._builder.set_output(output)
    return p


def test_sparse_wordwise_matrix_ignores_zero_coefficient_dependencies():
    import shutil

    if not shutil.which("kissat"):
        pytest.skip("requires Kissat")
    from claasp.drivers.solvers import KissatSolver
    from claasp.representations.constraints.sat import WordwiseDeterministicTruncatedSATModel
    from claasp.semantics.cryptanalysis import (
        WordwiseDifferenceKind as Kind,
    )
    from claasp.semantics.cryptanalysis import (
        WordwiseXorDifference as Difference,
    )

    p = _sparse_binary_field_primitive()
    model = WordwiseDeterministicTruncatedSATModel(
        p,
        fixed_input_differences={"input": (Difference(2, Kind.ZERO), Difference(2, Kind.UNKNOWN))},
    )
    result = KissatSolver().solve(model.cnf_formula())
    trail = model.decode_characteristic(result.assignment)
    assert tuple(d.kind for d in trail.output_differences) == (Kind.ZERO, Kind.UNKNOWN)
    # Every concrete difference is contained in its decoded abstract output.
    for y in range(4):
        assert p.evaluate(input=y) == y


@pytest.mark.parametrize("pattern", ["0000", "0100", "01?0", "????"])
@pytest.mark.parametrize("matrix", [((1, 0), (1, 1)), ((2, 0), (3, 1))])
def test_bitwise_binary_field_linear_maps_cover_concrete_differences(pattern, matrix):
    import shutil

    if not shutil.which("kissat"):
        pytest.skip("requires Kissat")
    from claasp.drivers.solvers import KissatSolver

    p = _sparse_binary_field_primitive(matrix)
    model = WordDeterministicTruncatedSATModel(p, fixed_input_patterns={"input": pattern})
    solved = KissatSolver().solve(model.cnf_formula())
    trail = model.decode_characteristic(solved.assignment)
    expected = str(trail.output_pattern)
    for value in range(16):
        bits = f"{value:04b}"
        if all(a == "?" or a == b for a, b in zip(pattern, bits)):
            output = p.evaluate(input=value)
            assert isinstance(output, int)
            assert all(a == "?" or a == b for a, b in zip(expected, f"{output:04b}"))


@pytest.mark.parametrize(
    "component_name", ("ModularAdd", "ModularSubtract", "BitwiseAnd", "BitwiseOr")
)
@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
@pytest.mark.parametrize("width", (1, 2))
def test_wordwise_elementary_sat_matches_independent_transfers(component_name, width):
    from itertools import product

    from claasp import components
    from claasp.drivers.solvers import KissatSolver
    from claasp.representations.constraints.sat import WordwiseDeterministicTruncatedSATModel
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
    from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference
    from claasp.semantics.cryptanalysis._wordwise_operations import _boolean, _modular

    primitive = _primitive(getattr(components, component_name), width)
    abstract = tuple(
        dict.fromkeys(
            (
                Difference(width, Kind.ZERO),
                Difference.known(width, 1),
                Difference.known(width, (1 << width) - 1),
                Difference(width, Kind.NONZERO),
                Difference(width, Kind.UNKNOWN),
            )
        )
    )
    transfer = _modular if component_name.startswith("Modular") else _boolean
    for left, right in product(abstract, repeat=2):
        model = WordwiseDeterministicTruncatedSATModel(
            primitive, fixed_input_differences={"left": (left,), "key": (right,)}
        )
        solved = KissatSolver().solve(model.cnf_formula())
        trail = model.decode_characteristic(solved.assignment)
        assert trail.output_differences == (transfer((left, right)),)
        assert model.check_characteristic(trail)
        wrong = Difference(
            width,
            Kind.UNKNOWN if trail.output_differences[0].kind is not Kind.UNKNOWN else Kind.ZERO,
        )
        assert not model.check_characteristic(replace(trail, output_differences=(wrong,)))


@pytest.mark.parametrize("kind", ("ZERO", "KNOWN", "NONZERO", "UNKNOWN"))
@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_wordwise_unpack_pack_bindings_are_checked_independently(kind):
    from claasp.components import BitwiseNot
    from claasp.drivers.solvers import KissatSolver
    from claasp.representations.constraints.sat import WordwiseDeterministicTruncatedSATModel
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
    from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference
    from claasp.semantics.cryptanalysis._wordwise_operations import _pack, _unpack

    p = Primitive("conversion", {"input": UnitArrayType(Word(3), (1,))})
    p._builder.add_round()
    bits = p._builder.unpack_bits(p.graph.input("input"))
    packed = p._builder.pack_bits(bits, 3)
    output = p._builder.add_component(BitwiseNot(packed))
    p._builder.set_output(output)
    difference = Difference.known(3, 5) if kind == "KNOWN" else Difference(3, Kind[kind])
    model = WordwiseDeterministicTruncatedSATModel(
        p, fixed_input_differences={"input": (difference,)}
    )
    solved = KissatSolver().solve(model.cnf_formula())
    trail = model.decode_characteristic(solved.assignment)
    assert trail.output_differences == (_pack(_unpack(difference, 3), 3),)
    assert model.check_characteristic(trail)


@pytest.mark.parametrize("direction", ("left", "right"))
@pytest.mark.parametrize("amount", (0, 1, 3, 4))
@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_bitwise_shift_sat_zero_padding_matches_every_concrete_difference(direction, amount):
    from claasp.drivers.solvers import KissatSolver
    from claasp.primitives.single_component_primitives import Shift

    p = Shift(3, amount, direction)
    for pattern in ("000", "101", "?01", "???"):
        model = WordDeterministicTruncatedSATModel(p, fixed_input_patterns={"input": pattern})
        run = KissatSolver().solve(model.cnf_formula())
        trail = model.decode_characteristic(run.assignment)
        expected = str(trail.output_pattern)
        for delta in range(8):
            if not all(a == "?" or a == b for a, b in zip(pattern, f"{delta:03b}")):
                continue
            for value in range(8):
                actual = p.evaluate(value) ^ p.evaluate(value ^ delta)
                assert all(a == "?" or a == b for a, b in zip(expected, f"{actual:03b}"))


@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_wordwise_checker_rejects_corrupted_conversion_payload():
    from claasp.components import Identity
    from claasp.drivers.solvers import KissatSolver
    from claasp.representations.constraints.sat import WordwiseDeterministicTruncatedSATModel
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
    from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference

    p = Primitive("conversion", {"input": UnitArrayType(Word(3), (1,))})
    p._builder.add_round()
    bits = p._builder.unpack_bits(p.graph.input("input"))
    output = p._builder.add_component(Identity(bits))
    p._builder.set_output(output)
    model = WordwiseDeterministicTruncatedSATModel(
        p, fixed_input_differences={"input": (Difference(3, Kind.UNKNOWN),)}
    )
    run = KissatSolver().solve(model.cnf_formula())
    trail = model.decode_characteristic(run.assignment)
    bad = dict(trail.semantic_assignment)
    name = next(
        name for name in bad if name.startswith("__wordwise_binding_") and "_value_" in name
    )
    bad[name] = 1
    assert not model.check_characteristic(replace(trail, semantic_assignment=tuple(bad.items())))


@pytest.mark.skipif(shutil.which("kissat") is None, reason="requires Kissat")
def test_wordwise_pack_sat_covers_all_mixed_abstract_bit_patterns():
    from itertools import product

    from claasp.components import Identity
    from claasp.drivers.solvers import KissatSolver
    from claasp.representations.constraints.sat import WordwiseDeterministicTruncatedSATModel
    from claasp.semantics.cryptanalysis import WordwiseDifferenceKind as Kind
    from claasp.semantics.cryptanalysis import WordwiseXorDifference as Difference
    from claasp.semantics.cryptanalysis._wordwise_operations import _pack
    from claasp.unit_types import Bit

    p = Primitive("pack_bits", {"input": UnitArrayType(Bit(), (3,))})
    p._builder.add_round()
    packed = p._builder.pack_bits(p.graph.input("input"), 3)
    p._builder.set_output(p._builder.add_component(Identity(packed)))
    bits = (
        Difference(1, Kind.ZERO),
        Difference.known(1, 1),
        Difference(1, Kind.NONZERO),
        Difference(1, Kind.UNKNOWN),
    )
    for pattern in product(bits, repeat=3):
        model = WordwiseDeterministicTruncatedSATModel(
            p, fixed_input_differences={"input": pattern}
        )
        solved = KissatSolver().solve(model.cnf_formula())
        trail = model.decode_characteristic(solved.assignment)
        assert trail.output_differences == (_pack(pattern, 3),)
