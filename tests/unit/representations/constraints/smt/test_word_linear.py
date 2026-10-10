"""Independent word-mask validation and enumeration completeness contracts."""

from dataclasses import replace

import pytest

from claasp import ArrayType, Primitive
from claasp.components import BitwiseAnd, Xor
from claasp.domains import Word
from claasp.drivers.solvers import SatResult, SatStatus
from claasp.representations.constraints.smt import WordLinearSMTModel


def _xor_model():
    primitive = Primitive(
        "xor", {"left": ArrayType(Word(2), (1,)), "key": ArrayType(Word(2), (1,))}
    )
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        Xor((primitive.graph.input("left"), primitive.graph.input("key")))
    )
    primitive._builder.set_output(output)
    return WordLinearSMTModel(primitive, maximum_weight=0, nonzero_input="key")


def test_word_mask_witness_and_arithmetic_checker_agree_and_reject_tampering():
    model = _xor_model()
    formula = model.smt_formula()
    assignment = dict.fromkeys(formula.variables, 1)
    trail = model.decode_characteristic(assignment)
    assert dict(trail.input_masks) == {"left": 3, "key": 3}
    assert trail.output_mask == 3
    assert model.check_characteristic(trail)
    assert not model.check_characteristic(replace(trail, output_mask=0))
    changed = list(trail.semantic_assignment)
    changed[0] = (changed[0][0], 0)
    assert not model.check_characteristic(replace(trail, semantic_assignment=tuple(changed)))
    with pytest.raises(ValueError, match="invalid"):
        model.decode_characteristic(dict.fromkeys(formula.variables, 0))


def test_path_limit_cannot_be_reported_as_complete():
    model = _xor_model()
    formula = model.smt_formula()
    assignment = dict.fromkeys(formula.variables, 1)

    class Solver:
        def solve(self, formula):
            return SatResult(SatStatus.SATISFIABLE, assignment, 0, "", "")

    result = model.enumerate_trails(Solver(), limit=1)
    assert not result.complete and len(result.trails) == 1
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()
    with pytest.raises(ValueError):
        model.enumerate_trails(Solver(), limit=True)


def test_word_linear_input_constraints_validate_names_and_widths():
    model = _xor_model()
    with pytest.raises(ValueError):
        WordLinearSMTModel(model.primitive, maximum_weight=0, nonzero_input="missing")
    with pytest.raises(ValueError):
        WordLinearSMTModel(model.primitive, maximum_weight=0, fixed_input_masks={"key": 4})


def test_facade_defaults_to_single_key_masks_and_preserves_provenance():
    model = _xor_model()

    class Solver:
        def solve(self, formula):
            assert "fixed_external_mask" not in formula.provenance
            return SatResult(SatStatus.UNSATISFIABLE, None, 0, "", "")

    result = model.primitive.analysis.enumerate_xor_linear_trails(
        0, nonzero_input="left", solver=Solver()
    )
    assert result.complete
    assert dict(result.reproducibility)["version"] == "unreported"
    assert dict(result.reproducibility)["fixed_inputs"] == "(('key', 0),)"


def test_concrete_fixed_keys_are_constants_not_zero_masks():
    primitive = _xor_model().primitive
    model = WordLinearSMTModel(
        primitive, maximum_weight=0, nonzero_input="left", fixed_inputs={"key": 3}
    )
    formula = model.smt_formula()
    trail = model.decode_characteristic(dict.fromkeys(formula.variables, 1))
    assert dict(trail.input_masks) == {"left": 3, "key": 0}
    assert trail.sign == 1  # parity of 3 & 3 is even
    assert model.check_characteristic(trail)


def test_bitwise_and_word_composition_recounts_signs_and_weights():
    primitive = Primitive(
        "and", {"left": ArrayType(Word(2), (1,)), "right": ArrayType(Word(2), (1,))}
    )
    primitive._builder.add_round()
    output = primitive._builder.add_component(
        BitwiseAnd((primitive.graph.input("left"), primitive.graph.input("right")))
    )
    primitive._builder.set_output(output)
    model = WordLinearSMTModel(primitive, maximum_weight=2, nonzero_input="left")
    formula = model.smt_formula()
    trail = model.decode_characteristic(dict.fromkeys(formula.variables, 1))
    assert trail.total_weight == 2 and trail.sign == 1
    assert model.check_characteristic(trail)
