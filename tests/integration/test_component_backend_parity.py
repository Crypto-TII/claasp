"""Exhaustive small-input functional miters through actual solver backends.

The scalar side supplies a complete truth table. Every input has a checked
CNF witness, and the selected external backend must prove that a different
output is impossible. These are scoped component checks, not trail claims.
"""

import os
from dataclasses import replace
from itertools import product

import pytest

from claasp.drivers.solvers import GLPKSolver, MinisatSolver, MiniZincSolver, SatStatus, Z3Solver
from claasp.primitives.single_component_primitives import (
    Add,
    BinaryAffineMap,
    BitVectorSBox,
    BitwiseAnd,
    BitwiseNot,
    BitwiseOr,
    Constant,
    Identity,
    LinearMap,
    ModularAdd,
    ModularMultiply,
    ModularSubtract,
    Multiply,
    Permutation,
    Power,
    Rotate,
    SBox,
    Shift,
    VariableRotate,
    VariableShift,
    Xor,
)
from claasp.representations.constraints.cp import BooleanMiniZincLowerer
from claasp.representations.constraints.milp import cnf_to_milp
from claasp.representations.constraints.sat import BooleanCNFModel
from claasp.representations.constraints.sat.encoding import resolved_selection_variable_names
from claasp.unit_types import BinaryExtensionField

pytestmark = pytest.mark.external
_BACKEND = os.environ.get("CLAASP_PARITY_BACKEND", "z3")
_FIELD = BinaryExtensionField(2, 0b111)
_CASES = (
    BitwiseAnd(2, 3),
    BitwiseOr(2, 3),
    BitwiseNot(2),
    ModularAdd(2, 3),
    ModularSubtract(2, 3),
    ModularMultiply(2, 3),
    Xor(2, 3),
    VariableRotate(2, 2),
    VariableShift(2, 2),
    Rotate(2),
    Shift(2),
    Permutation((1, 0)),
    BitVectorSBox(2, (0, 1, 1, 0), 1),
    LinearMap(((1, 1), (1, 0))),
    Identity(2),
    Constant(2, 2),
    Add(_FIELD, number_of_inputs=3),
    Multiply(_FIELD, number_of_inputs=3),
    Power(3, _FIELD),
    LinearMap(((1, 2), (2, 1)), unit_type=_FIELD),
    BinaryAffineMap(((0, 1), (1, 1)), 1, word_size=2),
    SBox((0, 1, 1, 0), unit_type=_FIELD),
)


def _miter(primitive):
    model = BooleanCNFModel(primitive)
    formula = model.cnf_formula()
    indices = {name: index + 1 for index, name in enumerate(formula.variables)}
    names = tuple(primitive.graph.input_arrays)
    widths = tuple(primitive.graph.input_arrays[name].array_type.encoded_bit_size for name in names)
    input_bits = tuple(
        ref
        for name in names
        for group in resolved_selection_variable_names(
            primitive, primitive.graph.input(name).select_all()
        )
        for ref in group
    )
    output_bits = tuple(
        ref
        for group in resolved_selection_variable_names(primitive, primitive.graph.output)
        for ref in group
    )
    clauses = []
    for values in product(*(range(1 << width) for width in widths)):
        evaluation = primitive.evaluate_with_trace(dict(zip(names, values)))
        assert formula.is_satisfied(model.witness(evaluation))
        expected = primitive.evaluate(dict(zip(names, values)))
        bits = tuple(
            (value >> bit) & 1
            for value, width in zip(values, widths)
            for bit in reversed(range(width))
        )
        mismatch = tuple(
            -indices[ref] if bit else indices[ref] for ref, bit in zip(input_bits, bits)
        )
        wrong_output = tuple(
            -indices[ref] if expected & (1 << (len(output_bits) - 1 - bit)) else indices[ref]
            for bit, ref in enumerate(output_bits)
        )
        clauses.append((*mismatch, *wrong_output))
    return replace(
        formula,
        clauses=(*formula.clauses, *clauses),
        provenance=(*formula.provenance, *(("complete_scalar_truth_table",) * len(clauses))),
    )


@pytest.mark.parametrize("primitive", _CASES, ids=lambda p: p.family_name)
def test_backend_has_no_counterexample_to_complete_small_component_truth_table(primitive):
    formula = _miter(primitive)
    if _BACKEND == "z3":
        solved = Z3Solver(timeout_seconds=30).solve(formula)
        assert solved.status is SatStatus.UNSATISFIABLE
    elif _BACKEND == "minisat":
        solved = MinisatSolver(timeout_seconds=30).solve(formula)
        assert solved.status is SatStatus.UNSATISFIABLE
    elif _BACKEND == "glpk":
        solved = GLPKSolver(timeout_seconds=30).solve(cnf_to_milp(formula))
        assert solved.status.value == "infeasible"
    elif _BACKEND == "minizinc":
        solver = MiniZincSolver(
            os.environ.get("CLAASP_PARITY_CP_SOLVER", "gecode"), timeout_seconds=30
        )
        solved = solver.solve(BooleanMiniZincLowerer().lower(formula))
        assert solved.status.value == "unsatisfiable"
    else:
        raise ValueError(f"unknown parity backend: {_BACKEND}")
