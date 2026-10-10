"""Portable whole-graph Boolean monomial reachability models."""

import pytest

from claasp import ArrayType, Primitive
from claasp.analysis import project_optimal_pool_monomial_parity
from claasp.components import BitwiseAnd
from claasp.domains import Word
from claasp.drivers.solvers import GurobiSolutionPoolResult, MILPStatus
from claasp.primitives import Simon
from claasp.representations.constraints.milp import (
    BooleanMonomialGraphMILPModel,
    CubeMonomialFeasibilityMILPModel,
    CubeSuperpolyQuery,
    MonomialDegreeMILPModel,
)


def test_simon_graph_model_has_a_maximum_degree_objective():
    model = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=1), 0, "plaintext").milp_model()
    assert model.objective_sense.value == "maximize"
    assert len(model.objective.terms) == 32
    assert len(model.variables) == 384


def test_simon_graph_model_can_restrict_degree_to_cube_positions():
    model = BooleanMonomialGraphMILPModel(
        Simon(number_of_rounds=2), 0, "plaintext", (0, 2)
    ).milp_model()
    assert dict(model.objective.terms) == {"wire_plaintext_0": 1.0, "wire_plaintext_2": 1.0}
    assert {constraint.name for constraint in model.constraints} >= {
        "exclude_variable_1",
        "exclude_variable_31",
    }


def test_public_monomial_queries_add_explicit_degree_and_cube_contracts():
    primitive = Simon(number_of_rounds=1)
    degree = MonomialDegreeMILPModel(
        primitive, output_bit=0, variable_input="plaintext"
    ).milp_model()
    cube = CubeMonomialFeasibilityMILPModel(
        primitive,
        output_bit=0,
        variable_input="plaintext",
        cube_positions=(1, 8),
    ).milp_model()
    assert degree.objective_sense.value == "maximize"
    assert cube.objective.terms == ()
    assert {constraint.name for constraint in cube.constraints} >= {"fix_cube_1", "fix_cube_8"}


def test_exact_cube_superpoly_accounts_for_parity_and_key_coefficients():
    primitive = Primitive(
        "and", {"plaintext": ArrayType(Word(1), (1,)), "key": ArrayType(Word(1), (1,))}
    )
    primitive._builder.add_round()
    primitive._builder.set_output(
        primitive._builder.add_component(
            BitwiseAnd((primitive.graph.input("plaintext"), primitive.graph.input("key")))
        )
    )
    result = CubeSuperpolyQuery(
        primitive,
        output_bit=0,
        cube_input="plaintext",
        cube_positions=(0,),
        symbolic_input="key",
        symbolic_positions=(0,),
    ).compute()
    assert result.truth_table == (0, 1)
    assert result.anf_terms == ((0,),)
    assert result.coefficient((0,)) == 1
    assert result.coefficient(()) == 0


def test_cube_superpoly_dimension_and_positions_are_explicitly_bounded():
    primitive = Simon(number_of_rounds=1)
    with pytest.raises(ValueError, match="dimension"):
        CubeSuperpolyQuery(
            primitive,
            output_bit=0,
            cube_input="plaintext",
            cube_positions=(0, 1),
            symbolic_input="key",
            symbolic_positions=(0,),
            maximum_dimension=2,
        )


def test_complete_solution_pool_projects_full_input_monomials_with_parity():
    compilation = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=1), 0, "plaintext")
    names = {
        f"{input_name}[{bit}]": compilation._wire(input_name, bit)
        for input_name, port in compilation.primitive.graph.input_ports.items()
        for bit in range(compilation._width(port.array_type))
    }

    def assignment(*active):
        return {
            solver_name: float(public_name in active) for public_name, solver_name in names.items()
        }

    pool = GurobiSolutionPoolResult(
        MILPStatus.OPTIMAL,
        (
            assignment("plaintext[0]", "key[1]"),
            assignment("plaintext[0]", "key[1]"),
            assignment("plaintext[2]", "key[3]", "key[4]"),
        ),
        3.0,
        0.0,
        True,
    )
    result = project_optimal_pool_monomial_parity(compilation, pool)
    assert result.odd_input_monomials == (("plaintext[2]", "key[3]", "key[4]"),)
    assert result.maximum_degree("key") == 2
    assert result.enumerated_paths == 3
    assert result.complete


def test_truncated_solution_pool_cannot_certify_projected_parity():
    compilation = BooleanMonomialGraphMILPModel(Simon(number_of_rounds=1), 0, "plaintext")
    assignment = {
        compilation._wire(input_name, bit): 0.0
        for input_name, port in compilation.primitive.graph.input_ports.items()
        for bit in range(compilation._width(port.array_type))
    }
    pool = GurobiSolutionPoolResult(MILPStatus.OPTIMAL, (assignment,), 0.0, 0.0, False)
    result = project_optimal_pool_monomial_parity(compilation, pool)
    assert result.termination == "pool_capacity"
    with pytest.raises(RuntimeError, match="incomplete"):
        result.require_complete()


@pytest.mark.parametrize("positions", ((0, 0), (-1,), (32,)))
def test_simon_graph_model_rejects_invalid_variable_positions(positions):
    with pytest.raises(ValueError, match="variable_positions"):
        BooleanMonomialGraphMILPModel(Simon(number_of_rounds=1), 0, "plaintext", positions)
