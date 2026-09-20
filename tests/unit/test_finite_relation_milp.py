from itertools import product

import pytest

from claasp.representations.constraints.milp.relations import FiniteBinaryRelationMILPModel


def test_one_hot_formulation_matches_all_possible_small_assignments():
    relation = FiniteBinaryRelationMILPModel(("x", "y"), ((0, 0), (1, 1)), row_costs=(0, 2))
    model = relation.milp_model()
    for values in product((0, 1), repeat=4):
        assignment = dict(zip(relation.columns + relation.selectors, values))
        assert model.is_feasible(assignment) is (
            values[:2] in relation.rows
            and sum(values[2:]) == 1
            and values[:2] == relation.rows[values[3]]
        )
    assert model.objective_value(relation.witness((1, 1))) == 2
    with pytest.raises(ValueError, match="not accepted"):
        relation.witness((0, 1))


def test_empty_relation_is_explicitly_infeasible():
    model = FiniteBinaryRelationMILPModel(("x",), ()).milp_model()
    assert not model.is_feasible({"x": 0}) and not model.is_feasible({"x": 1})


@pytest.mark.parametrize(
    "columns,rows",
    [
        ((), ()),
        (("x",), ((0,), (0,))),
        (("x",), ((2,),)),
        (("x",), ((0, 1),)),
        (("__relation_row_0",), ((0,),)),
    ],
)
def test_invalid_relations_are_rejected(columns, rows):
    with pytest.raises(ValueError):
        FiniteBinaryRelationMILPModel(columns, rows)
