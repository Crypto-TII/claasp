import shutil

import pytest

from claasp import Bit, Primitive, ValueType
from claasp.analysis import AnalysisProblem
from claasp.components import Add
from claasp.drivers.solvers import KissatSolver, SatStatus
from claasp.primitives import Speck

pytestmark = pytest.mark.external


def test_kissat_solves_named_cnf_and_reports_version():
    assert shutil.which("kissat") is not None, "the external test job must install Kissat"
    primitive = Primitive(
        "xor", {"plaintext": ValueType(Bit(), (1,)), "key": ValueType(Bit(), (1,))}
    )
    primitive._builder.add_round()
    primitive._builder.set_output(
        primitive._builder.add_component(
            Add(
                (
                    primitive.graph.input("plaintext").select_all(),
                    primitive.graph.input("key").select_all(),
                )
            )
        )
    )
    result = primitive.analysis.solve(AnalysisProblem(primitive, (), {}))
    assert result.status is SatStatus.SATISFIABLE
    assert result.backend == "KissatSolver"
    assert KissatSolver().version()


def test_kissat_is_the_default_speck_trail_solver():
    primitive = Speck(number_of_rounds=2)
    result = primitive.analysis.find_lowest_weight_xor_differential_trail()
    dependency_free = primitive.analysis.find_optimal_trail(
        "xor_differential", backend="dependency_free"
    )
    assert result.is_optimal
    assert result.trail.total_weight == 1
    assert result.metadata.solver == "Kissat"
    assert result.metadata.solver_version is not None
    assert dependency_free.trail.total_weight == result.trail.total_weight
    assert dependency_free.lower_bound == result.lower_bound
    assert dependency_free.metadata.solver is None
