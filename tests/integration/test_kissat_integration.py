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
    primitive.add_round()
    primitive.set_output(
        primitive.add_component(
            Add(
                (
                    primitive.input("plaintext").select_all(),
                    primitive.input("key").select_all(),
                )
            )
        )
    )
    result = primitive.analysis.solve(AnalysisProblem(primitive, (), {}))
    assert result.status is SatStatus.SATISFIABLE
    assert result.backend == "KissatSolver"
    assert KissatSolver().version()


def test_kissat_is_the_default_speck_trail_solver():
    result = Speck(number_of_rounds=2).analysis.find_lowest_weight_xor_differential_trail()
    assert result.is_optimal
    assert result.trail.total_weight == 1
    assert result.metadata.solver == "Kissat"
    assert result.metadata.solver_version is not None
