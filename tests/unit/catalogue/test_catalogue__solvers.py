"""Solver views reuse canonical driver metadata and explicit availability rules."""

import importlib
import subprocess
from dataclasses import FrozenInstanceError
from io import StringIO
from types import SimpleNamespace

import pytest

from claasp.catalogue import (
    Catalogue,
    DriverAvailabilityRecord,
    DriverRecord,
    SolverCatalogueResult,
)

module = importlib.import_module("claasp.catalogue.catalogue")


def test_supported_query_uses_registered_records_without_any_probe(monkeypatch):
    catalogue = Catalogue()

    def forbidden(*args, **kwargs):
        pytest.fail("supported discovery must not probe dependencies or execute commands")

    monkeypatch.setattr(catalogue, "driver_availability", forbidden)
    monkeypatch.setattr(module.shutil, "which", forbidden)
    monkeypatch.setattr(module.importlib.util, "find_spec", forbidden)
    monkeypatch.setattr(module.subprocess, "run", forbidden)
    result = catalogue.solvers()
    assert isinstance(result, SolverCatalogueResult)
    assert result.entries == catalogue.drivers(kind="solver")
    assert all(a is b for a, b in zip(result.entries, catalogue.drivers(kind="solver")))
    assert result.availability == ()
    result.to_terminal(file=StringIO())
    assert {"singular", "msolve", "minizinc_chuffed", "gurobi"} <= {d.name for d in result.entries}
    with pytest.raises(FrozenInstanceError):
        field = "view"
        setattr(result, field, "both")


def test_a_new_registration_appears_in_all_views_without_another_registry(monkeypatch):
    catalogue = Catalogue()
    future = DriverRecord(
        "future_backend",
        "solver",
        "executable",
        "future-solver",
        "example:FutureSolver",
        frozenset(),
    )
    catalogue._drivers += (future,)
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda name: "/bin/future-solver" if name == "future-solver" else None,
    )
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: None)
    assert catalogue.solvers().entries[-1] is future
    both = catalogue.solvers(view="both")
    assert both.entries == catalogue.drivers(kind="solver")
    assert both.availability[-1] == DriverAvailabilityRecord(future, True, "/bin/future-solver")
    available = catalogue.solvers(view="available")
    assert available.entries == (future,)
    assert available.availability == catalogue.available_drivers(kind="solver")
    output = StringIO()
    available.to_terminal(file=output)
    assert "FutureSolver" in output.getvalue() and "/bin/future-solver" in output.getvalue()


def test_both_and_available_preserve_structured_probes_and_table_status(monkeypatch):
    catalogue = Catalogue()
    calls: list[DriverRecord] = []

    def probe(record):
        calls.append(record)
        return DriverAvailabilityRecord(
            record,
            record.name == "kissat",
            resolved="/bin/kissat" if record.name == "kissat" else None,
        )

    monkeypatch.setattr(catalogue, "driver_availability", probe)
    result = catalogue.solvers(view="both")
    assert tuple(calls) == result.entries
    assert tuple(p.driver for p in result.availability) == result.entries
    output = StringIO()
    result.to_terminal(file=output)
    assert len(calls) == len(result.entries), "printing must not repeat a probe"
    assert all(
        text in output.getvalue()
        for text in ("Available", "yes", "no", "KissatSolver", "SingularDriver")
    )
    assert catalogue.solvers(view="available").entries == (catalogue.driver("kissat"),)


def test_canonical_package_detection_and_empty_view_are_shared(monkeypatch):
    catalogue = Catalogue()
    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        module.importlib.util, "find_spec", lambda name: object() if name == "gurobipy" else None
    )
    assert catalogue.solvers(view="available").entries == (catalogue.driver("gurobi"),)
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: None)
    result = catalogue.solvers(view="available")
    assert result.entries == result.availability == ()
    output = StringIO()
    result.to_terminal(file=output)
    assert "No registered solver matched this view." in output.getvalue()
    with pytest.raises(ValueError, match="view must be"):
        catalogue.solvers(view="all")


@pytest.mark.parametrize(
    "error", (ImportError("missing"), ValueError("invalid spec"), OSError("broken"))
)
def test_broken_python_package_is_an_unavailable_probe(monkeypatch, error):
    def broken(name):
        raise error

    monkeypatch.setattr(module.importlib.util, "find_spec", broken)
    result = Catalogue().driver_availability("gurobi")
    assert not result.available and result.detail is not None
    assert "Module discovery failed" in result.detail


@pytest.mark.parametrize("registered", (True, False))
def test_named_minizinc_configurations_use_the_existing_probe(monkeypatch, registered):
    catalogue = Catalogue()
    monkeypatch.setattr(module.shutil, "which", lambda name: "/bin/minizinc")
    commands: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="Chuffed 0.13" if registered else "Gecode 6")

    monkeypatch.setattr(module.subprocess, "run", run)
    result = catalogue.solvers(view="both")
    probe = next(p for p in result.availability if p.driver.name == "minizinc_chuffed")
    assert probe.available == registered
    assert commands[0][0] == ("/bin/minizinc", "--solvers")
    assert commands[0][1]["timeout"] == 10


@pytest.mark.parametrize(
    "error", (subprocess.TimeoutExpired("minizinc", 10), PermissionError("not executable"))
)
def test_failed_configuration_probe_retains_other_available_solvers(monkeypatch, error):
    catalogue = Catalogue()
    monkeypatch.setattr(module.shutil, "which", lambda name: "/bin/" + name)
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda name: None)

    def broken(*args, **kwargs):
        raise error

    monkeypatch.setattr(module.subprocess, "run", broken)
    result = catalogue.solvers(view="both")
    chuffed = next(p for p in result.availability if p.driver.name == "minizinc_chuffed")
    assert not chuffed.available and chuffed.detail
    assert "kissat" in {d.name for d in catalogue.solvers(view="available").entries}


def test_every_exported_constraint_solver_implementation_is_registered():
    from claasp.drivers import solvers

    catalogue = Catalogue()
    declared = {record.implementation for record in catalogue.drivers(kind="solver")}
    exported = {
        f"{value.__module__}:{value.__name__}"
        for name in solvers.__all__
        if name.endswith("Solver")
        for value in (getattr(solvers, name),)
    }
    assert exported <= declared
