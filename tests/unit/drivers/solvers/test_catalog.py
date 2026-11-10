"""Catalogue inventory, installation evidence and dependency-free discovery."""

from io import StringIO

import pytest

from claasp import SolverCatalog, solver_catalog
from claasp.drivers.solvers import catalog


def test_supported_does_not_probe_or_import_optional_backends(monkeypatch):
    def forbidden(*args):
        raise AssertionError("supported-only discovery must not probe the environment")

    monkeypatch.setattr(catalog, "which", forbidden)
    monkeypatch.setattr(catalog, "find_spec", forbidden)
    result = solver_catalog()
    assert isinstance(result, SolverCatalog)
    assert len(result.entries) == 8
    assert all(item.installed is None for item in result.entries)
    assert len({item.driver for item in result.entries}) == len(result.entries)


def test_both_and_available_share_detected_inventory_and_table(monkeypatch):
    monkeypatch.setattr(
        catalog, "which", lambda name: "/bin/" + name if name in ("kissat", "minizinc") else None
    )
    monkeypatch.setattr(catalog, "find_spec", lambda name: object() if name == "gurobipy" else None)
    result = solver_catalog("both")
    installed = tuple(item for item in result.entries if item.installed)
    assert solver_catalog("available").entries == installed
    assert [item.name for item in installed] == ["Kissat", "MiniZinc", "Gurobi"]
    assert "configured solver required" in installed[1].detail
    assert "license not checked" in installed[2].detail
    stream = StringIO()
    result.to_terminal(file=stream)
    text = stream.getvalue()
    assert all(word in text for word in ("Installed", "yes", "no", "/bin/kissat", "GurobiSolver"))
    assert "model compatibility" in text


def test_no_installed_backends_and_invalid_view(monkeypatch):
    monkeypatch.setattr(catalog, "which", lambda name: None)
    monkeypatch.setattr(catalog, "find_spec", lambda name: None)
    result = solver_catalog("available")
    assert not result.entries
    stream = StringIO()
    result.to_terminal(file=stream)
    assert "No supported solver installation detected." in stream.getvalue()
    with pytest.raises(ValueError, match="view must be"):
        solver_catalog("all")


def test_broken_optional_package_discovery_is_not_installed(monkeypatch):
    monkeypatch.setattr(catalog, "which", lambda name: None)

    def missing(name):
        raise ImportError(name)

    monkeypatch.setattr(catalog, "find_spec", missing)
    assert not solver_catalog("available").entries
