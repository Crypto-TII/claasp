"""Trail topics keep basic search guides separate from verification material."""

from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
DOCS = ROOT / "docs"


def _entries(name):
    lines = (DOCS / (name + ".rst")).read_text().splitlines()
    entries = []
    in_tree = False
    for line in lines:
        if line.startswith(".. toctree::"):
            in_tree = True
        elif (
            in_tree and line.startswith("   ") and line.strip() and not line.strip().startswith(":")
        ):
            entries.append(line.strip())
        elif in_tree and line and not line.startswith(" "):
            in_tree = False
    return entries


def test_every_trail_topic_has_basic_advanced_and_verification():
    topics = _entries("basic_trail_search")
    assert topics[0] == "trail_search_introduction"
    assert topics[-3:] == ["quasi_differential", "circle_differential", "circle_linear"]
    assert "Trail search and verification" in (DOCS / "basic_trail_search.rst").read_text()
    for topic in topics[1:]:
        entries = _entries(topic)
        assert [entry.split(" <")[0] for entry in entries] == [
            "Basic",
            "Advanced",
            "Verification",
        ]
        for entry in entries:
            target = entry.split("<", 1)[1].rstrip(">")
            assert (DOCS / (target + ".rst")).is_file()


def test_circle_endpoint_evaluation_is_below_verification():
    assert all(
        "basic_circle_linear_correlations" not in entry for entry in _entries("circle_linear")
    )
    entries = _entries("verification_circle_linear")
    assert entries == [
        "Characteristic validation <verification_circle_linear_characteristic>",
        "Distinguisher probability/correlation evaluation <basic_circle_linear_correlations>",
    ]
    text = (DOCS / "trail_search_introduction.rst").read_text()
    for term in (
        "Characteristic validation",
        "Concrete trail realizability",
        "Distinguisher probability/correlation evaluation",
    ):
        assert term in text
    assert "circle_differential().trail_probability" in text
    assert "does not automatically import an entire solver characteristic" in text
