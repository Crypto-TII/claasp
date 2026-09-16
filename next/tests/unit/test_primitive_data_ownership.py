import importlib
from pathlib import Path

from claasp_next.parameters import poseidon_bn254_width3 as convenience_poseidon_parameters
from claasp_next.primitives.permutations.poseidon import poseidon_bn254_width3


ROOT = Path(__file__).parents[2] / "src/claasp_next"
CATEGORIES = (
    "block_ciphers", "tweakable_block_ciphers", "permutations",
    "block_functions", "functions",
)


def test_every_frozen_graph_catalogue_is_owned_by_its_public_primitive_package():
    indexes = []
    for category in CATEGORIES:
        category_root = ROOT / "primitives" / category
        assert not (category_root / "data").exists()
        indexes.extend(category_root.glob("*/data/index.json"))

    assert len(indexes) == 89
    for index in indexes:
        owner = index.parents[1]
        assert (owner / "__init__.py").is_file()
        assert (owner / "primitive.py").is_file()
        importlib.import_module(
            f"claasp_next.primitives.{owner.parent.name}.{owner.name}"
        )


def test_poseidon_owns_parameters_data_provenance_and_license():
    package = ROOT / "primitives/permutations/poseidon"
    assert (package / "primitive.py").is_file()
    assert (package / "parameters.py").is_file()
    assert (package / "data/poseidon_bn254_width3.json").is_file()
    assert (package / "data/NOTICE.md").is_file()
    assert not (ROOT / "parameters/data").exists()
    assert convenience_poseidon_parameters() is poseidon_bn254_width3()
