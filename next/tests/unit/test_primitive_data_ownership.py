import importlib
from pathlib import Path

from claasp_next.parameters import poseidon_bn254_width3 as convenience_poseidon_parameters
from claasp_next.primitives.permutations.poseidon import poseidon_bn254_width3


ROOT = Path(__file__).parents[2] / "src/claasp_next"
CATEGORIES = (
    "block_ciphers", "tweakable_block_ciphers", "permutations",
    "block_functions", "functions",
)


def test_native_catalogue_has_no_frozen_graph_artifacts():
    for category in CATEGORIES:
        category_root = ROOT / "primitives" / category
        assert not (category_root / "data").exists()
        assert not tuple(category_root.glob("*/data/index.json"))
        assert not tuple(category_root.glob("*/data/*.json.gz"))


def test_packages_are_reserved_for_owned_realizations_or_supporting_data():
    primitive_root = ROOT / "primitives"
    assert (primitive_root / "block_ciphers/aes/primitive.py").is_file()
    assert (primitive_root / "block_ciphers/lowmc/data/lowmc_constants_p128_k128_r20.dat").is_file()
    assert (primitive_root / "permutations/poseidon/parameters.py").is_file()
    assert (primitive_root / "block_ciphers/twofish.py").is_file()
    assert (primitive_root / "block_ciphers/warp.py").is_file()
    for module in ("aes", "lowmc"):
        importlib.import_module(f"claasp_next.primitives.block_ciphers.{module}")


def test_every_multi_realization_family_uses_one_same_import_path_package():
    families = {
        "block_ciphers": {
            "aradi": ("primitive.py", "sbox.py", "sbox_compact_linear_map.py"),
            "des": ("primitive.py", "exact_key_length.py"),
            "gift": ("primitive.py", "sbox.py"),
            "katan": ("primitive.py", "fsr.py"),
            "ktantan": ("primitive.py", "fsr.py"),
            "prince": ("primitive.py", "v2.py"),
            "simeck": ("primitive.py", "sbox.py"),
            "simon": ("primitive.py", "sbox.py"),
            "tinyjambu": ("primitive.py", "word.py", "fsr_word.py"),
            "ublock": ("primitive.py", "single_linear_layer.py"),
        },
        "permutations": {
            "ascon": ("primitive.py", "sbox_sigma.py", "sbox_sigma_no_matrix.py"),
            "gaston": ("primitive.py", "sbox.py", "sbox_theta.py"),
            "gimli": ("primitive.py", "sbox.py"),
            "keccak": ("primitive.py", "sbox.py", "invertible.py"),
            "spongent_pi": ("primitive.py", "fsr.py", "precomputation.py"),
            "xoodoo": ("primitive.py", "sbox.py", "invertible.py"),
        },
        "tweakable_block_ciphers": {
            "qarmav2": ("primitive.py", "mixcolumn.py"),
        },
    }
    for category, packages in families.items():
        for family, modules in packages.items():
            package = ROOT / "primitives" / category / family
            assert (package / "__init__.py").is_file()
            assert {path.name for path in package.glob("*.py")} == {"__init__.py", *modules}
            assert not package.with_suffix(".py").exists()
            importlib.import_module(f"claasp_next.primitives.{category}.{family}")


def test_poseidon_owns_parameters_data_provenance_and_license():
    package = ROOT / "primitives/permutations/poseidon"
    assert (package / "primitive.py").is_file()
    assert (package / "parameters.py").is_file()
    assert (package / "data/poseidon_bn254_width3.json").is_file()
    assert (package / "data/NOTICE.md").is_file()
    assert not (ROOT / "parameters/data").exists()
    assert convenience_poseidon_parameters() is poseidon_bn254_width3()
