"""Sphinx configuration for the Sage-independent CLAASP documentation."""

from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

guide = os.environ.get("CLAASP_DOCS_GUIDE", "user")
if guide not in {"user", "developer"}:
    raise ValueError("CLAASP_DOCS_GUIDE must be 'user' or 'developer'")

project = "CLAASP"
author = "TII Cryptanalysis Team"
copyright = "Technology Innovation Institute LLC"
version = "5.0"
release = "5.0.0.dev0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
master_doc = f"{guide}_guide"
exclude_patterns = ["_build", "index.rst"]
if guide == "user":
    exclude_patterns.extend([
        "developer_guide.rst",
        "development.rst",
        "architecture.rst",
        "extending_analysis.rst",
        "api.rst",
        "boolean_models.rst",
        "polynomial_models.rst",
        "smt_models.rst",
    ])
else:
    exclude_patterns.extend([
        "user_guide.rst",
        "getting_started.rst",
        "traditional_ciphers.rst",
        "batch_evaluation.rst",
        "displaying_results.rst",
    ])
nitpicky = True
show_warning_types = True

html_theme = "furo"
html_title = f"CLAASP {guide.title()} Guide"
html_static_path = ["_static"]
html_theme_options = {
    "light_css_variables": {
        "color-brand-primary": "#006d77",
        "color-brand-content": "#006d77",
    },
    "dark_css_variables": {
        "color-brand-primary": "#83c5be",
        "color-brand-content": "#83c5be",
    },
}

autodoc_member_order = "bysource"
autodoc_typehints = "description"
doctest_test_doctest_blocks = "default"
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
