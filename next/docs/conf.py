"""Sphinx configuration for the Sage-independent CLAASP documentation."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

project = "CLAASP next"
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
exclude_patterns = ["_build"]
nitpicky = True
show_warning_types = True

html_theme = "furo"
html_title = "CLAASP 5 documentation"
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
