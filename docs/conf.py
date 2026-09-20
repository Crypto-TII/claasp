"""Sphinx configuration for the Sage-independent CLAASP documentation."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

guide = os.environ.get("CLAASP_DOCS_GUIDE", "user")
if guide not in {"user", "developer"}:
    raise ValueError("CLAASP_DOCS_GUIDE must be 'user' or 'developer'")

project = "CLAASP"
author = "TII Cryptanalysis Team"
copyright = "Technology Innovation Institute LLC"  # noqa: A001 - required by Sphinx
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
exclude_patterns = ["_build", "index.rst", "public_api_namespaces.rst"]
if guide == "user":
    exclude_patterns.extend(
        [
            "developer_guide.rst",
            "development.rst",
            "architecture.rst",
            "composite_architecture.rst",
            "representation_architecture.rst",
            "diagram_representations.rst",
            "extending_analysis.rst",
            "api.rst",
            "boolean_models.rst",
            "polynomial_models.rst",
            "smt_models.rst",
            "milp_models.rst",
            "cp_models.rst",
            "catalogue_architecture.rst",
            "transformation_architecture.rst",
            "component_analysis_architecture.rst",
            "presentation_architecture.rst",
            "serialization_architecture.rst",
            "documentation_quality.rst",
        ]
    )
else:
    exclude_patterns.extend(
        [
            "user_guide.rst",
            "getting_started.rst",
            "traditional_primitives.rst",
            "composite_blocks.rst",
            "batch_evaluation.rst",
            "displaying_results.rst",
            "primitive_catalogue.rst",
            "transformations.rst",
            "component_properties.rst",
            "serialization_and_source.rst",
        ]
    )
nitpicky = True
show_warning_types = True
# autodoc renders a Generic type parameter's bound TypeVar as a py:class
# cross-reference, but a TypeVar is not itself a documented class.
nitpick_ignore = [
    ("py:class", "claasp.analysis.statistical_results.StatisticalReport"),
    ("py:class", "claasp.graph.composite.CompositeTemplate"),
]
nitpick_ignore_regex = [("py:class", r"(?:~T|.*\.T)")]

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
autodoc_preserve_defaults = True
doctest_test_doctest_blocks = "default"
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
