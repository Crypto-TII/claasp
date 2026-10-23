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
release = "5.0.0rc1"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "matplotlib.sphinxext.plot_directive",
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
            "analysis.rst",
            "component_properties.rst",
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
            "algebraic_tests.rst",
            "polynomial_system_graphs.rst",
            "monomial_prediction.rst",
            "trail_search_introduction.rst",
            "differential_trail_search.rst",
            "linear_trail_search.rst",
            "truncated_differences.rst",
            "impossible_differentials.rst",
            "differential_linear.rst",
            "boomerang.rst",
            "quasi_differential.rst",
            "input_recovery.rst",
            "basic_randomness_intro.rst",
            "transformation_inversion.rst",
            "transformation_partial_inversion.rst",
            "transformation_slicing.rst",
            "transformation_key_schedule.rst",
            "transformation_pairing.rst",
            "basic_algebraic_tests.rst",
            "advanced_algebraic_tests.rst",
            "basic_polynomial_system_graphs.rst",
            "advanced_polynomial_system_graphs.rst",
            "basic_monomial_prediction.rst",
            "advanced_monomial_prediction.rst",
            "basic_differential_trail_search.rst",
            "advanced_differential_trail_search.rst",
            "basic_linear_trail_search.rst",
            "advanced_linear_trail_search.rst",
            "basic_truncated_differences.rst",
            "advanced_truncated_differences.rst",
            "basic_impossible_differentials.rst",
            "advanced_impossible_differentials.rst",
            "basic_differential_linear.rst",
            "advanced_differential_linear.rst",
            "basic_boomerang.rst",
            "advanced_boomerang.rst",
            "basic_quasi_differential.rst",
            "advanced_quasi_differential.rst",
            "basic_input_recovery.rst",
            "advanced_input_recovery.rst",
            "primitive_analysis.rst",
            "component_analysis.rst",
            "avalanche_analysis.rst",
            "continuous_diffusion.rst",
            "neural_blackbox.rst",
            "neural_differential.rst",
            "neural_autond.rst",
            "diffusion_and_randomness.rst",
            "basic_randomness_tests.rst",
            "basic_algebraic_analysis.rst",
            "basic_trail_search.rst",
            "basic_avalanche_analysis.rst",
            "basic_continuous_diffusion.rst",
            "basic_component_analysis.rst",
            "neural_distinguishers.rst",
            "basic_neural_blackbox.rst",
            "basic_neural_differential.rst",
            "basic_neural_autond.rst",
            "advanced_neural_blackbox.rst",
            "advanced_neural_differential.rst",
            "advanced_neural_autond.rst",
            "advanced_component_analysis.rst",
            "advanced_continuous_diffusion.rst",
            "advanced_avalanche_analysis.rst",
            "about_claasp.rst",
            "getting_started.rst",
            "evaluating_primitives.rst",
            "quick_analysis_scripts.rst",
            "traditional_primitives.rst",
            "customizing_aes.rst",
            "composite_blocks.rst",
            "batch_evaluation.rst",
            "displaying_results.rst",
            "primitive_catalogue.rst",
            "transformations.rst",
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

# Build notebook-style figures from the same script exercised by CI.
plot_include_source = False
plot_html_show_source_link = False
plot_formats = [("png", 120)]
