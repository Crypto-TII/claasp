# ****************************************************************************
# Copyright 2023 Technology Innovation Institute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ****************************************************************************

import re
from dataclasses import dataclass

from claasp.cipher_modules.models.cp.minizinc_utils.mzn_bct_predicates import get_bct_operations
from claasp.cipher_modules.models.cp.minizinc_utils.mzn_continuous_predicates import get_continuous_operations
from claasp.cipher_modules.models.cp.minizinc_utils.usefulfunctions import MINIZINC_USEFUL_FUNCTIONS
from claasp.cipher_modules.models.milp.utils.mzn_predicates import get_word_operations as get_milp_word_operations
from claasp.cipher_modules.models.sat.utils.mzn_predicates import get_word_operations as get_sat_word_operations


GENERIC_CP_UTILS = "generic_cp_utils"
CIPHER_EVALUATION_CP = "cipher_evaluation_cp"
XOR_DIFFERENTIAL_CP = "xor_differential_cp"
XOR_LINEAR_CP = "xor_linear_cp"
DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP = "deterministic_truncated_xor_differential_cp"
SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP = "semi_deterministic_truncated_xor_differential_cp"
CONTINUOUS_DIFFERENTIAL_LINEAR = "continuous_differential_linear"
XOR_DIFFERENTIAL_ARX_SAT = "xor_differential_arx_sat"
XOR_DIFFERENTIAL_ARX_MILP = "xor_differential_arx_milp"
BOOMERANG_BCT_SAT = "boomerang_bct_sat"

DEFAULT_CP_MODEL_CONTEXTS = (
    GENERIC_CP_UTILS,
    CIPHER_EVALUATION_CP,
    XOR_DIFFERENTIAL_CP,
    XOR_LINEAR_CP,
    DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP,
    SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP,
)


@dataclass(frozen=True)
class MiniZincHelper:
    name: str
    body: str
    dependencies: tuple[str, ...] = ()
    required_includes: tuple[str, ...] = ()
    model_contexts: tuple[str, ...] = (GENERIC_CP_UTILS,)


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*")


def _strip_minizinc_strings(text):
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def _strip_minizinc_comments(text):
    return "\n".join(line.split("%", 1)[0] for line in text.splitlines())


def _definition_name(line):
    stripped = line.lstrip()
    if stripped.startswith("function "):
        _, separator, suffix = stripped.partition(":")
        if not separator:
            return None
        stripped = suffix.lstrip()
    elif stripped.startswith("predicate "):
        stripped = stripped[len("predicate ") :].lstrip()
    else:
        return None

    match = _IDENTIFIER_RE.match(stripped)
    if match and stripped[match.end() :].lstrip().startswith("("):
        return match.group(0)
    return None


def _split_minizinc_definitions(block):
    includes = []
    prefix_lines = []
    definitions = {}
    current_name = None
    current_lines = []

    for line in block.strip().splitlines():
        if line.strip().startswith("include "):
            include = line.strip()
            if include not in includes:
                includes.append(include)
            continue

        name = _definition_name(line)
        if name:
            if current_name:
                definitions.setdefault(current_name, []).append("\n".join(current_lines).strip())
            elif current_lines:
                prefix_lines.extend(current_lines)
            current_name = name
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_name:
        definitions.setdefault(current_name, []).append("\n".join(current_lines).strip())
    elif current_lines:
        prefix_lines.extend(current_lines)

    prefix = "\n".join(prefix_lines).strip()
    return includes, prefix, {name: "\n\n".join(bodies) for name, bodies in definitions.items()}


def _helpers_from_block(block, context, dependencies=None, helper_includes=None, prefix_name=None):
    required_includes, prefix, definitions = _split_minizinc_definitions(block)
    helpers = {}

    if prefix and prefix_name:
        helpers[(context, prefix_name)] = MiniZincHelper(
            name=prefix_name,
            body=prefix,
            required_includes=tuple(required_includes),
            model_contexts=(context,),
        )
        required_includes = []

    for name, body in definitions.items():
        helper_dependencies = tuple((dependencies or {}).get(name, ()))
        if prefix_name and name != prefix_name:
            helper_dependencies = (prefix_name,) + helper_dependencies
        helpers[(context, name)] = MiniZincHelper(
            name=name,
            body=body,
            dependencies=helper_dependencies,
            required_includes=tuple((helper_includes or {}).get(name, required_includes)),
            model_contexts=(context,),
        )
        required_includes = []

    return helpers


def _helpers_from_definitions(definitions, context, names, dependencies=None):
    helpers = {}
    for name in names:
        helpers[(context, name)] = MiniZincHelper(
            name=name,
            body=definitions[name],
            dependencies=tuple((dependencies or {}).get(name, ())),
            model_contexts=(context,),
        )
    return helpers


GENERIC_CP_UTILS_NAMES = {
    "Xor2",
    "Xor3",
    "And",
    "OR",
    "Compl",
    "LRot",
    "RRot",
    "LShift",
    "RShift",
    "bitArrayToInt",
    "IntTobitArray",
    "IntToBitLen",
    "count_eq",
    "Ham_weight",
}

CIPHER_EVALUATION_CP_NAMES = {
    "modadd",
}

XOR_DIFFERENTIAL_CP_NAMES = {
    "Andz",
    "Eq",
}

XOR_LINEAR_CP_NAMES = {
    "modadd_linear",
}

XOR_LINEAR_CP_DEPENDENCIES = {
    "modadd_linear": ("Xor3",),
}

DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_NAMES = {
    "xor_bit_p1",
    "modular_addition_word",
    "TRUNCATED_XOR",
}

DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_DEPENDENCIES = {
    "modular_addition_word": ("LShift", "xor_bit_p1"),
}

SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_NAMES = {
    "TRUNCATED_XOR",
    "counter_based_modadd_semideterministic",
}

SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_DEPENDENCIES = {
    "counter_based_modadd_semideterministic": ("TRUNCATED_XOR",),
}

CONTINUOUS_DIFFERENTIAL_LINEAR_DEPENDENCIES = {
    "continuous_xor_bit": ("continuous_bounds",),
    "continuous_xor": ("continuous_bounds", "continuous_xor_bit"),
    "continuous_maj_bit": ("continuous_bounds",),
    "continuous_modadd": ("continuous_bounds", "continuous_maj_bit", "continuous_xor_bit"),
    "continuous_LRot": ("continuous_bounds",),
    "continuous_RRot": ("continuous_bounds",),
    "cast": ("continuous_bounds",),
}

XOR_DIFFERENTIAL_ARX_SAT_DEPENDENCIES = {
    "modular_addition_word": ("modular_addition_bit_level_sat", "n_window_heuristic_constraints"),
    "xor_word": ("xor_bit",),
}

XOR_DIFFERENTIAL_ARX_MILP_DEPENDENCIES = {
    "modular_addition_word": ("modular_addition", "n_window_heuristic_constraints"),
    "xor_word": ("xor_bit",),
}

BOOMERANG_BCT_SAT_DEPENDENCIES = {
    "BVAssign": ("bct_constants",),
    "onlyLargeSwitch_BCT_enum": ("BVAssign",),
}


def _build_registry():
    helpers = {}
    _, _, core_definitions = _split_minizinc_definitions(MINIZINC_USEFUL_FUNCTIONS)
    helpers.update(_helpers_from_definitions(core_definitions, GENERIC_CP_UTILS, GENERIC_CP_UTILS_NAMES))
    helpers.update(
        _helpers_from_definitions(core_definitions, CIPHER_EVALUATION_CP, CIPHER_EVALUATION_CP_NAMES)
    )
    helpers.update(_helpers_from_definitions(core_definitions, XOR_DIFFERENTIAL_CP, XOR_DIFFERENTIAL_CP_NAMES))
    helpers.update(
        _helpers_from_definitions(core_definitions, XOR_LINEAR_CP, XOR_LINEAR_CP_NAMES, XOR_LINEAR_CP_DEPENDENCIES)
    )
    helpers.update(
        _helpers_from_definitions(
            core_definitions,
            DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP,
            DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_NAMES,
            DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_DEPENDENCIES,
        )
    )
    helpers.update(
        _helpers_from_definitions(
            core_definitions,
            SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP,
            SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_NAMES,
            SEMI_DETERMINISTIC_TRUNCATED_XOR_DIFFERENTIAL_CP_DEPENDENCIES,
        )
    )
    helpers.update(
        _helpers_from_block(
            get_continuous_operations(),
            CONTINUOUS_DIFFERENTIAL_LINEAR,
            CONTINUOUS_DIFFERENTIAL_LINEAR_DEPENDENCIES,
            prefix_name="continuous_bounds",
        )
    )
    helpers.update(
        _helpers_from_block(
            get_bct_operations(),
            BOOMERANG_BCT_SAT,
            BOOMERANG_BCT_SAT_DEPENDENCIES,
            prefix_name="bct_constants",
        )
    )
    helpers.update(_helpers_from_block(get_sat_word_operations(), XOR_DIFFERENTIAL_ARX_SAT, XOR_DIFFERENTIAL_ARX_SAT_DEPENDENCIES))
    helpers.update(_helpers_from_block(get_sat_word_operations(), BOOMERANG_BCT_SAT, XOR_DIFFERENTIAL_ARX_SAT_DEPENDENCIES))
    helpers.update(
        _helpers_from_block(get_milp_word_operations(), XOR_DIFFERENTIAL_ARX_MILP, XOR_DIFFERENTIAL_ARX_MILP_DEPENDENCIES)
    )
    return helpers


HELPERS = _build_registry()


def helpers_for_model_contexts(model_contexts=DEFAULT_CP_MODEL_CONTEXTS):
    selected_contexts = set(model_contexts)
    return [helper for (context, _), helper in HELPERS.items() if context in selected_contexts]


def collect_used_helpers(fragments, model_contexts=DEFAULT_CP_MODEL_CONTEXTS):
    text = "\n".join(fragment for fragment in fragments if fragment)
    text = _strip_minizinc_comments(_strip_minizinc_strings(text))

    used = set()
    for helper in helpers_for_model_contexts(model_contexts):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(helper.name)}(?=\s*\()"
        if re.search(pattern, text):
            used.add(helper.name)

    return used


def _helper_key(name, model_contexts):
    matching_keys = [(context, helper_name) for context, helper_name in HELPERS if context in model_contexts and helper_name == name]
    if not matching_keys:
        raise ValueError(f"Unknown MiniZinc helper {name!r} for model contexts {model_contexts!r}")
    return matching_keys[0]


def resolve_helper_closure(names, model_contexts=DEFAULT_CP_MODEL_CONTEXTS):
    ordered = []
    visiting = set()
    visited = set()
    model_contexts = tuple(model_contexts)

    def visit(name):
        key = _helper_key(name, model_contexts)
        if key in visited:
            return
        if key in visiting:
            raise ValueError(f"Cyclic MiniZinc helper dependency involving {name!r}")

        visiting.add(key)
        helper = HELPERS[key]
        for dependency in helper.dependencies:
            visit(dependency)
        visiting.remove(key)
        visited.add(key)
        ordered.append(key)

    for name in sorted(names):
        visit(name)

    return ordered


def render_helper_block(names, model_contexts=DEFAULT_CP_MODEL_CONTEXTS):
    ordered_keys = resolve_helper_closure(names, model_contexts)
    includes = []
    bodies = []

    for key in ordered_keys:
        helper = HELPERS[key]
        for include in helper.required_includes:
            if include not in includes:
                includes.append(include)
        body = helper.body.strip()
        if body and body not in bodies:
            bodies.append(body)

    return "\n\n".join(includes + bodies)


def render_model_context_helpers(model_contexts=DEFAULT_CP_MODEL_CONTEXTS):
    names = {helper.name for helper in helpers_for_model_contexts(model_contexts)}
    return render_helper_block(names, model_contexts)


def inject_helpers_into_declarations(declarations, constraints, model_contexts=DEFAULT_CP_MODEL_CONTEXTS, extra_fragments=None):
    fragments = list(declarations) + list(constraints)
    if extra_fragments:
        fragments.extend(extra_fragments)
    helper_block = render_helper_block(collect_used_helpers(fragments, model_contexts), model_contexts)
    if helper_block:
        return [helper_block] + list(declarations)
    return declarations
