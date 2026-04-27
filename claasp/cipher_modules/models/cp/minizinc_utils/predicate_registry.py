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


CP_CORE = "cp_core"
CONTINUOUS = "continuous"
BCT = "bct"
SAT_WORD_OPS = "sat_word_ops"
MILP_WORD_OPS = "milp_word_ops"


@dataclass(frozen=True)
class MiniZincHelper:
    name: str
    body: str
    dependencies: tuple[str, ...] = ()
    required_includes: tuple[str, ...] = ()
    contexts: tuple[str, ...] = (CP_CORE,)


_FUNCTION_DECLARATION_RE = re.compile(r"^\s*function\s+.*?:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PREDICATE_DECLARATION_RE = re.compile(r"^\s*predicate\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _strip_minizinc_strings(text):
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def _strip_minizinc_comments(text):
    return "\n".join(line.split("%", 1)[0] for line in text.splitlines())


def _definition_name(line):
    match = _FUNCTION_DECLARATION_RE.match(line) or _PREDICATE_DECLARATION_RE.match(line)
    if match:
        return match.group(1)
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
            contexts=(context,),
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
            contexts=(context,),
        )
        required_includes = []

    return helpers


CP_CORE_DEPENDENCIES = {
    "modadd_linear": ("Xor3",),
    "modular_addition_word": ("LShift", "xor_bit_p1"),
    "counter_based_modadd_semideterministic": ("TRUNCATED_XOR",),
}

CONTINUOUS_DEPENDENCIES = {
    "continuous_xor_bit": ("continuous_bounds",),
    "continuous_xor": ("continuous_bounds", "continuous_xor_bit"),
    "continuous_maj_bit": ("continuous_bounds",),
    "continuous_modadd": ("continuous_bounds", "continuous_maj_bit", "continuous_xor_bit"),
    "continuous_LRot": ("continuous_bounds",),
    "continuous_RRot": ("continuous_bounds",),
    "cast": ("continuous_bounds",),
}

SAT_WORD_OPS_DEPENDENCIES = {
    "modular_addition_word": ("modular_addition_bit_level_sat", "n_window_heuristic_constraints"),
    "xor_word": ("xor_bit",),
}

MILP_WORD_OPS_DEPENDENCIES = {
    "modular_addition_word": ("modular_addition", "n_window_heuristic_constraints"),
    "xor_word": ("xor_bit",),
}

BCT_DEPENDENCIES = {
    "BVAssign": ("bct_constants",),
    "onlyLargeSwitch_BCT_enum": ("BVAssign",),
}


def _build_registry():
    helpers = {}
    helpers.update(_helpers_from_block(MINIZINC_USEFUL_FUNCTIONS, CP_CORE, CP_CORE_DEPENDENCIES))
    helpers.update(
        _helpers_from_block(
            get_continuous_operations(),
            CONTINUOUS,
            CONTINUOUS_DEPENDENCIES,
            prefix_name="continuous_bounds",
        )
    )
    helpers.update(_helpers_from_block(get_bct_operations(), BCT, BCT_DEPENDENCIES, prefix_name="bct_constants"))
    helpers.update(_helpers_from_block(get_sat_word_operations(), SAT_WORD_OPS, SAT_WORD_OPS_DEPENDENCIES))
    helpers.update(_helpers_from_block(get_milp_word_operations(), MILP_WORD_OPS, MILP_WORD_OPS_DEPENDENCIES))
    return helpers


HELPERS = _build_registry()


def helpers_for_contexts(contexts=(CP_CORE,)):
    selected_contexts = set(contexts)
    return [helper for (context, _), helper in HELPERS.items() if context in selected_contexts]


def collect_used_helpers(fragments, contexts=(CP_CORE,)):
    text = "\n".join(fragment for fragment in fragments if fragment)
    text = _strip_minizinc_comments(_strip_minizinc_strings(text))

    used = set()
    for helper in helpers_for_contexts(contexts):
        pattern = rf"(?<![A-Za-z0-9_]){re.escape(helper.name)}(?=\s*\()"
        if re.search(pattern, text):
            used.add(helper.name)

    return used


def _helper_key(name, contexts):
    matching_keys = [(context, helper_name) for context, helper_name in HELPERS if context in contexts and helper_name == name]
    if not matching_keys:
        raise ValueError(f"Unknown MiniZinc helper {name!r} for contexts {contexts!r}")
    return matching_keys[0]


def resolve_helper_closure(names, contexts=(CP_CORE,)):
    ordered = []
    visiting = set()
    visited = set()
    contexts = tuple(contexts)

    def visit(name):
        key = _helper_key(name, contexts)
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


def render_helper_block(names, contexts=(CP_CORE,)):
    ordered_keys = resolve_helper_closure(names, contexts)
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


def render_context_helpers(contexts=(CP_CORE,)):
    names = {helper.name for helper in helpers_for_contexts(contexts)}
    return render_helper_block(names, contexts)


def inject_helpers_into_declarations(declarations, constraints, contexts=(CP_CORE,), extra_fragments=None):
    fragments = list(declarations) + list(constraints)
    if extra_fragments:
        fragments.extend(extra_fragments)
    helper_block = render_helper_block(collect_used_helpers(fragments, contexts), contexts)
    if helper_block:
        return [helper_block] + list(declarations)
    return declarations
