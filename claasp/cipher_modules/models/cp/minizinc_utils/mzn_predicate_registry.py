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

from dataclasses import dataclass, field

from . import usefulfunctions

MINIZINC_GLOBALS = "minizinc_globals"
LEGACY_MINIZINC_USEFUL_FUNCTIONS = "legacy_minizinc_useful_functions"
MINIZINC_XOR_DIFFERENTIAL_HELPERS = "minizinc_xor_differential_helpers"

XOR_DIFFERENTIAL_HELPERS = """
% Eq
function array[int] of var 0..1: Eq(array[int] of var 0..1: a, array[int] of var 0..1: b, array[int] of var 0..1: c)=
array1d(0..(length(a)-1), [all_equal([a[j],b[j],c[j]]) | j in 0..length(a)-1]);

% Left shift of X by val positions
function array[int] of var 0..2: LShift(array[int] of var 0..2: X, var int:val)=
array1d(0..(length(X)-1), [if j<length(X)-val then X[(j+val) mod length(X)] else 0 endif | j in 0..(length(X)-1)]);
"""


@dataclass(frozen=True)
class MiniZincPredicateModule:
    name: str
    body: str
    dependencies: tuple[str, ...] = field(default_factory=tuple)


class MiniZincPredicateRegistry:
    def __init__(self, modules=None):
        self._modules = {}
        for module in modules or []:
            self.register_module(module)

    def register_module(self, module):
        if module.name in self._modules:
            raise ValueError(f"MiniZinc predicate module {module.name!r} is already registered")
        self._modules[module.name] = module

    def module_names(self):
        return tuple(self._modules)

    def resolve_modules(self, module_names):
        resolved = []
        visiting = set()
        visited = set()

        def visit(module_name):
            if module_name in visited:
                return
            if module_name in visiting:
                raise ValueError(f"MiniZinc predicate module dependency cycle at {module_name!r}")
            if module_name not in self._modules:
                raise ValueError(f"MiniZinc predicate module {module_name!r} is not registered")

            visiting.add(module_name)
            module = self._modules[module_name]
            for dependency in module.dependencies:
                visit(dependency)
            visiting.remove(module_name)
            visited.add(module_name)
            resolved.append(module)

        for module_name in module_names:
            visit(module_name)

        return tuple(resolved)

    def render_modules(self, module_names):
        return [module.body for module in self.resolve_modules(module_names) if module.body]


def build_default_minizinc_predicate_registry():
    return MiniZincPredicateRegistry(
        [
            MiniZincPredicateModule(MINIZINC_GLOBALS, 'include "globals.mzn";'),
            MiniZincPredicateModule(
                LEGACY_MINIZINC_USEFUL_FUNCTIONS,
                usefulfunctions.MINIZINC_USEFUL_FUNCTIONS,
                dependencies=(MINIZINC_GLOBALS,),
            ),
            MiniZincPredicateModule(
                MINIZINC_XOR_DIFFERENTIAL_HELPERS,
                XOR_DIFFERENTIAL_HELPERS,
                dependencies=(MINIZINC_GLOBALS,),
            ),
        ]
    )