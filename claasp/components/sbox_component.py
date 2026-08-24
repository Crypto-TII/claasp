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

import math
import subprocess
from itertools import combinations, product
from math import log
from operator import xor

from sage.arith.misc import is_power_of_two
from sage.crypto.sbox import SBox

from claasp.cipher_modules.models.milp.utils import utils as milp_utils
from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_large_sboxes import (
    get_dictionary_that_contains_inequalities_for_large_sboxes,
    update_dictionary_that_contains_inequalities_for_large_sboxes,
)
from claasp.cipher_modules.models.milp.utils.generate_sbox_inequalities_for_trail_search import (
    get_dictionary_that_contains_inequalities_for_small_sboxes,
    update_dictionary_that_contains_inequalities_for_small_sboxes,
)
from claasp.cipher_modules.models.milp.utils.generate_undisturbed_bits_inequalities_for_sboxes import (
    get_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits,
    update_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits,
)
from claasp.cipher_modules.models.milp.utils.milp_name_mappings import MILP_DEFAULT_WEIGHT_PRECISION
from claasp.cipher_modules.models.milp.utils.utils import espresso_pos_to_constraints
from claasp.cipher_modules.models.sat.utils import constants
from claasp.cipher_modules.models.smt.utils import utils as smt_utils
from claasp.component import Component, free_input
from claasp.input import Input


def check_table_feasibility(table, table_type, solver):
    """
    Check that every non-zero entry in a table is a power of two.

    INPUT:

    - ``table`` -- a Sage matrix-like object supporting ``rows()``
    - ``table_type`` -- **string**; label used in the error message
    - ``solver`` -- **string**; solver name used in the error message

    OUTPUT:

    - None; raises ``ValueError`` when a non-zero entry is not a power of two

    EXAMPLES::

        sage: from sage.matrix.constructor import matrix
        sage: from claasp.components.sbox_component import check_table_feasibility
        sage: check_table_feasibility(matrix([[0, 2], [4, 0]]), 'DDT', 'MILP') is None
        True
        sage: check_table_feasibility(matrix([[0, 3], [4, 0]]), 'DDT', 'MILP')
        Traceback (most recent call last):
        ...
        ValueError: The S-box DDT of the cipher contains 3 which is not a power of two. Currently, MILP cannot handle it.
    """
    occurrences = set(abs(value) for row in table.rows() for value in set(row)) - {0}
    for occurrence in occurrences:
        if not is_power_of_two(occurrence):
            raise ValueError(
                f"The S-box {table_type} of the cipher contains {occurrence} "
                f"which is not a power of two. Currently, {solver} cannot handle it."
            )


def cp_update_ddt_valid_probabilities(
    cipher, component, word_size, cp_declarations, table_items, valid_probabilities, sbox_mant
):
    """
    Update CP bookkeeping for S-box differential probabilities.

    INPUT:

    - ``cipher`` -- cipher-like object exposing ``is_spn()``
    - ``component`` -- component-like object with ``input_bit_size``, ``id``, ``description``,
      ``input_id_links`` and ``input_bit_positions``
    - ``word_size`` -- **integer**; word size used for SPN word activity declarations
    - ``cp_declarations`` -- **list**; declarations updated in place
    - ``table_items`` -- **list**; table items updated in place
    - ``valid_probabilities`` -- **set**; differential weights updated in place
    - ``sbox_mant`` -- **list**; cache of already processed S-boxes

    OUTPUT:

    - None; the input collections are modified in place

    EXAMPLES::

        sage: from claasp.components.sbox_component import Sbox, cp_update_ddt_valid_probabilities
        sage: class DummyCipher:
        ....:     def is_spn(self):
        ....:         return True
        sage: component = Sbox(0, 0, ['xor_0_0'], [[0, 1, 2, 3]], 4, [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])
        sage: cp_declarations, table_items, valid_probabilities, sbox_mant = [], [], set(), []
        sage: cp_update_ddt_valid_probabilities(DummyCipher(), component, 4, cp_declarations, table_items, valid_probabilities, sbox_mant)
        sage: len(valid_probabilities) > 0
        True
        sage: cp_declarations
        ['constraint (xor_0_0[0]+xor_0_0[1]+xor_0_0[2]+xor_0_0[3] > 0) = word_sbox_0_0[0];', 'array[0..0] of var 0..1: word_sbox_0_0;']
        sage: table_items
        ['[word_sbox_0_0[s] | s in 0..0]']
        sage: sbox_mant
        [([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2], 'sbox_0_0')]
    """
    input_size = int(component.input_bit_size)
    output_id_link = component.id
    description = component.description
    sbox = SBox(description)
    sbox_already_in = False
    for mant in sbox_mant:
        if description == mant[0]:
            sbox_already_in = True
    if not sbox_already_in:
        sbox_ddt = sbox.difference_distribution_table()
        for i in range(sbox_ddt.nrows()):
            set_of_occurrences = set(sbox_ddt.rows()[i])
            set_of_occurrences -= {0}
            valid_probabilities.update(
                {round(100 * math.log2(2**input_size / occurrence)) for occurrence in set_of_occurrences}
            )
        sbox_mant.append((description, output_id_link))
    if cipher.is_spn():
        input_id_link = component.input_id_links[0]
        input_bit_positions = component.input_bit_positions[0]
        all_inputs = [f"{input_id_link}[{position}]" for position in input_bit_positions]
        for i in range(input_size // word_size):
            ineq_left_side = "+".join([f"{all_inputs[i * word_size + j]}" for j in range(word_size)])
            new_declaration = f"constraint ({ineq_left_side} > 0) = word_{output_id_link}[{i}];"
            cp_declarations.append(new_declaration)
        cp_declarations.append(f"array[0..{input_size // word_size - 1}] of var 0..1: word_{output_id_link};")
        table_items.append(f"[word_{output_id_link}[s] | s in 0..{input_size // word_size - 1}]")


def cp_update_lat_valid_probabilities(component, valid_probabilities, sbox_mant):
    """
    Update CP bookkeeping for S-box linear probabilities.

    INPUT:

    - ``component`` -- component-like object with ``input_bit_size``, ``id`` and ``description``
    - ``valid_probabilities`` -- **set**; linear weights updated in place
    - ``sbox_mant`` -- **list**; cache of already processed S-boxes

    OUTPUT:

    - None; the input collections are modified in place

    EXAMPLES::

        sage: from claasp.components.sbox_component import Sbox, cp_update_lat_valid_probabilities
        sage: component = Sbox(0, 0, ['xor_0_0'], [[0, 1, 2, 3]], 4, [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2])
        sage: valid_probabilities, sbox_mant = set(), []
        sage: cp_update_lat_valid_probabilities(component, valid_probabilities, sbox_mant)
        sage: len(valid_probabilities) > 0
        True
        sage: sbox_mant
        [([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2], 'sbox_0_0')]
    """
    input_size = component.input_bit_size
    output_id_link = component.id
    description = component.description
    sbox = SBox(description)
    already_in = False
    for i in range(len(sbox_mant)):
        if description == sbox_mant[i][0]:
            already_in = True
    if not already_in:
        sbox_lat = sbox.linear_approximation_table()
        for i in range(sbox_lat.nrows()):
            set_of_occurrences = set(sbox_lat.rows()[i])
            set_of_occurrences -= {0}
            valid_probabilities.update(
                {round(100 * math.log2(abs(pow(2, input_size - 1) / occurence))) for occurence in set_of_occurrences}
            )
        sbox_mant.append((description, output_id_link))


def milp_set_constraints_from_dictionnary_for_large_sbox(
    component_id,
    input_vars,
    output_vars,
    sbox_input_size,
    sbox_output_size,
    x,
    p,
    probability_dictionary,
    analysis,
    weight_precision,
):
    """
    Build MILP constraints for a large S-box from a probability-to-inequalities dictionary.

    INPUT:

    - ``component_id`` -- **string**; identifier of the S-box component
    - ``input_vars`` -- **list**; names of input MILP variables
    - ``output_vars`` -- **list**; names of output MILP variables
    - ``sbox_input_size`` -- **integer**; input bit width of the S-box
    - ``sbox_output_size`` -- **integer**; output bit width of the S-box
    - ``x`` -- MILP variable dictionary for bit and activity variables
    - ``p`` -- MILP variable dictionary for probability variables
    - ``probability_dictionary`` -- **dict**; maps a probability value to its inequality encodings
    - ``analysis`` -- **string**; either ``'differential'`` or a linear-analysis label
    - ``weight_precision`` -- **integer**; decimal precision used for probability weights

    OUTPUT:

    - ``list`` -- MILP constraints derived from the dictionary

    EXAMPLES::

        sage: from claasp.components.sbox_component import milp_set_constraints_from_dictionnary_for_large_sbox
        sage: x = {
        ....:     'sbox_0_0_active': 1,
        ....:     'i0': 1,
        ....:     'i1': 0,
        ....:     'o0': 1,
        ....:     'o1': 0,
        ....:     'sbox_0_0_sboxproba_2': 1,
        ....: }
        sage: p = {'sbox_0_0_probability': 1}
        sage: constraints = milp_set_constraints_from_dictionnary_for_large_sbox(
        ....:     'sbox_0_0', ['i0', 'i1'], ['o0', 'o1'], 2, 2, x, p, {2: ['1111']}, 'differential', 0
        ....: )
        sage: constraints
        [True, True, True, True, True, True, True]
    """
    constraints = []
    # condition to know if sbox is active or not
    constraints.append(
        sbox_input_size * x[f"{component_id}_active"] >= sum(x[input_vars[i]] for i in range(sbox_input_size))
    )
    constraints.append(
        sbox_input_size * (1 - x[f"{component_id}_active"])
        >= -sum(x[input_vars[i]] for i in range(sbox_input_size)) + 1
    )
    constraints += [x[f"{component_id}_active"] >= x[output_vars[i]] for i in range(sbox_output_size)]
    # mip.add_constraint(sum(x[output_vars[i]] for i in range(sbox.input_size())) >= x[id + "_active"])

    if analysis == "differential":
        exponent = sbox_input_size
    else:
        exponent = sbox_input_size - 1

    M = (10**weight_precision) * sbox_input_size
    constraint_choice_proba = 0
    constraint_compute_proba = 0
    for proba in probability_dictionary.keys():
        for ineq in probability_dictionary[proba]:
            constraint = milp_large_xor_probability_constraint_for_inequality(
                M, component_id, ineq, input_vars, output_vars, proba, sbox_input_size, sbox_output_size, x
            )
            constraints.append(constraint >= 0)

        constraint_choice_proba += x[f"{component_id}_sboxproba_{proba}"]
        constraint_compute_proba += (
            x[f"{component_id}_sboxproba_{proba}"]
            * (10**weight_precision)
            * round(-log(abs(proba) / (2**exponent), 2), weight_precision)
        )
    constraints.append(constraint_choice_proba == x[f"{component_id}_active"])
    constraints.append(p[f"{component_id}_probability"] == constraint_compute_proba)

    return constraints


def milp_large_xor_probability_constraint_for_inequality(
    M, component_id, ineq, input_vars, output_vars, proba, sbox_input_size, sbox_output_size, x
):
    """
    Build the linear expression corresponding to one large-S-box inequality.

    INPUT:

    - ``M`` -- **integer**; big-M constant used to activate the inequality conditionally
    - ``component_id`` -- **string**; identifier of the S-box component
    - ``ineq`` -- **string**; bit-pattern encoding of the inequality
    - ``input_vars`` -- **list**; names of input MILP variables
    - ``output_vars`` -- **list**; names of output MILP variables
    - ``proba`` -- probability key associated with the inequality
    - ``sbox_input_size`` -- **integer**; input bit width of the S-box
    - ``sbox_output_size`` -- **integer**; output bit width of the S-box
    - ``x`` -- MILP variable dictionary for bit and probability-choice variables

    OUTPUT:

    - MILP linear expression representing the inequality before the final comparison

    EXAMPLES::

        sage: from claasp.components.sbox_component import milp_large_xor_probability_constraint_for_inequality
        sage: x = {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'sbox_0_0_sboxproba_4': 0}
        sage: milp_large_xor_probability_constraint_for_inequality(
        ....:     10, 'sbox_0_0', '1010', ['a', 'b'], ['c', 'd'], 4, 2, 2, x
        ....: )
        11
    """
    constraint = 0
    for i in range(sbox_input_size - 1, -1, -1):
        char = ineq[i]
        if char == "1":
            constraint += 1 - x[input_vars[i]]
        elif char == "0":
            constraint += x[input_vars[i]]
    for i in range(sbox_input_size + sbox_output_size - 1, sbox_input_size - 1, -1):
        char = ineq[i]
        if char == "1":
            constraint += 1 - x[output_vars[i % sbox_input_size]]
        elif char == "0":
            constraint += x[output_vars[i % sbox_input_size]]
    constraint -= 1
    constraint += M * (1 - x[f"{component_id}_sboxproba_{proba}"])  # conditional constraints

    return constraint


def sat_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_size):
    """
    Build a SAT/CMS clause template from a transition table using Espresso.

    INPUT:

    - ``table`` -- Sage matrix-like table of transition counts or correlations
    - ``get_hamming_weight_function`` -- callable returning the encoded hamming weight width
    - ``input_bit_len`` -- **integer**; number of input bits
    - ``output_bit_size`` -- **integer**; number of output bits

    OUTPUT:

    - ``list`` -- tuples of ``(bit_value, bit_index)`` pairs representing a clause template

    EXAMPLES::

        sage: from sage.matrix.constructor import matrix
        sage: from claasp.components.sbox_component import sat_build_table_template
        sage: def hw(_, value):
        ....:     return 0 if value == 1 else 1
        sage: template = sat_build_table_template(matrix([[0, 1], [2, 0]]), hw, 1, 1)
        sage: template
        [((0, 1), (0, 2)), ((0, 0), (1, 2)), ((1, 0), (1, 1))]
    """
    # create espresso input
    input_length = input_bit_len + 2 * output_bit_size
    espresso_input = [f".i {input_length}", ".o 1"]
    for i in range(table.nrows()):
        for j in range(table.ncols()):
            if table[i, j] != 0:
                input_diff = f"{i:0{input_bit_len}b}"
                output_diff = f"{j:0{output_bit_size}b}"
                hamming_weight = get_hamming_weight_function(input_bit_len, table[i, j])
                weight_vec = "0" * (output_bit_size - hamming_weight)
                weight_vec += "1" * hamming_weight
                espresso_input.append(f"{input_diff}{output_diff}{weight_vec} 1")
    espresso_input.append(".e")
    espresso_input = "\n".join(espresso_input) + "\n"

    # execute espresso process
    espresso_process = subprocess.run(["espresso", "-epos"], input=espresso_input, capture_output=True, text=True)
    espresso_output = espresso_process.stdout.splitlines()

    # formatting template
    template = []
    for line in espresso_output[4:-1]:
        clause = tuple((int(line[i]), i) for i in range(input_length) if line[i] != "-")
        template.append(clause)

    return template


def smt_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_size):
    """
    Build an SMT clause template from a transition table.

    INPUT:

    - ``table`` -- Sage matrix-like table of transition counts or correlations
    - ``get_hamming_weight_function`` -- callable returning the encoded hamming weight width
    - ``input_bit_len`` -- **integer**; number of input bits
    - ``output_bit_size`` -- **integer**; number of output bits

    OUTPUT:

    - ``list`` -- SMT-ready clause template, identical to ``sat_build_table_template`` output

    EXAMPLES::

        sage: from sage.matrix.constructor import matrix
        sage: from claasp.components.sbox_component import sat_build_table_template, smt_build_table_template
        sage: def hw(_, value):
        ....:     return 0 if value == 1 else 1
        sage: table = matrix([[0, 1], [2, 0]])
        sage: smt_build_table_template(table, hw, 1, 1) == sat_build_table_template(table, hw, 1, 1)
        True
    """
    return sat_build_table_template(table, get_hamming_weight_function, input_bit_len, output_bit_size)


def smt_get_sbox_probability_constraints(bit_ids, template):
    """
    Convert a clause template into SMT assertions.

    INPUT:

    - ``bit_ids`` -- **list**; bit identifiers ordered by template index
    - ``template`` -- **list**; tuples of ``(bit_value, bit_index)`` pairs

    OUTPUT:

    - ``list`` -- SMT assertion strings

    EXAMPLES::

        sage: from claasp.components.sbox_component import smt_get_sbox_probability_constraints
        sage: smt_get_sbox_probability_constraints(['a', 'b'], [((0, 0), (1, 1))])
        ['(assert (or a (not b)))']
    """
    constraints = []
    for clause in template:
        literals = []
        for value in clause:
            literal = bit_ids[value[1]]
            if value[0]:
                literal = smt_utils.smt_not(literal)
            literals.append(literal)
        constraints.append(smt_utils.smt_assert(smt_utils.smt_or(literals)))

    return constraints


def _combine_truncated(input_1, input_2):
    """
    Combine two truncated bit-vectors.

    INPUT:

    - ``input_1`` -- **iterable**; first truncated bit-vector
    - ``input_2`` -- **iterable**; second truncated bit-vector

    OUTPUT:

    - ``list`` -- combined vector where differing positions are replaced by ``2``

    EXAMPLES::

        sage: from claasp.components.sbox_component import _combine_truncated
        sage: _combine_truncated((0, 1, 2), (0, 0, 2))
        [0, 2, 2]
    """
    return [bit_1 if bit_1 == bit_2 else 2 for bit_1, bit_2 in zip(input_1, input_2)]


def _get_truncated_output_difference(ddt_row, n):
    """
    Derive a truncated output difference from one DDT row.

    INPUT:

    - ``ddt_row`` -- **iterable**; one row of a difference distribution table
    - ``n`` -- **integer**; number of output bits

    OUTPUT:

    - ``tuple`` -- ``(has_undisturbed_bits, output_bits)`` where ``output_bits`` uses ``2`` for unknown bits

    EXAMPLES::

        sage: from claasp.components.sbox_component import _get_truncated_output_difference
        sage: _get_truncated_output_difference([4, 0, 0, 0], 2)
        (True, [0, 0])
        sage: _get_truncated_output_difference([1, 1, 1, 1], 2)
        (False, [2, 2])
    """
    output_bits = [2] * n
    has_undisturbed_bits = False
    list_of_delta_out = [delta_out for delta_out, probability in enumerate(ddt_row) if probability]
    for bit in range(n):
        delta = [j & (1 << bit) for j in list_of_delta_out]
        if delta.count(delta[0]) == len(delta):
            has_undisturbed_bits = True
            output_bits[n - 1 - bit] = 1 if delta[0] else 0
    return has_undisturbed_bits, output_bits


def _mzn_update_sbox_mant_for_deterministic_truncated_xor_differential(
    inv_output_id_link, undisturbed_bits, sbox_mant, inverse
):
    """
    Update and query the S-box deduplication cache for deterministic truncated xor differential constraints.

    `sbox_mant` ("S-box Materialized") is a deduplication cache that accumulates S-box table descriptions
    to avoid generating duplicate constraint declarations during constraint programming model generation.
    This is critical when the same S-box appears across multiple cipher rounds or component instances.

    Entries in `sbox_mant` for this function are stored as:
        [undisturbed_table_bits_string, output_id_link]

    where:
    - undisturbed_table_bits_string: comma-separated string of truncated input/output differential bits
    - output_id_link: the component ID (possibly with "inverse_" prefix if inverse=True)

    This function:
    1. Checks if the S-box's undisturbed table has already been declared (cache hit)
    2. Returns the existing output_id_link if found (for constraint reuse)
    3. Otherwise, adds the new entry to sbox_mant and returns the new output_id_link

    Args:
        inv_output_id_link: Component ID for this S-box (used as lookup key)
        undisturbed_bits: List of (input_tuple, output_tuple) differential pairs with undisturbed bits
        sbox_mant: Accumulating cache list modified in-place; tracks [table_bits, id] entries
        inverse: Boolean flag used for matching cache entries (e.g., "inverse_sbox_0_1")

    Returns:
        (already_in, output_id_link_sost, undisturbed_table_bits):
        - already_in: True if this S-box was already cached
        - output_id_link_sost: Component ID to use (reused if cached, new if not)
        - undisturbed_table_bits: The computed undisturbed bits as comma-separated string
    """
    undisturbed_bits_ddt = []
    for pair in undisturbed_bits:
        undisturbed_bits_ddt += list(pair[0]) + list(pair[1])
    for i in range(len(undisturbed_bits_ddt)):
        undisturbed_bits_ddt[i] = str(undisturbed_bits_ddt[i])
    undisturbed_table_bits = ",".join(undisturbed_bits_ddt)
    already_in = False
    output_id_link_sost = inv_output_id_link
    for mant in sbox_mant:
        if undisturbed_table_bits == mant[0] and ((not inverse) or (inverse and "inverse" in mant[1])):
            already_in = True
            output_id_link_sost = mant[1]
    if not already_in:
        sbox_mant.append([undisturbed_table_bits, inv_output_id_link])

    return already_in, output_id_link_sost, undisturbed_table_bits


class Sbox(Component):
    """
    Construct an S-box component.


    INPUT:

    - ``current_round_number`` -- **integer**; round index where the component is created. ``0`` is valid.
    - ``current_round_number_of_components`` -- **integer**; index of the component inside the round. ``0`` is valid.
    - ``input_id_links`` -- **list**; input component identifiers (usually strings). Must align with ``input_bit_positions``.
    - ``input_bit_positions`` -- **list**; bit positions for each input identifier (list of lists). Must align with ``input_id_links``.
    - ``output_bit_size`` -- **integer**; output size in bits. ``0`` is valid only when supported by the component semantics.
    - ``s_box_description`` -- **list**; S-box lookup table values.

    EXAMPLES::

        sage: from claasp.components.sbox_component import Sbox
        sage: component = Sbox(0, 0, ['input'], [[0, 1, 2]], 3, [0, 1, 2, 3, 4, 5, 6, 7])
        sage: print(component.id)
        sbox_0_0
        sage: print(component.type)
        sbox
        sage: print(len(component.description))
        8

    NOTE ON `sbox_mant` (S-box Materialized Cache):

    The S-box component's constraint generation methods for Constraint Programming (CP) models
    accept and return an ``sbox_mant`` parameter, a deduplication cache that avoids redundant table declarations.

    **Purpose**: When multiple S-boxes in a cipher are identical or share the same lookup structure, declaring
    the same constraint table multiple times is wasteful. The `sbox_mant` cache tracks already-generated tables
    across component rounds and instances.

    **Structure**: A list of entries where each entry type depends on the constraint model:
    - For ``cp_constraints``: ``(sbox_description, component_id)`` tuple
    - For ``cp_deterministic_truncated_xor_differential_constraints``: ``[undisturbed_bits_string, component_id]`` list

    **Usage Pattern**:
    1. Initialize with empty list: ``sbox_mant = []``
    2. Pass to first component: ``decls1, constraints1, sbox_mant = sbox1.cp_constraints(sbox_mant=[])``
    3. Reuse cache for subsequent components: ``decls2, constraints2, sbox_mant = sbox2.cp_constraints(sbox_mant)``
    4. If sbox2 matches sbox1, then ``decls2`` will be empty (table reused via table name reference)

    **Benefit**: Reduces constraint bloat in models with repeated S-box instances and improves solver performance.
    """
    sboxes_ddt_templates = {}
    sboxes_lat_templates = {}

    def __init__(
        self,
        current_round_number,
        current_round_number_of_components,
        input_id_links,
        input_bit_positions,
        output_bit_size,
        s_box_description,
    ):
        component_id = f"sbox_{current_round_number}_{current_round_number_of_components}"
        component_type = "sbox"
        input_len = sum(map(len, input_bit_positions))
        description = s_box_description
        component_input = Input(input_len, input_id_links, input_bit_positions)
        super().__init__(component_id, component_type, component_input, output_bit_size, description)

    def algebraic_polynomials(self, model):
        """
        Return a list of SBOX polynomials.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.algebraic.algebraic_model import AlgebraicModel
            sage: cipher = SboxCipher(bit_size=2, lookup_table=[0, 1, 3, 2])
            sage: sbox_component = cipher.component_from_id("sbox_0_0")
            sage: algebraic = AlgebraicModel(cipher)
            sage: sbox_component.algebraic_polynomials(algebraic)
            [sbox_0_0_y1 + sbox_0_0_x1,
            sbox_0_0_y0 + sbox_0_0_x1 + sbox_0_0_x0,
            sbox_0_0_x0*sbox_0_0_y0 + sbox_0_0_x0*sbox_0_0_x1 + sbox_0_0_x0,
            sbox_0_0_x0*sbox_0_0_y1 + sbox_0_0_x0*sbox_0_0_x1,
            sbox_0_0_x1*sbox_0_0_y0 + sbox_0_0_x0*sbox_0_0_x1 + sbox_0_0_x1,
            sbox_0_0_x1*sbox_0_0_y1 + sbox_0_0_x1,
            sbox_0_0_y0*sbox_0_0_y1 + sbox_0_0_x0*sbox_0_0_x1 + sbox_0_0_x1]
        """
        if self.type != "sbox":
            raise ValueError("component must be of a type sbox")

        S = SBox(self.description, big_endian=False)
        input_vars = [f"{self.id}_{model.input_postfix}{i}" for i in range(S.input_size())]
        output_vars = [f"{self.id}_{model.output_postfix}{i}" for i in range(S.output_size())]
        ring_R = model.ring()
        input_vars = list(map(ring_R, input_vars))
        output_vars = list(map(ring_R, output_vars))

        return S.polynomials(input_vars, output_vars)

    def get_ddt_with_undisturbed_transitions(self):
        """
        Returns a list of all truncated input/outputs tuples that have undisturbed differential bits (see [CZZ2023]_)

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: present_sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
            sage: sbox_component = Sbox(0, 2, ['input'], [[0, 1, 2, 3]], 4, present_sbox)
            sage: valid_transitions = sbox_component.get_ddt_with_undisturbed_transitions()
            sage: len(valid_transitions)
            81
            sage: valid_transitions[:5]
            [((0, 0, 0, 0), (0, 0, 0, 0)),
            ((0, 0, 0, 1), (2, 2, 2, 1)),
            ((0, 0, 1, 0), (2, 2, 2, 2)),
            ((0, 0, 1, 1), (2, 2, 2, 2)),
            ((0, 1, 0, 0), (2, 2, 2, 2))]

            sage: ascon_sbox = [
            ....:     0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02,
            ....:     0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06, 0x1c,
            ....:     0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18,
            ....:     0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a, 0x0f, 0x17
            ....: ]
            sage: sbox_component = Sbox(0, 3, ['input'], [[0, 1, 2, 3, 4]], 5, ascon_sbox)
            sage: valid_transitions = sbox_component.get_ddt_with_undisturbed_transitions()
            sage: len(valid_transitions)
            243
        """

        sbox = SBox(self.description, big_endian=False)
        n = sbox.input_size()
        ddt = sbox.difference_distribution_table()

        valid_points = []
        fixed_inputs_with_undisturbed_bits = []

        all_fixed_inputs = list(product([0, 1], repeat=n))
        all_combinations_of_inputs_with_undisturbed_bits = {}

        for input_bits in all_fixed_inputs:
            delta_in = int("".join(map(str, input_bits)), 2)
            has_undisturbed_bits, output_bits = _get_truncated_output_difference(ddt[delta_in], n)
            if has_undisturbed_bits:
                fixed_inputs_with_undisturbed_bits.append(input_bits)
                all_combinations_of_inputs_with_undisturbed_bits[str(input_bits)] = output_bits
            valid_points.append((input_bits, tuple(output_bits)))

        tested_inputs = all_fixed_inputs[:]
        inputs_to_combine = fixed_inputs_with_undisturbed_bits[:]

        while len(inputs_to_combine) != 0:
            newly_combined_inputs = []
            for input_1, input_2 in combinations(inputs_to_combine, 2):
                truncated_positions = list(map(xor, input_1, input_2))
                combined_input = tuple(_combine_truncated(input_1, input_2))
                output_1 = all_combinations_of_inputs_with_undisturbed_bits[str(input_1)]
                output_2 = all_combinations_of_inputs_with_undisturbed_bits[str(input_2)]
                combined_output = _combine_truncated(output_1, output_2)
                if sum(truncated_positions) == 1 and combined_output != [2] * n:
                    all_combinations_of_inputs_with_undisturbed_bits[str(combined_input)] = combined_output
                    newly_combined_inputs.append(combined_input)
                else:
                    combined_output = [2] * n
                if combined_input not in tested_inputs:
                    tested_inputs.append(combined_input)
                    valid_points.append((combined_input, tuple(combined_output)))
            inputs_to_combine = newly_combined_inputs

        for input_bits in set(list(product([0, 1, 2], repeat=n))).difference(set(tested_inputs)):
            valid_points.append((input_bits, (2,) * n))

        return valid_points

    def cms_constraints(self):
        """
        Return a list of variables and a list of clauses for S-BOX in CMS CIPHER model.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: present_sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
            sage: sbox_component = Sbox(0, 2, ['xor_0_0'], [[4, 5, 6, 7]], 4, present_sbox)
            sage: sbox_component.cms_constraints()
            (['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3'],
             ['xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0',
              'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1',
              ...
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'])
        """
        return self.sat_constraints()

    def cms_xor_differential_propagation_constraints(self, model):
        return self.sat_xor_differential_propagation_constraints(model)

    def cms_xor_linear_mask_propagation_constraints(self, model):
        return self.sat_xor_linear_mask_propagation_constraints(model)

    def cp_constraints(self, sbox_mant, second=False):
        """
        Return lists of declarations and constraints for SBOX component for CP CIPHER model.

        INPUT:

        - ``sbox_mant`` -- **list of objects**; the list of the S-boxes already encountered so that there is no need to calculate the constraints again

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox = [12, 10, 13, 3, 14, 11, 15, 7, 8, 9, 1, 5, 0, 2, 4, 6]
            sage: sbox_component = Sbox(0, 5, ['xor_0_1'], [[4, 5, 6, 7]], 4, sbox)
            sage: sbox_component.cp_constraints([])
            (['array [1..16, 1..8] of int: table_sbox_0_5 = array2d(1..16, 1..8, [0,0,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,0,1,1,1,0,0,1,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,1,0,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,1,1,1,1,0,1,1,0]);'],
             ['constraint table([xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]++[sbox_0_5[0]]++[sbox_0_5[1]]++[sbox_0_5[2]]++[sbox_0_5[3]], table_sbox_0_5);'])
        """
        sbox = self.description
        if second:
            sec_output_id_link = f"second_{self.id}"
        else:
            sec_output_id_link = self.id
        already_in = False
        output_id_link_sost = sec_output_id_link
        for mant in sbox_mant:
            if sbox == mant[0] and ((not second) or (second and "second" in mant[1])):
                already_in = True
                output_id_link_sost = mant[1]
        cp_declarations = []
        input_size = self.input_bit_size
        output_size = self.output_bit_size
        if not already_in:
            bin_i = (",".join(f"{i:0{input_size}b}") for i in range(2**input_size))
            bin_sbox = (",".join(f"{sbox[i]:0{output_size}b}") for i in range(2**input_size))
            table_values = ",".join([f"{i},{s}" for i, s in zip(bin_i, bin_sbox)])
            sbox_declaration = (
                f"array [1..{len(sbox)}, 1..{input_size + output_size}] of int: "
                f"table_{output_id_link_sost} = array2d(1..{len(sbox)}, 1..{input_size + output_size}, "
                f"[{table_values}]);"
            )
            cp_declarations.append(sbox_declaration)
            sbox_mant.append((sbox, self.id))
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"[{id_link}[{position}]]" for position in bit_positions])
        table_input = "++".join(all_inputs)
        table_output = "++".join([f"[{self.id}[{i}]]" for i in range(output_size)])
        cp_constraints = [f"constraint table({table_input}++{table_output}, table_{output_id_link_sost});"]

        return cp_declarations, cp_constraints

    def cp_deterministic_truncated_xor_differential_constraints(self, sbox_mant, inverse=False):
        """
        Return lists of declarations and constraints for SBOX component for CP deterministic truncated xor differential.

        INPUT:

        - ``inverse`` -- **boolean** (default: `False`)

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox = [1, 2, 3, 4, 0, 7, 6, 5]
            sage: sbox_component = Sbox(0, 1, ['xor_0_0'], [[0, 1, 2, 3]], 4, sbox)
            sage: declarations, constraints, sbox_mant = sbox_component.cp_deterministic_truncated_xor_differential_constraints(sbox_mant = [])
            sage: declarations
            ['array [1..27, 1..6] of int: table_sbox_0_1 = array2d(1..27, 1..6, [0,0,0,0,0,0,0,0,1,2,1,1,0,1,0,2,1,0,0,1,1,2,0,1,1,0,0,2,0,1,1,0,1,2,1,0,1,1,0,2,1,1,1,1,1,1,0,0,0,0,2,2,2,2,0,2,0,2,2,0,0,2,2,2,2,2,2,0,0,2,0,2,2,0,2,2,2,2,2,2,0,2,2,2,2,2,2,2,2,2,0,2,1,2,2,1,2,0,1,2,1,2,2,2,1,2,2,2,0,1,2,2,2,2,2,1,0,2,1,2,2,1,2,2,2,2,2,1,1,2,0,2,1,0,2,2,2,2,1,2,0,2,2,1,1,2,2,2,2,2,1,2,1,2,2,0,1,1,2,2,2,2]);']
            sage: constraints
            ['constraint table([xor_0_0[0]]++[xor_0_0[1]]++[xor_0_0[2]]++[xor_0_0[3]]++[sbox_0_1[0]]++[sbox_0_1[1]]++[sbox_0_1[2]]++[sbox_0_1[3]], table_sbox_0_1);']
            sage: sbox_mant
            [['0,0,0,0,0,0,0,0,1,2,1,1,0,1,0,2,1,0,0,1,1,2,0,1,1,0,0,2,0,1,1,0,1,2,1,0,1,1,0,2,1,1,1,1,1,1,0,0,0,0,2,2,2,2,0,2,0,2,2,0,0,2,2,2,2,2,2,0,0,2,0,2,2,0,2,2,2,2,2,2,0,2,2,2,2,2,2,2,2,2,0,2,1,2,2,1,2,0,1,2,1,2,2,2,1,2,2,2,0,1,2,2,2,2,2,1,0,2,1,2,2,1,2,2,2,2,2,1,1,2,0,2,1,0,2,2,2,2,1,2,0,2,2,1,1,2,2,2,2,2,1,2,1,2,2,0,1,1,2,2,2,2',
            'sbox_0_1']]
        """
        output_id_link = self.id
        if inverse:
            inv_output_id_link = f"inverse_{self.id}"
        else:
            inv_output_id_link = self.id
        all_inputs = []
        eventual_undisturbed_bits = self.get_ddt_with_undisturbed_transitions()
        num_pairs = len(eventual_undisturbed_bits)
        len_input = len(eventual_undisturbed_bits[0][0])
        len_output = len(eventual_undisturbed_bits[0][1])
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"[{id_link}[{position}]]" for position in bit_positions])
        table_input = "++".join(all_inputs)
        table_output = "++".join([f"[{output_id_link}[{i}]]" for i in range(self.output_bit_size)])

        already_in, output_id_link_sost, undisturbed_table_bits = (
            _mzn_update_sbox_mant_for_deterministic_truncated_xor_differential(
                inv_output_id_link, eventual_undisturbed_bits, sbox_mant, inverse
            )
        )

        cp_declarations = []
        cp_constraints = []
        if not already_in:
            undisturbed_declaration = (
                f"array [1..{num_pairs}, 1..{len_input + len_output}] of int: "
                f"table_{output_id_link_sost} = array2d(1..{num_pairs}, 1..{len_input + len_output}, "
                f"[{undisturbed_table_bits}]);"
            )
            cp_declarations.append(undisturbed_declaration)
        new_constraint = f"constraint table({table_input}++{table_output}, table_{output_id_link_sost});"
        cp_constraints.append(new_constraint)

        return cp_declarations, cp_constraints, sbox_mant

    def cp_deterministic_truncated_xor_differential_trail_constraints(self, sbox_mant, inverse=False):
        return self.cp_deterministic_truncated_xor_differential_constraints(sbox_mant, inverse)

    def cp_semi_deterministic_truncated_xor_differential_constraints(self, sbox_mant=None, inverse=False):
        raise NotImplementedError("Semi-deterministic CP model not supported for SBOX component yet")

    def cp_hybrid_deterministic_truncated_xor_differential_constraints(
        self, sbox_mant, inverse=False, list_of_component_number=[]
    ):
        """
        Return lists of declarations and constraints for SBOX component for CP hybrid deterministic truncated xor differential.

        INPUT:
        - ``sbox_mant`` -- **list**
        - ``inverse`` -- **boolean** (default: `False`)
        - ``list_of_component_number`` -- **list** (default: `[]`)


        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: lblock_sbox = [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5]
            sage: sbox_component = Sbox(0, 2, ['xor_0_1'], [[4, 5, 6, 7]], 4, lblock_sbox)
            sage: declarations, constraints, sbox_mant = sbox_component.cp_hybrid_deterministic_truncated_xor_differential_constraints(sbox_mant = [])
            sage: constraints
            ['constraint abstract_sbox_0_2(array1d(0..3, [xor_0_1[4]]++[xor_0_1[5]]++[xor_0_1[6]]++[xor_0_1[7]]), array1d(0..3, [sbox_0_2[0]]++[sbox_0_2[1]]++[sbox_0_2[2]]++[sbox_0_2[3]]), 0, 0);']
        """

        def _get_abstracted_predicate():
            if list_of_component_number != []:
                max_number_of_sboxes = max(len(lst) for lst in list_of_component_number.values())
                sbox_id = f"{max_number_of_sboxes * 10}*r + 10*(index+1)"
            else:
                sbox_id = "100*r + 10*(index+1)"

            sbox_declaration = f"predicate abstract_{output_id_link_sost}(array[int] of var int: x, array[int] of var int: y, int: r, int: index) =\n"

            condition1 = " /\\ ".join(f"x[{j}] == 0" for j in range(len(all_inputs)))
            outcome1 = " /\\ ".join([f"y[{j}] = 0" for j in range(output_size)])
            condition2 = " \\/ ".join([f"x[{j}] == 1" for j in range(len(all_inputs))])
            outcome2_1 = " /\\ ".join([f"y[{j}] = {sbox_id}" for j in range(output_size)])
            outcome2_2 = f"apply_{output_id_link_sost}(x, y)"
            outcome2 = f"({outcome2_1}) \\/ ({outcome2_2})"
            condition3_1 = " /\\ ".join([f"x[{j}] > 2" for j in range(len(all_inputs))])
            condition3_2 = " /\\ ".join([f"x[{j}] = x[0]" for j in range(1, len(all_inputs))])
            condition3 = f"({condition3_1}) /\\ ({condition3_2})"
            default = " /\\ ".join([f"y[{j}] = 2" for j in range(len(all_inputs))])
            sbox_declaration += (
                f"\tif ({condition1}) then ({outcome1})\n"
                f"\telseif ({condition2}) then ({outcome2})\n"
                f"\telseif ({condition3}) then ({outcome2_1})\n"
                f"\telse ({default}) endif;\n"
            )

            return sbox_declaration

        def _get_sbox_predicate():
            sbox_declaration = (
                f"predicate apply_{output_id_link_sost}(array[int] of var int: x, array[int] of var int: y) =\n"
            )
            for i, (inputs, outputs) in enumerate(undisturbed_bits):
                condition = " /\\ ".join([f"x[{j}] == {inputs[j]}" for j in range(len(all_inputs))])
                outcome = " /\\ ".join([f"y[{j}] = {outputs[j]}" for j in range(output_size)])

                if i == 0:
                    sbox_declaration += f"\tif ({condition}) then ({outcome})\n"
                else:
                    sbox_declaration += f"\telseif ({condition}) then ({outcome})\n"

            else_condition = " /\\ ".join([f"y{[j]} = 2" for j in range(output_size)])
            sbox_declaration += f"\telse ({else_condition}) endif;"
            return sbox_declaration

        if inverse:
            inv_output_id_link = "inverse_" + self.id
        else:
            inv_output_id_link = self.id
        output_size = self.output_bit_size
        all_inputs = []
        eventual_undisturbed_bits = self.get_ddt_with_undisturbed_transitions()
        undisturbed_bits = [tr for tr in eventual_undisturbed_bits if tr[1] != (2,) * self.output_bit_size]
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"[{id_link}[{position}]]" for position in bit_positions])
        table_input = "++".join(all_inputs)
        table_output = "++".join([f"[{self.id}[{i}]]" for i in range(output_size)])

        already_in, output_id_link_sost, _ = _mzn_update_sbox_mant_for_deterministic_truncated_xor_differential(
            inv_output_id_link, undisturbed_bits, sbox_mant, inverse
        )

        cp_declarations = []
        if not already_in:
            sbox_declaration = _get_sbox_predicate()
            abstract_sbox_declaration = _get_abstracted_predicate()
            cp_declarations += [sbox_declaration, abstract_sbox_declaration]
        round, id_in_round = map(int, self.id.split("_")[-2:])
        index_of_id = 0
        if list_of_component_number != []:
            index_of_id = list_of_component_number[round].index(id_in_round)
        cp_constraint = f"constraint abstract_{output_id_link_sost}(array1d(0..{len(all_inputs) - 1}, {table_input}), array1d(0..{output_size - 1}, {table_output}), {round}, {index_of_id});"
        cp_constraints = [cp_constraint]

        return cp_declarations, cp_constraints, sbox_mant

    def cp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Return lists of declarations and constraints for SBOX component for CP wordwise deterministic truncated xor differential.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox = [1, 2, 3, 4, 5, 6, 7, 0]
            sage: sbox_component = Sbox(0, 0, ['plaintext'], [[0, 1, 2]], 3, sbox)
            sage: model = type('DummyModel', (), {'word_size': 3})()
            sage: sbox_component.cp_wordwise_deterministic_truncated_xor_differential_constraints(model)
            ([], ['constraint if plaintext_value[0]==0 then sbox_0_0_active[0] = 0 else sbox_0_0_active[0] = 2 endif;'])
        """
        cp_declarations = []
        all_inputs = []
        word_size = model.word_size
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend(
                [
                    f"{id_link}_value[{bit_positions[j * word_size] // word_size}]"
                    for j in range(len(bit_positions) // word_size)
                ]
            )
        cp_constraints = []
        for i, input_ in enumerate(all_inputs):
            cp_constraints.append(
                f"constraint if {input_}==0 then {self.id}_active[{i}] = 0 else {self.id}_active[{i}] = 2 endif;"
            )

        return cp_declarations, cp_constraints

    def cp_xor_differential_first_step_constraints(self, model):
        """
        Return lists of declarations and constraints for SBOX component for the CP xor differential first step model.

        INPUT:

        - ``model`` -- **model object**; a model instance with word_size attribute

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: class DummyModel:
            ....:     word_size = 2
            ....:     def __init__(self):
            ....:         self.input_sbox = []
            ....:         self.table_of_solutions_length = 0
            sage: model = DummyModel()
            sage: sbox_component = Sbox(0, 0, ['input0'], [list(range(4))], 4, list(range(16)))
            sage: sbox_component.cp_xor_differential_first_step_constraints(model)
            (['array[0..1] of var 0..1: sbox_0_0;'],
                ['constraint sbox_0_0[0] = input0[0];',
                'constraint sbox_0_0[1] = input0[1];'])
            sage: model.input_sbox
            [('input0[0]', 1), ('input0[1]', 1)]
            sage: model.table_of_solutions_length
            4
        """
        all_inputs = []
        word_size = model.word_size
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            for j in range(len(bit_positions) // word_size):
                all_inputs.append(f"{id_link}[{bit_positions[j * word_size] // word_size}]")
                model.input_sbox.append(
                    (f"{id_link}[{bit_positions[j * word_size] // word_size}]", self.input_bit_size // word_size - 1)
                )
                model.table_of_solutions_length += self.input_bit_size // word_size
        cp_declarations = [f"array[0..{(self.output_bit_size - 1) // word_size}] of var 0..1: {self.id};"]
        cp_constraints = [f"constraint {self.id}[{i}] = {input_};" for i, input_ in enumerate(all_inputs)]

        return cp_declarations, cp_constraints

    def cp_xor_differential_propagation_first_step_constraints(self, model):
        return self.cp_xor_differential_first_step_constraints(model)

    def cp_xor_differential_propagation_constraints(self, model, inverse=False):
        """
        Return lists of declarations and constraints for the probability of SBOX component for CP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance
        - ``inverse`` -- **boolean** (default: `False`); used to model components in the impossible xor differential model

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['plaintext'], [[0, 1, 2]], 3, [0, 1, 2, 3, 4, 5, 6, 7])
            sage: cp = type('DummyModel', (), {})()
            sage: cp.sbox_mant = []
            sage: cp.component_and_probability = {}
            sage: cp.c = 0
            sage: cp_decl, cp_constr = sbox_component.cp_xor_differential_propagation_constraints(cp)[0:2]
            sage: cp_constr
            ['constraint table([plaintext[0]]++[plaintext[1]]++[plaintext[2]]++[sbox_0_0[0]]++[sbox_0_0[1]]++[sbox_0_0[2]]++[p[0]], DDT_sbox_0_0);']
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        description = self.description
        sbox = SBox(description)
        already_in = False
        if inverse:
            output_id_link_sost = f"inverse_{self.id}"
        else:
            output_id_link_sost = self.id
        for mant in model.sbox_mant:
            if description == mant[0] and ((not inverse) or (inverse and "inverse" in mant[1])):
                already_in = True
                output_id_link_sost = mant[1]
        cp_declarations = []
        if not already_in:
            sbox_ddt = sbox.difference_distribution_table()
            dim_ddt = len([i for i in sbox_ddt.list() if i])
            ddt_entries = []
            for i in range(sbox_ddt.nrows()):
                for j in range(sbox_ddt.ncols()):
                    if sbox_ddt[i][j]:
                        sep_bin_i = ",".join(f"{i:0{input_size}b}")
                        sep_bin_j = ",".join(f"{j:0{output_size}b}")
                        log_of_prob = round(100 * math.log2((2**input_size) / sbox_ddt[i][j]))
                        ddt_entries.append(f"{sep_bin_i},{sep_bin_j},{log_of_prob}")
            ddt_values = ",".join(ddt_entries)
            sbox_declaration = (
                f"array [1..{dim_ddt}, 1..{input_size + output_size + 1}] of int: "
                f"DDT_{output_id_link_sost} = array2d(1..{dim_ddt}, 1..{input_size + output_size + 1}, "
                f"[{ddt_values}]);"
            )
            cp_declarations.append(sbox_declaration)
            model.sbox_mant.append((description, self.id))
        all_inputs = []
        for id_link, bit_positions in zip(self.input_id_links, self.input_bit_positions):
            all_inputs.extend([f"[{id_link}[{position}]]" for position in bit_positions])
        table_input = "++".join(all_inputs)
        table_output = "++".join([f"[{self.id}[{i}]]" for i in range(output_size)])
        constraint = f"constraint table({table_input}++{table_output}++[p[{model.c}]], DDT_{output_id_link_sost});"
        cp_constraints = [constraint]
        model.component_and_probability[self.id] = model.c
        model.c += 1

        return cp_declarations, cp_constraints

    def cp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of declarations and constraints for the probability of SBOX component for CP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['plaintext'], [[0, 1, 2]], 3, [0, 1, 2, 3, 4, 5, 6, 7])
            sage: cp = type('DummyModel', (), {})()
            sage: cp.sbox_mant = []
            sage: cp.component_and_probability = {}
            sage: cp.c = 0
            sage: cp_decl, cp_constr = sbox_component.cp_xor_linear_mask_propagation_constraints(cp)[0:2]
            sage: cp_constr
            ['constraint table([sbox_0_0_i[0]]++[sbox_0_0_i[1]]++[sbox_0_0_i[2]]++[sbox_0_0_o[0]]++[sbox_0_0_o[1]]++[sbox_0_0_o[2]]++[p[0]],LAT_sbox_0_0);']
        """
        input_size = int(self.input_bit_size)
        output_size = int(self.output_bit_size)
        output_id_link = self.id
        description = self.description
        sbox = SBox(description)
        cp_declarations = []
        cp_constraints = []
        already_in = 0
        output_id_link_sost = output_id_link
        sbox_mant = model.sbox_mant
        for i in range(len(sbox_mant)):
            if description == sbox_mant[i][0]:
                already_in = 1
                output_id_link_sost = sbox_mant[i][1]
        if already_in == 0:
            size = 0
            sbox_lat = sbox.linear_approximation_table()
            sbox_declaration = "["
            for i in range(sbox_lat.nrows()):
                for j in range(sbox_lat.ncols()):
                    sep_bin_i = ",".join(f"{i:0{input_size}b}")
                    sep_bin_j = ",".join(f"{j:0{output_size}b}")
                    if sbox_lat[i, j] != 0:
                        size += 1
                        bias = round(100 * math.log2(abs(pow(2, input_size - 1) / sbox_lat[i, j])))
                        sbox_declaration = sbox_declaration + f"{sep_bin_i},{sep_bin_j},{bias},"
            pre_declaration = (
                f"array [1..{size},1..{input_size + output_size + 1}] of int: "
                f"LAT_{output_id_link}=array2d(1..{size},1..{input_size + output_size + 1},"
            )
            sbox_declaration = pre_declaration + sbox_declaration[:-1] + "]);"
            cp_declarations.append(sbox_declaration)
            sbox_mant.append((description, output_id_link))
        cp_declarations.append(f"array[0..{input_size - 1}] of var 0..1: {output_id_link}_i;")
        cp_declarations.append(f"array[0..{output_size - 1}] of var 0..1: {output_id_link}_o;")
        new_constraint = "constraint table("
        for i in range(input_size):
            new_constraint = new_constraint + f"[{output_id_link}_i[{i}]]++"
        for i in range(output_size):
            new_constraint = new_constraint + f"[{output_id_link}_o[{i}]]++"
        new_constraint = new_constraint + f"[p[{model.c}]],LAT_{output_id_link_sost});"
        cp_constraints.append(new_constraint)
        model.component_and_probability[output_id_link] = model.c
        model.c = model.c + 1

        return cp_declarations, cp_constraints

    def generate_sbox_sign_lat(self):
        """
        Build the sign matrix of the S-box linear approximation table (LAT).

        INPUT:

        - None

        OUTPUT:

        - ``list`` -- square matrix with entries in ``{-1, 0, 1}``, where non-zero values are the sign of LAT entries

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['input'], [[0, 1]], 2, [0, 1, 3, 2])
            sage: sign_lat = sbox_component.generate_sbox_sign_lat()
            sage: sign_lat
            [[1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0], [0, 1, 0, 0]]
        """
        input_size = pow(2, self.input_bit_size)
        output_size = pow(2, self.output_bit_size)
        description = self.description
        sbox = SBox(description)
        sbox_lat = sbox.linear_approximation_table()
        sbox_sign_lat = [[0 for _ in range(input_size)] for _ in range(output_size)]
        for i in range(input_size):
            for j in range(output_size):
                if sbox_lat[i][j] != 0:
                    sbox_sign_lat[i][j] = sbox_lat[i][j] / (abs(sbox_lat[i][j]))

        return sbox_sign_lat

    def get_bit_based_c_code(self, verbosity):
        """
        Return C code lines implementing this S-box at bit level.

        INPUT:

        - ``verbosity`` -- **boolean**; when ``True``, include value-printing code

        OUTPUT:

        - ``list`` -- C source-code lines for selection, substitution, optional printing, and cleanup

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['input'], [[0, 1]], 2, [0, 1, 3, 2])
            sage: code = sbox_component.get_bit_based_c_code(False)
            sage: code
            ['\tinput_id = (BitString*[]) {input};\n\tinput_positions = (uint16_t*[]) {',
            '\t\t(uint16_t[]) {2, 0, 1},',
            '\t};',
            '\tinput = select_bits(1, input_id, input_positions, 2);',
            '\tsubstitution_list = (uint64_t[]) {0, 1, 3, 2};',
            '\tBitString* sbox_0_0 = SBOX(input, 2, substitution_list);\n',
            '\tdelete_bitstring(input);\n']
        """
        sbox_code = []
        self.select_bits(sbox_code)

        sbox_code.append(f"\tsubstitution_list = (uint64_t[]) {{{', '.join([str(x) for x in self.description])}}};")
        sbox_code.append(f"\tBitString* {self.id} = SBOX(input, {self.output_bit_size}, substitution_list);\n")

        if verbosity:
            self.print_values(sbox_code)

        free_input(sbox_code)

        return sbox_code

    def get_bit_based_vectorized_python_code(self, params, convert_output_to_bytes):
        """
        Return vectorized Python code lines for bit-based S-box evaluation.

        INPUT:

        - ``params`` -- code-generation parameter placeholder (kept for API compatibility)
        - ``convert_output_to_bytes`` -- **boolean**; code-generation flag (kept for API compatibility)

        OUTPUT:

        - ``list`` -- Python source-code lines implementing bit-vector S-box evaluation

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['x'], [[0, 1]], 2, [0, 1, 3, 2])
            sage: code = sbox_component.get_bit_based_vectorized_python_code(None, False)
            sage: code
            ['  sbox_0_0 = bit_vector_SBOX(bit_vector_CONCAT([bit_vector_select_word(x,  [0, 1]) ]), np.array([0, 1, 3, 2], dtype=np.uint8), output_bit_size = 2)']
        """
        sbox_params = [
            f"bit_vector_select_word({self.input_id_links[i]},  {self.input_bit_positions[i]})"
            for i in range(len(self.input_id_links))
        ]
        return [
            f"  {self.id} = bit_vector_SBOX(bit_vector_CONCAT([{','.join(sbox_params)} ]), "
            f"np.array({self.description}, dtype=np.uint8), output_bit_size = {self.output_bit_size})"
        ]

    def get_byte_based_vectorized_python_code(self, params):
        """
        Return vectorized Python code lines for byte-based S-box evaluation.

        INPUT:

        - ``params`` -- expression passed to ``byte_vector_SBOX``

        OUTPUT:

        - ``list`` -- Python source-code lines implementing byte-vector S-box evaluation

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['x'], [[0, 1]], 2, [0, 1, 3, 2])
            sage: sbox_component.get_byte_based_vectorized_python_code('state')
            ['  sbox_0_0 = byte_vector_SBOX(state, [0, 1, 3, 2], 2)']
        """
        return [f"  {self.id} = byte_vector_SBOX({params}, {self.description}, {self.input_bit_size})"]

    def get_word_based_c_code(self, verbosity, word_size, wordstring_variables):
        """
        Return word-based C code lines for this S-box component.

        INPUT:

        - ``verbosity`` -- **boolean**; verbosity flag (currently unused)
        - ``word_size`` -- **integer**; target word size (currently unused)
        - ``wordstring_variables`` -- code-generation context (currently unused)

        OUTPUT:

        - ``list`` -- placeholder C code lines (word-based implementation is not yet available)

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox_component = Sbox(0, 0, ['x'], [[0, 1]], 2, [0, 1, 3, 2])
            sage: sbox_component.get_word_based_c_code(False, 8, {})
            ['\t//// TODO']
        """
        # TODO: consider the option for sbox
        return ["\t//// TODO"]

    def milp_large_xor_differential_probability_constraints(
        self, binary_variable, integer_variable, non_linear_component_id, weight_precision=MILP_DEFAULT_WEIGHT_PRECISION
    ):
        """
        Return lists of variables and constrains modeling SBOX component, with input bit size less or equal to 6.

        .. NOTE::

        This is for MILP large xor differential probability. Constraints extracted from [ASTTY2017]_.

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **boolean MIPVariable object**
        - ``non_linear_component_id`` -- **string**
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` where ``variables`` is a list of MILP variables and ``constraints`` is a list of MILP constraints

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: from claasp.cipher_modules.models.milp.utils.generate_inequalities_for_large_sboxes import delete_dictionary_that_contains_inequalities_for_large_sboxes
            sage: delete_dictionary_that_contains_inequalities_for_large_sboxes()
            sage: variables, constraints = sbox_component.milp_large_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            sage: variables
            [('x[plaintext_0]', x_0),
             ('x[plaintext_1]', x_1),
             ('x[plaintext_2]', x_2),
             ('x[sbox_0_0_0]', x_3),
             ('x[sbox_0_0_1]', x_4),
             ('x[sbox_0_0_2]', x_5)]
            sage: constraints[:3]
            [x_0 + x_1 + x_2 <= 3*x_6, 1 - x_0 - x_1 - x_2 <= 3 - 3*x_6, x_3 <= x_6]

        """

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        sbox_input_size, sbox_output_size = sbox.input_size(), sbox.output_size()
        update_dictionary_that_contains_inequalities_for_large_sboxes(sbox, analysis="differential")
        dict_product_of_sum = get_dictionary_that_contains_inequalities_for_large_sboxes(analysis="differential")

        constraints = milp_set_constraints_from_dictionnary_for_large_sbox(
            component_id,
            input_vars,
            output_vars,
            sbox_input_size,
            sbox_output_size,
            x,
            p,
            dict_product_of_sum[str(sbox)],
            analysis="differential",
            weight_precision=weight_precision,
        )

        return variables, constraints

    def milp_large_xor_linear_probability_constraints(
        self, binary_variable, integer_variable, non_linear_component_id, weight_precision=MILP_DEFAULT_WEIGHT_PRECISION
    ):
        """
        Return lists of variables and constrains modeling SBOX component, with input bit size less or equal to 6.

        .. NOTE::

        This is for MILP large xor linear probability. Constraints extracted from [ASTTY2017]_.

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **integer MIPVariable object**
        - ``non_linear_component_id`` -- **string**
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` where ``variables`` is a list of MILP variables and ``constraints`` is a list of MILP constraints

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_large_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            sage: variables
            [('x[sbox_0_0_0_i]', x_0),
            ('x[sbox_0_0_1_i]', x_1),
            ('x[sbox_0_0_2_i]', x_2),
            ('x[sbox_0_0_0_o]', x_3),
            ('x[sbox_0_0_1_o]', x_4),
            ('x[sbox_0_0_2_o]', x_5)]
            sage: constraints
            [x_0 + x_1 + x_2 <= 3*x_6,
            1 - x_0 - x_1 - x_2 <= 3 - 3*x_6,
            x_3 <= x_6,
            x_4 <= x_6,
            x_5 <= x_6,
            x_6 == 0,
            x_7 == 0]
        """

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        sbox_input_size, sbox_output_size = sbox.input_size(), sbox.output_size()
        update_dictionary_that_contains_inequalities_for_large_sboxes(sbox, analysis="linear")
        dict_product_of_sum = get_dictionary_that_contains_inequalities_for_large_sboxes(analysis="linear")

        constraints = milp_set_constraints_from_dictionnary_for_large_sbox(
            component_id,
            input_vars,
            output_vars,
            sbox_input_size,
            sbox_output_size,
            x,
            p,
            dict_product_of_sum[str(sbox)],
            analysis="linear",
            weight_precision=weight_precision,
        )

        return variables, constraints

    def milp_small_xor_differential_probability_constraints(
        self, binary_variable, integer_variable, non_linear_component_id, weight_precision=MILP_DEFAULT_WEIGHT_PRECISION
    ):
        """
        Return a list of variables and a list of constrains modeling a component of type SBOX.

        NOTE::

        This is for MILP small xor differential probability. Constraints extracted from
        [SHW+2014]_ and [ASTTY2017]_.

        INPUT:

        - ``binary_variable`` -- **boolean MIPVariable object**
        - ``integer_variable`` -- **integer MIPVariable object**
        - ``non_linear_component_id`` -- **string**
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` where ``variables`` is a list of MILP variables and ``constraints`` is a list of MILP constraints

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_small_xor_differential_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            sage: variables
            [('x[plaintext_0]', x_0),
             ('x[plaintext_1]', x_1),
             ('x[plaintext_2]', x_2),
             ('x[sbox_0_0_0]', x_3),
             ('x[sbox_0_0_1]', x_4),
             ('x[sbox_0_0_2]', x_5)]
            sage: constraints[:3]
            [x_6 <= x_0 + x_1 + x_2, x_0 <= x_6, x_1 <= x_6]
            sage: constraints[-1]
            x_8 == 0
        """

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        non_linear_component_id.append(self.id)
        sbox = SBox(self.description)
        update_dictionary_that_contains_inequalities_for_small_sboxes(sbox, analysis="differential")
        dictio = get_dictionary_that_contains_inequalities_for_small_sboxes(analysis="differential")
        dict_inequalities = dictio[f"{sbox}"]
        input_size, output_size = self.input_bit_size, self.output_bit_size

        # condition to know if sbox is active or not
        constraints.append(x[f"{self.id}_active"] <= sum(x[input_vars[i]] for i in range(input_size)))
        for i in range(input_size):
            constraints.append(x[f"{self.id}_active"] >= x[input_vars[i]])
        for i in range(output_size):
            constraints.append(x[f"{self.id}_active"] >= x[output_vars[i]])
        # mip.add_constraint(sum(x[output_vars[i]] for i in range(sbox.input_size())) >= x[id + "_active"])

        M = (10**weight_precision) * max(input_size, output_size)
        dict_constraints = {}
        for proba in dict_inequalities:
            dict_constraints[proba] = []
            for ineq in dict_inequalities[proba]:
                dict_constraints[proba].append(
                    sum(x[input_vars[i]] * ineq[i + 1] for i in range(len(input_vars)))
                    + sum(x[output_vars[i]] * ineq[i + 1 + len(input_vars)] for i in range(len(output_vars)))
                    + ineq[0]
                    + M * (1 - x[f"{self.id}_proba_{proba}"])
                    >= 0
                )

        for proba in dict_constraints:
            constraints.extend(dict_constraints[proba])

        constraints.append(sum(x[f"{self.id}_proba_{proba}"] for proba in dict_constraints) == x[f"{self.id}_active"])
        constraints.append(
            p[f"{self.id}_probability"]
            == (10**weight_precision)
            * sum(
                x[f"{self.id}_proba_{proba}"] * (-log(proba / 2 ** sbox.input_size(), 2)) for proba in dict_constraints
            )
        )

        return variables, constraints

    def milp_small_xor_linear_probability_constraints(
        self, binary_variable, integer_variable, non_linear_component_id, weight_precision=MILP_DEFAULT_WEIGHT_PRECISION
    ):
        """
        Return a list of variables and a list of constrains modeling a component of type Sbox.

        .. NOTE::

        This is for MILP small xor linear probability. Constraints extracted from
        [SHW+2014]_ (Appendix A) and [ASTTY2017]_.

        INPUT:

        - ``binary_variable`` -- **MIPVariable object**
        - ``integer_variable`` -- **MIPVariable object**
        - ``non_linear_component_id`` -- **list**
        - ``weight_precision`` -- **integer** (default: `2`); the number of decimals to use when rounding the weight of the trail.

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` where ``variables`` is a list of MILP variables and ``constraints`` is a list of MILP constraints

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_model import MilpModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_small_xor_linear_probability_constraints(milp.binary_variable, milp.integer_variable, milp._non_linear_component_id)
            sage: variables
            [('x[sbox_0_0_0_i]', x_0),
             ('x[sbox_0_0_1_i]', x_1),
             ('x[sbox_0_0_2_i]', x_2),
             ('x[sbox_0_0_0_o]', x_3),
             ('x[sbox_0_0_1_o]', x_4),
             ('x[sbox_0_0_2_o]', x_5)]
            sage: constraints[:3]
            [x_6 <= x_3 + x_4 + x_5, x_0 <= x_6, x_1 <= x_6]
            sage: constraints[-1]
            x_8 == 0
        """

        x = binary_variable
        p = integer_variable
        input_vars, output_vars = self._get_independent_input_output_variables()
        variables = [(f"x[{var}]", x[var]) for var in input_vars + output_vars]
        constraints = []
        component_id = self.id
        non_linear_component_id.append(component_id)
        sbox = SBox(self.description)
        update_dictionary_that_contains_inequalities_for_small_sboxes(sbox, analysis="linear")
        dictio = get_dictionary_that_contains_inequalities_for_small_sboxes(analysis="linear")
        dict_inequalities = dictio[f"{sbox}"]
        input_size = self.input_bit_size
        output_size = self.output_bit_size

        # condition to know if sbox is active or not
        # from https://eprint.iacr.org/2014/747.pdf (Appendix A)
        constraints.append(x[f"{component_id}_active"] <= sum(x[output_vars[i]] for i in range(output_size)))
        for i in range(input_size):
            constraints.append(x[f"{component_id}_active"] >= x[input_vars[i]])
        for i in range(output_size):
            constraints.append(x[f"{component_id}_active"] >= x[output_vars[i]])

        # Big-M Reformulation method as used in 4.1 of
        # https://tosc.iacr.org/index.php/ToSC/article/view/805/759
        M = (10**weight_precision) * max(input_size, output_size)
        dict_constraints = {}
        for proba in dict_inequalities:
            dict_constraints[proba] = []
            for ineq in dict_inequalities[proba]:
                dict_constraints[proba].append(
                    sum(x[input_vars[i]] * ineq[i + 1] for i in range(len(input_vars)))
                    + sum(x[output_vars[i]] * ineq[i + 1 + len(input_vars)] for i in range(len(output_vars)))
                    + ineq[0]
                    + M * (1 - x[f"{component_id}_proba_{proba}"])
                    >= 0
                )

        for proba in dict_constraints:
            constraints.extend(dict_constraints[proba])

        constraints.append(
            sum(x[f"{component_id}_proba_{proba}"] for proba in dict_constraints) == x[f"{component_id}_active"]
        )

        # correlation[i,j] =  2p[i,j] - 1, where p[i,j] = LAT[i,j] / 2^n + 1/2
        constraints.append(
            p[f"{component_id}_probability"]
            == (10**weight_precision)
            * sum(
                x[f"{component_id}_proba_{proba}"] * (log((2 ** (sbox.input_size() - 1)) / abs(proba), 2))
                for proba in dict_constraints
            )
        )

        return variables, constraints

    def milp_xor_differential_propagation_constraints(self, model):
        """
        Return list of variables and constrains modeling a component of type SBOX for MILP xor differential probability.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` from the selected MILP xor differential formulation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_differential_model import MilpXorDifferentialModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_xor_differential_propagation_constraints(milp)
            sage: variables
            [('x[plaintext_0]', x_0),
             ('x[plaintext_1]', x_1),
             ('x[plaintext_2]', x_2),
             ('x[sbox_0_0_0]', x_3),
             ('x[sbox_0_0_1]', x_4),
             ('x[sbox_0_0_2]', x_5)]
            sage: constraints[:3]
            [x_0 + x_1 + x_2 <= 3*x_6, 1 - x_0 - x_1 - x_2 <= 3 - 3*x_6, x_3 <= x_6]
            sage: constraints[-1]
            x_7 == 0
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        non_linear_component_id = model.non_linear_component_id
        weight_precision = model.weight_precision
        variables, constraints = self.milp_large_xor_differential_probability_constraints(
            binary_variable, integer_variable, non_linear_component_id, weight_precision
        )

        return variables, constraints

    def milp_xor_linear_mask_propagation_constraints(self, model):
        """
        Return lists of variables and constraints for the probability of the SBOX component for the MILP xor linear model.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` from the selected MILP xor linear formulation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_xor_linear_model import MilpXorLinearModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpXorLinearModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_xor_linear_mask_propagation_constraints(milp)
            sage: variables
            [('x[sbox_0_0_0_i]', x_0),
             ('x[sbox_0_0_1_i]', x_1),
             ('x[sbox_0_0_2_i]', x_2),
             ('x[sbox_0_0_0_o]', x_3),
             ('x[sbox_0_0_1_o]', x_4),
             ('x[sbox_0_0_2_o]', x_5)]
            sage: constraints[:3]
            [x_0 + x_1 + x_2 <= 3*x_6, 1 - x_0 - x_1 - x_2 <= 3 - 3*x_6, x_3 <= x_6]
            sage: constraints[-1]
            x_7 == 0
        """
        binary_variable = model.binary_variable
        integer_variable = model.integer_variable
        non_linear_component_id = model.non_linear_component_id
        weight_precision = model.weight_precision
        variables, constraints = self.milp_large_xor_linear_probability_constraints(
            binary_variable, integer_variable, non_linear_component_id, weight_precision
        )
        return variables, constraints

    def milp_wordwise_branch_number_number_of_active_sboxes_constraints(self, model):
        w = model._word_variable
        output_ids = self._milp_wordwise_branch_number_active_sboxes_output_ids(model)
        input_ids = model._resolved_input_word_ids(self)
        if len(input_ids) != 1 or len(output_ids) != 1:
            raise NotImplementedError(f"{self.id}: S-box input/output size does not match the word size")

        return [w[output_ids[0]] == w[input_ids[0]]]

    def milp_wordwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Models the wordwise Sbox component according to Model 4 from [SGWW2020]_

        The valid set for the input output pair (x, y) is {(0, 0), (1, 2), (2, 2), (3, 3)}

        6 inequalities can enforce these transitions. They can either be computer using
        Sage with the Polyhedron class:

            sage: valid_points = [[0,0,0,0], [0,1,1,0],[1,0,1,0],[1,1,1,1]]
            sage: from sage.geometry.polyhedron.constructor import Polyhedron
            sage: poly = Polyhedron(vertices=valid_points)
            sage: for inequality in poly.Hrepresentation():
            ....:    print(f'{inequality.repr_pretty()}')
            x0 + x1 - x2 - x3 == 0
            x3 >= 0
            x0 - x3 >= 0
            x1 - x3 >= 0
            -x0 - x1 + x3 >= -1

        or using espresso

        INPUTS:

        - ``component`` -- *dict*, the sbox component in Graph Representation
          of an SPN cipher

        .. NOTE::

        This formulation currently supports only S-boxes whose input and output sizes match
        ``model.word_size`` exactly, so the component corresponds to one input word and one
        output word. If the S-box width is not word-aligned, this method raises ``ValueError``.

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` where ``variables`` are MILP class-bit variables and ``constraints`` enforce valid wordwise transitions

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: cipher = SboxCipher(bit_size=4)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x[plaintext_word_0_class_bit_0]', x_0),
             ('x[plaintext_word_0_class_bit_1]', x_1),
             ('x[sbox_0_0_word_0_class_bit_0]', x_2),
             ('x[sbox_0_0_word_0_class_bit_1]', x_3)]
            sage: constraints
            [x_0 + x_1 <= 1 + x_3,
             x_2 <= x_0 + x_1,
             x_3 <= x_0,
             x_3 <= x_1,
             x_1 <= x_2,
             x_0 <= x_2]
            sage: cipher = SboxCipher(bit_size=3)
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: sbox_component.milp_wordwise_deterministic_truncated_xor_differential_constraints(milp)
            Traceback (most recent call last):
            ...
            ValueError: sbox_0_0 wordwise MILP constraints require input and output sizes to match model.word_size (4); got input_size=3 and output_size=3.
        """
        if self.input_bit_size != model.word_size or self.output_bit_size != model.word_size:
            raise ValueError(
                f"{self.id} wordwise MILP constraints require input and output sizes to match "
                f"model.word_size ({model.word_size}); got input_size={self.input_bit_size} "
                f"and output_size={self.output_bit_size}."
            )

        x = model.binary_variable

        input_class_tuple, output_class_tuple = self._get_wordwise_input_output_linked_class_tuples(model)

        variables = [
            (f"x[{var_elt}]", x[var_elt])
            for var_tuple in input_class_tuple + output_class_tuple
            for var_elt in var_tuple
        ]

        input_vars = [x[i] for _ in input_class_tuple for i in _]
        output_vars = [x[i] for _ in output_class_tuple for i in _]

        constraints = [
            1 + output_vars[1] >= input_vars[0] + input_vars[1],
            input_vars[0] + input_vars[1] >= output_vars[0],
            input_vars[0] >= output_vars[1],
            input_vars[1] >= output_vars[1],
            output_vars[0] >= input_vars[1],
            output_vars[0] >= input_vars[0],
        ]

        return variables, constraints

    def milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(self, model):
        """
        Models the wordwise Sbox component according to a simplified version of Model 4 from [SGWW2020]_

        The valid set for the input output pair (x, y) is {(0, 0), (1, 2), (2, 2), (3, 3)}

        if dX = 1
            then dY = 2
        else
            dY = dX

        INPUTS:

        - ``component`` -- *dict*, the sbox component in Graph Representation
          of an SPN cipher

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` for the simplified wordwise deterministic truncated model

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: cipher = SboxCipher(bit_size=3)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_wordwise_deterministic_truncated_xor_differential_model import MilpWordwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpWordwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_wordwise_deterministic_truncated_xor_differential_simple_constraints(milp)
            sage: variables
            [('x_class[plaintext_word_0_class]', x_0)]
            sage: constraints
            []

        """
        x_class = model.trunc_wordvar

        constraints = []
        input_class, output_class = self._get_wordwise_input_output_linked_class(model)
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_class + output_class]

        big_m = model._model.get_max(x_class) + 1

        for input, output in zip(input_class, output_class):
            var_if, if_constraints = milp_utils.milp_eq(model, x_class[input], 1, big_m)
            then_constraints = [x_class[output] == 2]
            else_constraints = [x_class[input] == x_class[output]]
            constraints.extend(
                if_constraints + milp_utils.milp_if_then_else(var_if, then_constraints, else_constraints, big_m)
            )

        return variables, constraints

    def milp_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Models the wordwise Sbox component.

        INPUTS:

        - ``component`` -- *dict*, the sbox component in Graph Representation
          of an SPN cipher

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` for bitwise deterministic truncated propagation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: cipher = SboxCipher(bit_size=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x_class[plaintext_0]', x_0),
            ('x_class[plaintext_1]', x_1),
            ('x_class[sbox_0_0_0]', x_2),
            ('x_class[sbox_0_0_1]', x_3)]
            sage: constraints
            [x_0 + x_1 <= 4 - 4*x_4,
            1 - 4*x_4 <= x_0 + x_1,
            x_2 <= 2 - 2*x_4,
            0 <= 2 + x_2 - 2*x_4,
            x_3 <= 2 - 2*x_4,
            0 <= 2 + x_3 - 2*x_4,
            x_2 <= 2 + 2*x_4,
            2 <= x_2 + 2*x_4,
            x_3 <= 2 + 2*x_4,
            2 <= x_3 + 2*x_4]
        """
        x_class = model.trunc_binvar

        input_class_vars, output_class_vars = self._get_input_output_variables()
        variables = [(f"x_class[{var}]", x_class[var]) for var in input_class_vars + output_class_vars]
        constraints = []

        input_sum = sum(x_class[input] for input in input_class_vars)
        # if sum(x_class[input]) <= 0 (i.e. all x_class[input] == 0)
        d_leq, c_leq = milp_utils.milp_leq(model, input_sum, 0, 2 * len(input_class_vars))
        constraints += c_leq
        # then all outputs are 0's, else they are all 2's
        constraints += milp_utils.milp_if_then_else(
            d_leq, [x_class[_] == 0 for _ in output_class_vars], [x_class[_] == 2 for _ in output_class_vars], 2
        )

        return variables, constraints

    def milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints(self, model):
        """
        Models the wordwise Sbox component, with added undisturbed bits information, as mentioned in [CZZ2023]_

        INPUTS:

        - ``component`` -- *dict*, the sbox component in Graph Representation
          of an SPN cipher

        OUTPUT:

        - ``tuple`` -- ``(variables, constraints)`` including undisturbed-bit inequalities

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: cipher = SboxCipher(bit_size=2)
            sage: from claasp.cipher_modules.models.milp.milp_models.milp_bitwise_deterministic_truncated_xor_differential_model import MilpBitwiseDeterministicTruncatedXorDifferentialModel
            sage: milp = MilpBitwiseDeterministicTruncatedXorDifferentialModel(cipher)
            sage: milp.init_model_in_sage_milp_class()
            sage: sbox_component = cipher.component_from(0, 0)
            sage: variables, constraints = sbox_component.milp_undisturbed_bits_bitwise_deterministic_truncated_xor_differential_constraints(milp)
            sage: variables
            [('x[plaintext_0_class_bit_0]', x_0),
            ('x[plaintext_0_class_bit_1]', x_1),
            ('x[plaintext_1_class_bit_0]', x_2),
            ('x[plaintext_1_class_bit_1]', x_3),
            ('x[sbox_0_0_0_class_bit_0]', x_4),
            ('x[sbox_0_0_0_class_bit_1]', x_5),
            ('x[sbox_0_0_1_class_bit_0]', x_6),
            ('x[sbox_0_0_1_class_bit_1]', x_7)]
            sage: constraints
            [x_8 == 2*x_0 + x_1,
            x_9 == 2*x_2 + x_3,
            x_10 == 2*x_4 + x_5,
            x_11 == 2*x_6 + x_7,
            1 <= 2 - x_1 - x_4,
            1 <= 1 + x_0 - x_4,
            1 <= 2 - x_2 - x_3,
            1 <= 1 - x_0 + x_4,
            1 <= 2 - x_0 - x_5,
            1 <= 2 - x_2 - x_3,
            1 <= 1 - x_1 + x_5,
            1 <= 1 + x_1 - x_5,
            1 <= 2 - x_3 - x_6,
            1 <= 1 + x_2 - x_6,
            1 <= 2 - x_0 - x_1,
            1 <= 1 - x_2 + x_6,
            1 <= 2 - x_2 - x_7,
            1 <= 2 - x_0 - x_1,
            1 <= 1 - x_3 + x_7,
            1 <= 1 + x_3 - x_7]
        """

        x = model.binary_variable
        sbox = SBox(self.description)
        output_bit_size = self.output_bit_size
        input_id_tuples, output_id_tuples = self._get_input_output_variables_tuples()
        input_ids, output_ids = self._get_input_output_variables()

        linking_constraints = model.link_binary_tuples_to_integer_variables(
            input_id_tuples + output_id_tuples, input_ids + output_ids
        )

        variables = [
            (f"x[{var_elt}]", x[var_elt]) for var_tuple in input_id_tuples + output_id_tuples for var_elt in var_tuple
        ]
        constraints = [] + linking_constraints

        input_vars = [tuple(x[i] for i in _) for _ in input_id_tuples]
        output_vars = [tuple(x[i] for i in _) for _ in output_id_tuples]

        valid_points = self.get_ddt_with_undisturbed_transitions()
        update_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits(sbox, valid_points)
        dict_product_of_sum = get_dictionary_that_contains_inequalities_for_sboxes_with_undisturbed_bits()

        for position in range(output_bit_size):
            for bit in range(2):
                espresso_inequalities = dict_product_of_sum[str(sbox)][position][bit]
                all_vars = [_ for sublist in input_vars for _ in sublist] + [output_vars[position][bit]]
                minimized_constraints = espresso_pos_to_constraints(espresso_inequalities, all_vars)
                constraints.extend(minimized_constraints)

        return variables, constraints

    def sat_constraints(self):
        """
        Return a list of variables and a list of clauses representing S-BOX for SAT CIPHER model

        The underlying logic is: for every (input, output) pair of the S-boxes build the implication
        ``(i0, i1, ..., in) -> oj`` for every bit in the binary representation of the output. The ``i``s
        vector is the binary representation of the input. Note that this is the same logic of the method
        ``cnf()`` in ``sage.crypto.sbox.SBox`` class.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - None

        OUTPUT:

        - ``tuple`` -- ``(output_bit_ids, constraints)`` with SAT output variable names and CNF clauses

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: present_sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
            sage: sbox_component = Sbox(0, 2, ['xor_0_0'], [[4, 5, 6, 7]], 4, present_sbox)
            sage: sbox_component.sat_constraints()
            (['sbox_0_2_0', 'sbox_0_2_1', 'sbox_0_2_2', 'sbox_0_2_3'],
             ['xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_0',
              'xor_0_0_4 xor_0_0_5 xor_0_0_6 xor_0_0_7 sbox_0_2_1',
              ...
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_1',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 sbox_0_2_2',
              '-xor_0_0_4 -xor_0_0_5 -xor_0_0_6 -xor_0_0_7 -sbox_0_2_3'])
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        sbox_outputs = self.description
        constraints = []
        for sbox_input, sbox_output in enumerate(sbox_outputs):
            input_signs = ("-" * (sbox_input >> j & 1) for j in reversed(range(self.input_bit_size)))
            current_input_bit_ids = (f"{sign}{bit_id}" for sign, bit_id in zip(input_signs, input_bit_ids))
            output_signs = ("-" * ((sbox_output >> j & 1) ^ 1) for j in reversed(range(self.output_bit_size)))
            current_output_bit_ids = (f"{sign}{bit_id}" for sign, bit_id in zip(output_signs, output_bit_ids))
            input_constraint = " ".join(current_input_bit_ids)
            current_constraints = (f"{input_constraint} {bit_id}" for bit_id in current_output_bit_ids)
            constraints.extend(current_constraints)

        return output_bit_ids, constraints

    def sat_bitwise_deterministic_truncated_xor_differential_constraints(self):
        """
        Return a list of variables and a list of clauses representing S-BOX for SAT DETERMINISTIC TRUNCATED XOR DIFFERENTIAL model

        This method implements the undisturbed bits idea from [CZZ2023]_.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - ``tuple`` -- ``(output_ids, constraints)`` with SAT double-output identifiers and CNF clauses

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: present_sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
            sage: sbox_component = Sbox(0, 2, ['xor_0_0'], [[4, 5, 6, 7]], 4, present_sbox)
            sage: sbox_component.sat_bitwise_deterministic_truncated_xor_differential_constraints()
            (['sbox_0_2_0_0',
              'sbox_0_2_1_0',
              ...
              'sbox_0_2_2_1',
              'sbox_0_2_3_1'],
             ['-xor_0_0_4_1 -xor_0_0_7_1 sbox_0_2_3_0 -sbox_0_2_3_1',
              '-xor_0_0_4_1 sbox_0_2_2_0',
              ...
              '-xor_0_0_5_0 sbox_0_2_3_0',
              '-xor_0_0_4_0 sbox_0_2_3_0'])
        """
        valid_transitions = self.get_ddt_with_undisturbed_transitions()
        # building espresso input and run it
        espresso_input_length = 2 * (len(valid_transitions[0][0]) + len(valid_transitions[0][1]))
        espresso_input = [f".i {espresso_input_length}", ".o 1"]
        for transition in valid_transitions:
            espresso_condition = ["0" * (value == 0 or value == 1) + "1" * (value == 2) for value in transition[0]]
            espresso_condition += [
                "0" * (value == 0) + "1" * (value == 1) + "-" * (value == 2) for value in transition[0]
            ]
            espresso_condition += ["0" * (value == 0 or value == 1) + "1" * (value == 2) for value in transition[1]]
            espresso_condition += [
                "0" * (value == 0) + "1" * (value == 1) + "-" * (value == 2) for value in transition[1]
            ]
            espresso_input += ["".join(espresso_condition) + " 1"]
        espresso_input += [".e"]
        espresso_input = "\n".join(espresso_input)
        espresso_process = subprocess.run(["espresso", "-epos"], input=espresso_input, capture_output=True, text=True)
        espresso_output = espresso_process.stdout.splitlines()
        # building constraints
        input_ids_0, input_ids_1 = self._generate_input_double_ids()
        output_ids_0, output_ids_1 = self._generate_output_double_ids()
        input_ids = input_ids_0 + input_ids_1
        output_ids = output_ids_0 + output_ids_1
        ids = input_ids + output_ids
        constraints = []
        for line in espresso_output[4:-1]:
            literals = ["-" * int(line[i]) + ids[i] for i in range(espresso_input_length) if line[i] != "-"]
            constraints.append(" ".join(literals))

        return output_ids, constraints

    def sat_xor_differential_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing S-BOX for SAT XOR DIFFERENTIAL model

        The DDT is encoded in CNF using the following method: for every ``(input_difference, output_difference)`` pair,
        we compute the ``weight``, i.e. the ``-log2(p)``. Then every tuple ``(input_difference, output_difference, weight)``
        will be the minterm of the Sum Of Products (SOP) form of the DDT. Note that both ``input_difference`` and
        ``output_difference`` are binary representation, instead weight has unary representation.

        The SOP is then processed by Espresso and the resulting form is the CNF of the DDT. This approach is the same
        contained in [SW2023]_.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - ``tuple`` -- ``(output_and_hw_ids, constraints)`` for SAT xor differential propagation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: sbox_component = cipher.component_from(0, 0)
            sage: sat = SatModel(cipher)
            sage: output_ids, clauses = sbox_component.sat_xor_differential_propagation_constraints(sat)
            sage: output_ids
            ['sbox_0_0_0',
            'sbox_0_0_1',
            'sbox_0_0_2',
            'hw_sbox_0_0_0',
            'hw_sbox_0_0_1',
            'hw_sbox_0_0_2']
            sage: clauses
            ['-plaintext_2 sbox_0_0_2',
            'plaintext_2 -sbox_0_0_2',
            '-plaintext_1 sbox_0_0_1',
            'plaintext_1 -sbox_0_0_1',
            '-plaintext_0 sbox_0_0_0',
            'plaintext_0 -sbox_0_0_0',
            '-hw_sbox_0_0_2',
            '-hw_sbox_0_0_1',
            '-hw_sbox_0_0_0']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f"hw_{output_bit_id}" for output_bit_id in output_bit_ids]
        sbox_values = self.description

        # if optimized SAT DDT template is not initialized in instance fields, compute it
        if f"{sbox_values}" not in self.sboxes_ddt_templates:
            ddt = SBox(sbox_values).difference_distribution_table()

            check_table_feasibility(ddt, "DDT", "SAT")

            get_hamming_weight_function = lambda input_bit_len, entry: input_bit_len - int(math.log2(entry))
            template = sat_build_table_template(ddt, get_hamming_weight_function, self.input_bit_size, self.output_bit_size)
            self.sboxes_ddt_templates[f"{sbox_values}"] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = self.sboxes_ddt_templates[f"{sbox_values}"]
        constraints = []
        for clause in template:
            literals = ["-" * value[0] + bit_ids[value[1]] for value in clause]
            constraints.append(" ".join(literals))

        return output_bit_ids + hw_bit_ids, constraints

    def sat_xor_linear_mask_propagation_constraints(self, model=None):
        """
        Return a list of variables and a list of clauses representing S-BOX for SAT XOR LINEAR model

        The approach used here is very similar to the one in :meth:`SBOX.sat_xor_differential_propagation_constraints`.
        The only difference is that we encode here the absolute value of the correlation instead of weight.

        The SOP is then processed by Espresso and the resulting form is the CNF of the DDT. This approach is the same
        contained in [SW2023]_.

        .. SEEALSO::

            :ref:`sat-standard` for the format.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.sat.sat_model import SatModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: sbox_component = cipher.component_from(0, 0)
            sage: sat = SatModel(cipher)
            sage: bit_ids, clauses = sbox_component.sat_xor_linear_mask_propagation_constraints(sat)
            sage: bit_ids
            ['sbox_0_0_0_i',
            'sbox_0_0_1_i',
            'sbox_0_0_2_i',
            'sbox_0_0_0_o',
            'sbox_0_0_1_o',
            'sbox_0_0_2_o',
            'hw_sbox_0_0_0_o',
            'hw_sbox_0_0_1_o',
            'hw_sbox_0_0_2_o']
            sage: clauses
            ['-sbox_0_0_2_i sbox_0_0_2_o',
            'sbox_0_0_2_i -sbox_0_0_2_o',
            '-sbox_0_0_1_i sbox_0_0_1_o',
            'sbox_0_0_1_i -sbox_0_0_1_o',
            '-sbox_0_0_0_i sbox_0_0_0_o',
            'sbox_0_0_0_i -sbox_0_0_0_o',
            '-hw_sbox_0_0_2_o',
            '-hw_sbox_0_0_1_o',
            '-hw_sbox_0_0_0_o']
        """
        input_bit_ids = self._generate_component_input_ids()
        output_bit_ids = self._generate_output_ids(suffix=constants.OUTPUT_BIT_ID_SUFFIX)
        hw_bit_ids = [f"hw_{output_bit_id}" for output_bit_id in output_bit_ids]
        sbox_values = self.description

        # if optimized SAT LAT template is not initialized in instance fields, compute it
        if f"{sbox_values}" not in self.sboxes_lat_templates:
            lat = SBox(sbox_values).linear_approximation_table()

            check_table_feasibility(lat, "LAT", "SAT")

            get_hamming_weight_function = lambda input_bit_len, entry: input_bit_len - int(math.log2(abs(entry))) - 1
            template = sat_build_table_template(lat, get_hamming_weight_function, self.input_bit_size, self.output_bit_size)
            self.sboxes_lat_templates[f"{sbox_values}"] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = self.sboxes_lat_templates[f"{sbox_values}"]
        constraints = []
        for clause in template:
            literals = ["-" * value[0] + bit_ids[value[1]] for value in clause]
            constraints.append(" ".join(literals))

        return bit_ids, constraints

    def smt_constraints(self):
        """
        Return a variable list and SMT-LIB list asserts representing S-BOX for SMT CIPHER model

        The approach used here is very similar to the one in :meth:`SBOX.sat_constraints`.
        The only difference is in the consequent, that is here the whole representation of the output value.

        INPUT:

        - None

        OUTPUT:

        - ``tuple`` -- ``(output_bit_ids, constraints)`` with SMT output identifiers and assertion strings

        EXAMPLES::

            sage: from claasp.components.sbox_component import Sbox
            sage: sbox = [1, 2, 3, 0]
            sage: component = Sbox(0, 1, ['input'], [[0, 1]], 2, sbox)
            sage: output_ids, asserts = component.smt_constraints()
            sage: output_ids
            ['sbox_0_1_0', 'sbox_0_1_1']
            sage: asserts
            ['(assert (=> (and (not input_0) (not input_1)) (and (not sbox_0_1_0) sbox_0_1_1)))',
            '(assert (=> (and (not input_0) input_1) (and sbox_0_1_0 (not sbox_0_1_1))))',
            '(assert (=> (and input_0 (not input_1)) (and sbox_0_1_0 sbox_0_1_1)))',
            '(assert (=> (and input_0 input_1) (and (not sbox_0_1_0) (not sbox_0_1_1))))']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        sbox = self.description
        constraints = []
        for in_value, out_value in enumerate(sbox):
            bits = map(int, f"{in_value:0{self.input_bit_size}b}")
            input_literals = [
                input_bit_id if bit else smt_utils.smt_not(input_bit_id)
                for input_bit_id, bit in zip(input_bit_ids, bits)
            ]
            input_difference = smt_utils.smt_and(input_literals)
            bits = map(int, f"{out_value:0{self.input_bit_size}b}")
            output_literals = [
                output_bit_id if bit else smt_utils.smt_not(output_bit_id)
                for output_bit_id, bit in zip(output_bit_ids, bits)
            ]
            output_difference = smt_utils.smt_and(output_literals)
            implication = smt_utils.smt_implies(input_difference, output_difference)
            constraints.append(smt_utils.smt_assert(implication))

        return output_bit_ids, constraints

    def smt_xor_differential_propagation_constraints(self, model):
        """
        Return a variable list and SMT-LIB list asserts representing S-BOX for SMT XOR DIFFERENTIAL model

        The approach is described in detail in :meth:`SBOX.sat_xor_differential_propagation_constraints`.

        INPUT:

        - ``model`` -- **model object**; a model instance

        OUTPUT:

        - ``tuple`` -- ``(output_and_hw_ids, constraints)`` for SMT xor differential propagation

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: cipher = SboxCipher(bit_size=3)
            sage: smt = SmtModel(cipher)
            sage: sbox_component = cipher.component_from(0, 0)
            sage: output_ids, asserts = sbox_component.smt_xor_differential_propagation_constraints(smt)
            sage: output_ids
            ['sbox_0_0_0',
             'sbox_0_0_1',
             'sbox_0_0_2',
             'hw_sbox_0_0_0',
             'hw_sbox_0_0_1',
             'hw_sbox_0_0_2']
            sage: asserts
            ['(assert (or (not plaintext_2) sbox_0_0_2))',
             '(assert (or plaintext_2 (not sbox_0_0_2)))',
             '(assert (or (not plaintext_1) sbox_0_0_1))',
             '(assert (or plaintext_1 (not sbox_0_0_1)))',
             '(assert (or (not plaintext_0) sbox_0_0_0))',
             '(assert (or plaintext_0 (not sbox_0_0_0)))',
             '(assert (or (not hw_sbox_0_0_2)))',
             '(assert (or (not hw_sbox_0_0_1)))',
             '(assert (or (not hw_sbox_0_0_0)))']
        """
        input_bit_ids = self._generate_input_ids()
        output_bit_ids = self._generate_output_ids()
        hw_bit_ids = [f"hw_{output_bit_id}" for output_bit_id in output_bit_ids]
        sbox_values = self.description
        sboxes_ddt_templates = model.sboxes_ddt_templates

        # if optimized DDT template is not initialized in instance fields, compute it
        if f"{sbox_values}" not in sboxes_ddt_templates:
            ddt = SBox(sbox_values).difference_distribution_table()

            check_table_feasibility(ddt, "DDT", "SMT")

            get_hamming_weight_function = lambda input_bit_len, entry: input_bit_len - int(math.log2(entry))
            template = smt_build_table_template(ddt, get_hamming_weight_function, self.input_bit_size, self.output_bit_size)
            sboxes_ddt_templates[f"{sbox_values}"] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_ddt_templates[f"{sbox_values}"]
        constraints = smt_get_sbox_probability_constraints(bit_ids, template)

        return output_bit_ids + hw_bit_ids, constraints

    def smt_xor_linear_mask_propagation_constraints(self, model):
        """
        Return a variable list and SMT-LIB list asserts representing S-BOX for SMT XOR LINEAR model

        The approach is described in detail in :meth:`SBOX.sat_xor_linear_mask_propagation_constraints`.

        INPUT:

        - ``model`` -- **model object**; a model instance

        EXAMPLES::

            sage: from claasp.ciphers.single_component_ciphers.sbox_cipher import SboxCipher
            sage: from claasp.cipher_modules.models.smt.smt_model import SmtModel
            sage: cipher = SboxCipher(bit_size=2)
            sage: sbox_component = cipher.component_from(0, 0)
            sage: smt = SmtModel(cipher)
            sage: bit_ids, asserts = sbox_component.smt_xor_linear_mask_propagation_constraints(smt)
            sage: bit_ids
            ['sbox_0_0_0_i',
             'sbox_0_0_1_i',
             'sbox_0_0_0_o',
             'sbox_0_0_1_o',
             'hw_sbox_0_0_0_o',
             'hw_sbox_0_0_1_o']
            sage: asserts
            ['(assert (or (not sbox_0_0_1_i) sbox_0_0_1_o))',
             '(assert (or sbox_0_0_1_i (not sbox_0_0_1_o)))',
             '(assert (or (not sbox_0_0_0_i) sbox_0_0_0_o))',
             '(assert (or sbox_0_0_0_i (not sbox_0_0_0_o)))',
             '(assert (or (not hw_sbox_0_0_1_o)))',
             '(assert (or (not hw_sbox_0_0_0_o)))']
        """
        input_bit_ids = self._generate_component_input_ids()
        output_bit_ids = self._generate_output_ids(suffix=constants.OUTPUT_BIT_ID_SUFFIX)
        hw_bit_ids = [f"hw_{output_bit_id}" for output_bit_id in output_bit_ids]
        sbox_values = self.description
        sboxes_lat_templates = model.sboxes_lat_templates

        # if optimized LAT template is not initialized in instance fields, compute it
        if f"{sbox_values}" not in sboxes_lat_templates:
            lat = SBox(sbox_values).linear_approximation_table()

            check_table_feasibility(lat, "LAT", "SMT")

            get_hamming_weight_function = lambda input_bit_len, entry: input_bit_len - int(math.log2(abs(entry))) - 1
            template = smt_build_table_template(lat, get_hamming_weight_function, self.input_bit_size, self.output_bit_size)
            sboxes_lat_templates[f"{sbox_values}"] = template

        bit_ids = input_bit_ids + output_bit_ids + hw_bit_ids
        template = sboxes_lat_templates[f"{sbox_values}"]
        constraints = smt_get_sbox_probability_constraints(bit_ids, template)

        return bit_ids, constraints
