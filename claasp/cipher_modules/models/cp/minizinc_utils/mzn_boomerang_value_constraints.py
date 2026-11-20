# Copyright 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact four-execution constraints for the retained boomerang event.

The four forward executions share one master key (and all other non-data
inputs). Their input differences pair executions 0/1 and 2/3, and their output
differences pair 0/2 and 1/3. No inverse component model or product of local
probabilities is required. This certifies existence, not a probability.

The exact layer intersects the componentwise search space; it does not restore
switches omitted by that search space. See Cid et al., EUROCRYPT 2018,
https://doi.org/10.1007/978-3-319-78375-8_22, and Kidmose et al.,
A Formal Analysis of Boomerang Probabilities, ToSC 2022(4).
"""

from copy import deepcopy

from claasp.cipher_modules.models.cp.mzn_models.mzn_cipher_model import MznCipherModel
from claasp.name_mappings import CIPHER_OUTPUT, SBOX, WORD_OPERATION

_PAIRS = {"upper": ((0, 1), (2, 3)), "lower": ((0, 2), (1, 3))}
_NONLINEAR = ("AND", "MODADD", "MODSUB")


def _execution_constraints(cipher, execution):
    graph = deepcopy(cipher)
    graph.add_prefix(f"quartet_{execution}_")
    exact = MznCipherModel(graph)
    declarations = exact.input_declarations()
    constraints = []
    for component in graph.all_components():
        if not callable(getattr(component, "cp_constraints", None)):
            raise NotImplementedError(f"No exact CP value model for {component.id}")
        if component.type == SBOX:
            extra, equations = component.cp_constraints(exact.sbox_cache)
        else:
            extra, equations = component.cp_constraints()
        declarations.extend(extra)
        constraints.extend(equations)
    # MODSUB supplies its own output declaration as well as the graph's one.
    return list(dict.fromkeys(declarations)) + constraints


def _difference_constraints(side, name, positions):
    original = name.removeprefix(side + "_")
    return [
        f"constraint (quartet_{left}_{original}[{bit}] + "
        f"quartet_{right}_{original}[{bit}]) mod 2 = {name}[{bit}];"
        for left, right in _PAIRS[side]
        for bit in positions
    ]


def _component_inputs(component):
    return [
        (name, bit)
        for name, positions in zip(
            component.input_id_links, component.input_bit_positions
        )
        for bit in positions
    ]


def _retained_middle_bits(component, side, kind):
    """Identify actual retained bits, excluding the free BCT endpoints."""
    inputs = _component_inputs(component)
    operation = component.description[0]
    if side == "upper":
        keep_inputs = inputs
        keep_output = kind in ("ubct", "ebct")
    elif operation == "AND":
        # AND switching retains two input directions, unlike lifted addition.
        keep_inputs = inputs
        keep_output = kind in ("lbct", "ebct")
    else:
        # The second operand is the unchanged output of the triangular lift.
        keep_inputs = inputs if kind in ("lbct", "ebct") else inputs[len(inputs) // 2 :]
        keep_output = True
    result = set(keep_inputs)
    if keep_output:
        result.update((component.id, bit) for bit in range(component.output_bit_size))
    return result


def _retained_bits(model):
    result = {side: set() for side in _PAIRS}
    top = model.top_part_number_of_rounds
    end = top + model.middle_part_number_of_rounds
    for round_number, round_ in enumerate(model._cipher.rounds_as_list):
        for component in round_.components:
            side = component.id.split("_", 1)[0]
            if side not in result:
                continue
            if round_number < top or round_number >= end:
                result[side].update(
                    (component.id, bit) for bit in range(component.output_bit_size)
                )
            elif (
                component.type == WORD_OPERATION
                and component.description[0] in _NONLINEAR
            ):
                result[side].update(
                    _retained_middle_bits(
                        component, side, model._switch_kind(round_number)
                    )
                )
    return result


def build_boomerang_value_constraints(model):
    """Return exact value constraints and the endpoint variable names to export.

    INPUT:

    - ``model`` -- built ``MznHadipourBoomerangModel``. The original graph
      must describe a permutation of its first input for each fixed tuple of
      remaining inputs, with one equally sized cipher output. Every component
      must implement exact ``cp_constraints`` (including the key schedule).

    OUTPUT: ``(constraints, witness_names)``. Four complete forward graphs
    enforce shared non-data inputs and actual retained differences. Existential
    satisfiability certifies a compatible quartet within the original restricted
    local model. UNSAT rejects that modeled event, not its whole external hull.
    Unsupported components or incompatible input/output sizes raise explicitly.
    This helper does not run a solver, mutate the original graph, or write files.

    EXAMPLES::

        sage: from claasp.ciphers.block_ciphers.simon_block_cipher import SimonBlockCipher
        sage: from claasp.cipher_modules.models.cp.mzn_models.mzn_hadipour_boomerang_model import MznHadipourBoomerangModel
        sage: model = MznHadipourBoomerangModel(SimonBlockCipher(number_of_rounds=3), dict(top_part_number_of_rounds=1, middle_part_number_of_rounds=1, bottom_part_number_of_rounds=1))
        sage: model.build_hadipour_boomerang_model(weight=None)
        sage: from claasp.cipher_modules.models.cp.minizinc_utils.mzn_boomerang_value_constraints import build_boomerang_value_constraints
        sage: constraints, names = build_boomerang_value_constraints(model)
        sage: 'quartet_0_plaintext' in names
        True

    The quartet construction follows the external event of Cid et al.,
    https://doi.org/10.1007/978-3-319-78375-8_22. It makes no independence or
    Markov assumption about cipher rounds or the master-key schedule.
    """
    cipher = model.original_cipher
    outputs = [c for c in cipher.all_components() if c.type == CIPHER_OUTPUT]
    if len(outputs) != 1 or outputs[0].output_bit_size != cipher.inputs_bit_size[0]:
        raise ValueError(
            "Exact boomerang values require one output matching the first input size"
        )
    output = outputs[0]
    constraints = []
    for execution in range(4):
        constraints.extend(_execution_constraints(cipher, execution))
    for name, size in zip(cipher.inputs[1:], cipher.inputs_bit_size[1:]):
        constraints.extend(
            f"constraint quartet_{execution}_{name}[{bit}] = quartet_0_{name}[{bit}];"
            for execution in range(1, 4)
            for bit in range(size)
        )
    retained = _retained_bits(model)
    retained["upper"].update(
        ("upper_" + cipher.inputs[0], bit) for bit in range(cipher.inputs_bit_size[0])
    )
    retained["lower"].update(
        ("lower_" + output.id, bit) for bit in range(output.output_bit_size)
    )
    for side, bits in retained.items():
        for name, bit in sorted(bits):
            constraints.extend(_difference_constraints(side, name, [bit]))
    names = [
        f"quartet_{execution}_{name}"
        for execution in range(4)
        for name in cipher.inputs + [output.id]
    ]
    return constraints, names
