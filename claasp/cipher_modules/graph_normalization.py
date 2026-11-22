# Copyright 2026 Technology Innovation Institute
# SPDX-License-Identifier: GPL-3.0-or-later
"""Value-preserving graph normalization for binary-operation model backends."""
from copy import deepcopy
from claasp.components.modadd_component import ModAdd
from claasp.name_mappings import WORD_OPERATION


def _binary_sum_components(component, round_number, next_index):
    width = component.output_bit_size
    wires = [(name, bit) for name, positions in zip(component.input_id_links, component.input_bit_positions)
             for bit in positions]
    if len(wires) != component.description[1] * width:
        raise ValueError("Modular addition input width disagrees with its operand count")
    modulus = component.description[2]
    if modulus not in (None, 1 << width):
        raise NotImplementedError("Binary normalization supports only word-size power-of-two modulus")
    accumulator = wires[:width]
    result = []
    for offset in range(width, len(wires), width):
        pair = accumulator + wires[offset:offset + width]
        addition = ModAdd(round_number, next_index + len(result),
                         [name for name, _ in pair], [[bit] for _, bit in pair], width, modulus)
        result.append(addition)
        accumulator = [(addition.id, bit) for bit in range(width)]
    # Preserve every existing downstream reference and public endpoint identifier.
    result[-1].id = component.id
    return result


def binary_modadd_copy(cipher):
    """Copy a graph, replacing multioperand word additions by binary chains.

    The identity is addition modulo 2^w associativity. This transformation
    preserves the function, input order, round boundaries and existing output
    identifiers. It allocates fresh intermediate identifiers within each round.
    It does not mutate ``cipher``. Nonstandard moduli are rejected if an addition
    needs splitting. Binary additions and other operations retain their wiring.

    INPUT: ``cipher`` -- a CLAASP graph, possibly containing additions with
    more than two width-sized operands, including fragmented or repeated wires.

    OUTPUT: a deep copied ``Cipher`` usable by two-operand backends. Differential
    arm scores on the resulting chain remain the backend's modeling objective;
    associativity alone does not justify multiplying independent probabilities.
    Exact four-execution checks still use the actual values of the whole graph.

    EXAMPLES::

        sage: from claasp.ciphers.single_component_ciphers.modadd_cipher import ModaddCipher
        sage: from claasp.cipher_modules.graph_normalization import binary_modadd_copy
        sage: original = ModaddCipher(word_bit_size=2, number_of_inputs=3)
        sage: normalized = binary_modadd_copy(original)
        sage: original.evaluate([1] * len(original.inputs)) == normalized.evaluate([1] * len(normalized.inputs))
        True
    """
    result = deepcopy(cipher)
    for number, round_ in enumerate(result.rounds_as_list):
        next_index = max((int(c.id.rsplit("_", 1)[1]) for c in round_.components), default=-1) + 1
        components = []
        for component in round_.components:
            if (component.type == WORD_OPERATION and component.description[0] == "MODADD"
                    and component.description[1] > 2):
                additions = _binary_sum_components(component, number, next_index)
                next_index += len(additions)
                components.extend(additions)
            else:
                components.append(component)
        round_.components[:] = components
    result.rounds._invalidate_indexes()
    return result
