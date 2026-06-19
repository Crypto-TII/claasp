"""Bit-equivalence map and bit-name helpers for the inversion engine.
Extracted from inverse_cipher.py (behaviour unchanged)."""

from claasp.cipher_modules.inverse.cipher_view import get_cipher_components
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT


# --- Equivalence read/write helpers --------------------------------------------------------
# The engine asks two questions of the equivalence relation: "are these two bits the same value?"
# and "what bits are equivalent to this one?". These named helpers give those one definition each.
# The relation is an adjacency dict kept as a union of cliques (every pair in a class linked
# directly), so direct membership already equals transitive closure.
# (A union-find replacement was prototyped and measured 15-40% slower - small classes make the
# C-level dict ``in`` beat a Python ``find()`` - so the dict stays. See inversion_gate_log.md.)


def bits_equivalent(bit_name, other_bit_name, all_equivalent_bits):
    """Whether ``other_bit_name`` is recorded as equivalent to ``bit_name`` (same value)."""
    return other_bit_name in all_equivalent_bits.get(bit_name, [])


def equivalent_bit_names(bit_name, all_equivalent_bits):
    """The bit-names recorded as equivalent to ``bit_name`` (empty list if it has none)."""
    return all_equivalent_bits.get(bit_name, [])


def add_equivalence(all_equivalent_bits, bit_a, bit_b, ensure_a=False, symmetric=True):
    """Record ``bit_b`` as the same value as ``bit_a``, extending ``bit_a``'s class to include it.

    The relation is stored as a union of cliques (every pair in a class linked directly), so this
    links ``bit_b`` to ``bit_a`` and to each of ``bit_a``'s existing members - keeping direct
    membership equal to transitive closure. This is the single *write* seam mirroring the read
    seam above; 3c will reimplement both over a union-find.

    Two flags capture the (verbatim) differences between the original inline call sites:
    ``ensure_a`` creates ``bit_a``'s entry when a site does not already guarantee it; ``symmetric``
    also appends ``bit_b`` to each existing member's own list (the readiness-evaluation site did
    this, the dynamic-output sites did not).
    """
    if ensure_a:
        all_equivalent_bits.setdefault(bit_a, [])
    all_equivalent_bits[bit_a].append(bit_b)
    all_equivalent_bits.setdefault(bit_b, [])
    all_equivalent_bits[bit_b].append(bit_a)
    for name in all_equivalent_bits[bit_a]:
        if name != bit_b:
            all_equivalent_bits[bit_b].append(name)
            if symmetric:
                all_equivalent_bits[name].append(bit_b)


def is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
    """Whether ``bit_name`` is the same value as any name in ``list_of_bit_names``."""
    return any(bits_equivalent(bit_name, name, all_equivalent_bits) for name in list_of_bit_names)


def equivalent_bits_in_common(bits_of_an_output_component, component_bits, all_equivalent_bits):
    bits_in_common = []
    for bit1 in bits_of_an_output_component:
        bit_name1 = f"{bit1['component_id']}_{bit1['position']}_{bit1['type']}"
        if bit_name1 not in all_equivalent_bits.keys():
            return []
        for bit2 in component_bits:
            bit_name2 = f"{bit2['component_id']}_{bit2['position']}_{bit2['type']}"
            if bits_equivalent(bit_name1, bit_name2, all_equivalent_bits):
                bits_in_common.append(bit1)
                break
    return bits_in_common


def get_all_bit_names(self):
    dictio = {}
    cipher_components = get_cipher_components(self)
    for c in cipher_components:
        if c.type != INTERMEDIATE_OUTPUT:
            starting_bit_position = 0
            for index, input_id_link in enumerate(c.input_id_links):
                j = 0
                for i in c.input_bit_positions[index]:
                    output_bit = {"component_id": input_id_link, "position": i, "type": "output"}
                    output_bit_name = f"{input_id_link}_{i}_output"
                    input_bit = {"component_id": c.id, "position": starting_bit_position + j, "type": "input"}
                    input_bit_name = c.id + "_" + str(starting_bit_position + j) + "_input"
                    if output_bit_name not in dictio:
                        dictio[output_bit_name] = output_bit
                    if input_bit_name not in dictio:
                        dictio[input_bit_name] = input_bit

                    if c.type != CIPHER_OUTPUT:
                        output_updated_bit = {"component_id": input_id_link, "position": i, "type": "output_updated"}
                        output_updated_bit_name = f"{input_id_link}_{i}_output_updated"
                        if output_updated_bit_name not in dictio:
                            dictio[output_updated_bit_name] = output_updated_bit
                    output_updated_bit = {
                        "component_id": c.id,
                        "position": starting_bit_position + j,
                        "type": "output_updated",
                    }
                    output_updated_bit_name = f"{c.id}_{starting_bit_position + j}_output_updated"
                    if output_updated_bit_name not in dictio:
                        dictio[output_updated_bit_name] = output_updated_bit
                    j += 1
                starting_bit_position += len(c.input_bit_positions[index])

    return dictio


def get_all_equivalent_bits(self):
    dictio = {}
    component_list = self.get_all_components()
    for c in component_list:
        current_bit_position = 0
        for index, input_id_link in enumerate(c.input_id_links):
            if c.type == "constant":
                input_bit_positions = list(range(c.output_bit_size))
            else:
                input_bit_positions = c.input_bit_positions[index]
            for i in input_bit_positions:
                output_bit_name = f"{input_id_link}_{i}_output"
                input_bit_name = f"{c.id}_{current_bit_position}_input"
                current_bit_position += 1
                if output_bit_name not in dictio:
                    dictio[output_bit_name] = []
                dictio[output_bit_name].append(input_bit_name)

    updated_dictio = {}
    for key, values in dictio.items():
        updated_dictio[key] = values
        for value in values:
            if value not in dictio:
                updated_dictio[value] = []
            updated_dictio[value].append(key)
            for other_value in values:
                if other_value != value:
                    updated_dictio[value].append(other_value)

    return updated_dictio
