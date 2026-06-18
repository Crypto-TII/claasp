"""Bit-equivalence map and bit-name helpers for the inversion engine.
Extracted from inverse_cipher.py (behaviour unchanged)."""

from claasp.cipher_modules.inverse.cipher_view import get_cipher_components
from claasp.name_mappings import CIPHER_OUTPUT, INTERMEDIATE_OUTPUT


# --- Phase 3b shadow instrumentation -------------------------------------------------------
# Off-by-default measurement hook. When enabled, every adjacency query also computes the
# *transitive* answer (would the value-class/union-find model decide the same thing?) and records
# divergences, WITHOUT changing what the engine returns. This is how we measure - across real
# ciphers - whether routing the engine's direct-adjacency checks through transitive closure would
# change any decision, before committing to that switch. When disabled it is a no-op.
_SHADOW = {
    "enabled": False,
    "cipher": None,
    "calls": 0,
    "divergences": 0,
    "false_to_true": 0,  # engine said not-adjacent, closure says same-class (the case that matters)
    "true_to_false": 0,  # must stay 0: adjacency implies closure (sanity check on the BFS)
    "per_cipher": {},
    "samples": [],
    "max_samples": 60,
}


def shadow_enable(cipher_name=None):
    _SHADOW["enabled"] = True
    _SHADOW["cipher"] = cipher_name
    _SHADOW["per_cipher"].setdefault(cipher_name, {"calls": 0, "divergences": 0, "false_to_true": 0})


def shadow_set_cipher(cipher_name):
    _SHADOW["cipher"] = cipher_name
    _SHADOW["per_cipher"].setdefault(cipher_name, {"calls": 0, "divergences": 0, "false_to_true": 0})


def shadow_disable():
    _SHADOW["enabled"] = False


def shadow_report():
    return dict(_SHADOW)


def _reachable_any(start, targets, all_equivalent_bits):
    """Whether ``start`` reaches any name in ``targets`` through the equivalence map (transitive
    closure / same value class). Identity counts as reachable."""
    if start in targets:
        return True
    seen = {start}
    frontier = [start]
    while frontier:
        next_frontier = []
        for node in frontier:
            for neighbour in all_equivalent_bits.get(node, []):
                if neighbour in targets:
                    return True
                if neighbour not in seen:
                    seen.add(neighbour)
                    next_frontier.append(neighbour)
        frontier = next_frontier
    return False


def _shadow_record(bit_name, list_of_bit_names, all_equivalent_bits, engine_answer):
    targets = set(list_of_bit_names)
    transitive_answer = _reachable_any(bit_name, targets, all_equivalent_bits)
    bucket = _SHADOW["per_cipher"].setdefault(
        _SHADOW["cipher"], {"calls": 0, "divergences": 0, "false_to_true": 0}
    )
    _SHADOW["calls"] += 1
    bucket["calls"] += 1
    if transitive_answer != engine_answer:
        _SHADOW["divergences"] += 1
        bucket["divergences"] += 1
        if engine_answer is False and transitive_answer is True:
            _SHADOW["false_to_true"] += 1
            bucket["false_to_true"] += 1
        else:
            _SHADOW["true_to_false"] += 1
        if len(_SHADOW["samples"]) < _SHADOW["max_samples"]:
            _SHADOW["samples"].append(
                {
                    "cipher": _SHADOW["cipher"],
                    "bit": bit_name,
                    "engine": engine_answer,
                    "transitive": transitive_answer,
                }
            )


def is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
    engine_answer = False
    if bit_name in all_equivalent_bits:
        for name in list_of_bit_names:
            if name in all_equivalent_bits[bit_name]:
                engine_answer = True
                break
    if _SHADOW["enabled"]:
        _shadow_record(bit_name, list_of_bit_names, all_equivalent_bits, engine_answer)
    return engine_answer


def equivalent_bits_in_common(bits_of_an_output_component, component_bits, all_equivalent_bits):
    bits_in_common = []
    for bit1 in bits_of_an_output_component:
        bit_name1 = f"{bit1['component_id']}_{bit1['position']}_{bit1['type']}"
        if bit_name1 not in all_equivalent_bits.keys():
            return []
        for bit2 in component_bits:
            bit_name2 = f"{bit2['component_id']}_{bit2['position']}_{bit2['type']}"
            if bit_name2 in all_equivalent_bits[bit_name1]:
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
