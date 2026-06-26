"""Cached, indexed read-only view of a cipher, plus the low-level component/bit lookups
used by the inversion engine.
"""

import weakref

from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import CIPHER_OUTPUT, INPUT_KEY, INTERMEDIATE_OUTPUT


class _CipherView:
    """Cached, indexed read-only view of a cipher used by the inversion engine.

    The component list (plus the synthetic ``cipher_input`` components) and its indexes are built
    once. The cipher is not mutated during inversion, so the view is cached per cipher object
    (weakly, to avoid leaks).
    """

    __slots__ = ("components", "by_id", "consumer_links", "all_bit_names")

    def __init__(self, cipher):
        components = cipher.get_all_components()
        for index, input_id in enumerate(cipher.inputs):
            description = [INPUT_KEY] if INPUT_KEY in input_id else [input_id]
            input_component = Component(
                input_id, "cipher_input", Input(0, [[]], [[]]), cipher.inputs_bit_size[index], description
            )
            components.append(input_component)
        self.components = components
        self.by_id = {component.id: component for component in components}
        # consumer_links[id]   -> [(consuming component, [(offset, nbits), ...]), ...] where the
        #                         offset/nbits locate, in the consumer's input-bit space, each link
        #                         that reads `id`.
        consumer_links = {}
        for component in components:
            accumulator = 0
            per_consumed = {}
            for index, link in enumerate(component.input_id_links):
                nbits = len(component.input_bit_positions[index])
                # links are component-id strings; synthetic inputs carry [[]] placeholders.
                if isinstance(link, str):
                    per_consumed.setdefault(link, []).append((accumulator, nbits))
                accumulator += nbits
            for link, offsets in per_consumed.items():
                consumer_links.setdefault(link, []).append((component, offsets))
        self.consumer_links = consumer_links
        # all_bit_names: whole-cipher {bit_name: bit_dict} map used by get_equivalent_input_bit.
        # Built once here instead of on every call to get_all_bit_names.
        bit_names = {}
        for c in components:
            if c.type == INTERMEDIATE_OUTPUT:
                continue
            starting_bit_position = 0
            for index, input_id_link in enumerate(c.input_id_links):
                if not isinstance(input_id_link, str):
                    starting_bit_position += len(c.input_bit_positions[index])
                    continue
                for j, i in enumerate(c.input_bit_positions[index]):
                    out_name = f"{input_id_link}_{i}_output"
                    if out_name not in bit_names:
                        bit_names[out_name] = {"component_id": input_id_link, "position": i, "type": "output"}
                    in_name = f"{c.id}_{starting_bit_position + j}_input"
                    if in_name not in bit_names:
                        bit_names[in_name] = {"component_id": c.id, "position": starting_bit_position + j, "type": "input"}
                    if c.type != CIPHER_OUTPUT:
                        out_upd_name = f"{input_id_link}_{i}_output_updated"
                        if out_upd_name not in bit_names:
                            bit_names[out_upd_name] = {"component_id": input_id_link, "position": i, "type": "output_updated"}
                    out_upd_name2 = f"{c.id}_{starting_bit_position + j}_output_updated"
                    if out_upd_name2 not in bit_names:
                        bit_names[out_upd_name2] = {"component_id": c.id, "position": starting_bit_position + j, "type": "output_updated"}
                starting_bit_position += len(c.input_bit_positions[index])
        self.all_bit_names = bit_names


_CIPHER_VIEW_CACHE = weakref.WeakKeyDictionary()


def _cipher_view(cipher):
    view = _CIPHER_VIEW_CACHE.get(cipher)
    if view is None:
        view = _CipherView(cipher)
        _CIPHER_VIEW_CACHE[cipher] = view
    return view


def get_cipher_components(self):
    # Return a fresh shallow copy so callers can mutate the returned list without disturbing the
    # cached view's list and indexes.
    return list(_cipher_view(self).components)


class AvailableBits:
    """List-like store of recovered bits with O(1) membership.

    Keeps list semantics (append-order, iteration, ``len``, duplicates) and additionally maintains
    a ``set`` of ``(component_id, position, type)`` keys, so membership tests are O(1) rather than a
    linear scan over a list that grows with every recovered bit.
    """

    __slots__ = ("_list", "_keys")

    def __init__(self):
        self._list = []
        self._keys = set()

    @staticmethod
    def _key(bit):
        return (bit["component_id"], bit["position"], bit["type"])

    def append(self, bit):
        self._list.append(bit)
        self._keys.add(self._key(bit))

    def __contains__(self, bit):
        return self._key(bit) in self._keys

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)


def is_bit_contained_in(bit, available_bits):
    keys = getattr(available_bits, "_keys", None)
    if keys is not None:  # fast path for AvailableBits (O(1)); falls back for plain lists
        return (bit["component_id"], bit["position"], bit["type"]) in keys
    for b in available_bits:
        if bit["component_id"] == b["component_id"] and bit["position"] == b["position"] and bit["type"] == b["type"]:
            return True
    return False


def add_bit_to_bit_list(bit, bit_list):
    if not is_bit_contained_in(bit, bit_list):
        bit_list.append(bit)


def _are_all_bits_available(id, input_bit_positions_len, offset, available_bits):
    for j in range(input_bit_positions_len):
        bit = {"component_id": id, "position": offset + j, "type": "input"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def get_available_output_components(component, available_bits, self, return_index=False):
    # Iterate the precomputed consumer_links index (each consumer of `component` paired with the
    # (offset, nbits) of every input link that reads it). _are_all_bits_available runs per link
    # since it depends on the live available_bits. Non-index mode adds each consumer at most once
    # (first available link); index mode emits one entry per available link.
    available_output_components = []
    for c, link_offsets in _cipher_view(self).consumer_links.get(component.id, []):
        for offset, nbits in link_offsets:
            if _are_all_bits_available(c.id, nbits, offset, available_bits):
                if return_index:
                    available_output_components.append((c, list(range(offset, offset + nbits))))
                else:
                    available_output_components.append(c)
                    break

    return available_output_components
