"""Cached, indexed read-only view of a cipher, plus the low-level component/bit lookups
used by the inversion engine. Extracted from inverse_cipher.py (behaviour unchanged).
"""

import weakref
from copy import copy

from claasp.component import Component
from claasp.input import Input
from claasp.name_mappings import INPUT_KEY


class _CipherView:
    """Cached, indexed read-only view of a cipher used by the inversion engine.

    The component list (plus the synthetic ``cipher_input`` components) and its indexes are
    built once; previously every ``component_from_id`` / ``get_output_components`` call
    rebuilt the whole list, making the traversal O(n^2). The cipher is not mutated during
    inversion, so the view is cached per cipher object (weakly, to avoid leaks).
    """

    __slots__ = ("components", "by_id", "consumers")

    def __init__(self, cipher):
        components = cipher.get_all_components()
        for component in components:
            setattr(component, "round", int(component.id.split("_")[-2]))
        for index, input_id in enumerate(cipher.inputs):
            description = [INPUT_KEY] if INPUT_KEY in input_id else [input_id]
            input_component = Component(
                input_id, "cipher_input", Input(0, [[]], [[]]), cipher.inputs_bit_size[index], description
            )
            setattr(input_component, "round", -1)
            components.append(input_component)
        self.components = components
        self.by_id = {component.id: component for component in components}
        consumers = {}
        for component in components:
            seen = set()
            for link in component.input_id_links:
                # links are component-id strings; synthetic inputs carry [[]] placeholders.
                if isinstance(link, str) and link not in seen:
                    seen.add(link)
                    consumers.setdefault(link, []).append(component)
        self.consumers = consumers


_CIPHER_VIEW_CACHE = weakref.WeakKeyDictionary()


def _cipher_view(cipher):
    view = _CIPHER_VIEW_CACHE.get(cipher)
    if view is None:
        view = _CipherView(cipher)
        _CIPHER_VIEW_CACHE[cipher] = view
    return view


def get_cipher_components(self):
    # Return a fresh shallow copy: callers (e.g. the cipher_inverse worklist) mutate the
    # returned list with .remove(). The cached view's list and indexes stay intact.
    return list(_cipher_view(self).components)


def get_all_components_with_the_same_input_id_link_and_input_bit_positions(input_id_link, input_bit_positions, self):
    cipher_components = get_cipher_components(self)
    output_list = []
    for c in cipher_components:
        for i in range(len(c.input_id_links)):
            copy_input_bit_positions = copy(input_bit_positions)
            copy_input_bit_positions.sort()
            list_to_be_compared = copy(c.input_bit_positions[i])
            list_to_be_compared.sort()
            if input_id_link == c.input_id_links[i] and all(
                ele in copy_input_bit_positions for ele in list_to_be_compared
            ):
                output_list.append(c)
                break
    return output_list


def get_output_components(component, self):
    return list(_cipher_view(self).consumers.get(component.id, []))


class AvailableBits:
    """List-like store of recovered bits with O(1) membership.

    ``available_bits`` was a plain ``list`` of ``{"component_id", "position", "type"}`` dicts,
    so every ``is_bit_contained_in`` / ``bit in available_bits`` was an O(n) linear scan over a
    list that grows with every recovered bit - O(n^2) over a full inversion, and the single
    biggest cost in profiling (e.g. 78% of a Keccak inverse). This wrapper keeps the exact list
    semantics every call site relies on (append-order, iteration, ``len``, duplicates) but also
    maintains a ``set`` of ``(component_id, position, type)`` keys so membership is O(1).
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
    return


def _are_all_bits_available(id, input_bit_positions_len, offset, available_bits):
    for j in range(input_bit_positions_len):
        bit = {"component_id": id, "position": offset + j, "type": "input"}
        if not is_bit_contained_in(bit, available_bits):
            return False
    return True


def get_available_output_components(component, available_bits, self, return_index=False):
    cipher_components = get_cipher_components(self)
    available_output_components = []
    for c in cipher_components:
        accumulator = 0
        for i in range(len(c.input_id_links)):
            if (component.id == c.input_id_links[i]) and (c not in available_output_components):
                all_bits_available = _are_all_bits_available(
                    c.id, len(c.input_bit_positions[i]), accumulator, available_bits
                )
                if all_bits_available:
                    if return_index:
                        available_output_components.append(
                            (c, list(range(accumulator, accumulator + len(c.input_bit_positions[i]))))
                        )
                    else:
                        available_output_components.append(c)
            accumulator += len(c.input_bit_positions[i])

    return available_output_components
