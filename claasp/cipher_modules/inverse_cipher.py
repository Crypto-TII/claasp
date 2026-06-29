"""Cipher inversion engine.

Given a CLAASP ``Cipher``, build its inverse: a new ``Cipher`` that maps outputs back to inputs
(e.g. ciphertext + key back to plaintext). The engine walks the cipher's component graph and, for
each component, either

* **evaluates it forward**, when all of its inputs are already known, or
* **inverts it**, when its output and enough of its inputs are known.

Components are processed in repeated passes until every one has been rebuilt; a pass that makes no
progress means the cipher cannot be inverted from the information available (see
``_inversion_stall_message``). A bit-equivalence map records which bits are known to carry the same
value, so a needed operand can be sourced from any equivalent recovered bit; a cached, indexed view
of the cipher (``_CipherView``) and an O(1) recovered-bit store (``_AvailableBits``) keep the
repeated lookups cheap.

The public entry point is ``Cipher.cipher_inverse()``; the functions in this module are its
building blocks.
"""

import weakref

from sage.crypto.sbox import SBox
from sage.rings.finite_rings.finite_field_constructor import FiniteField as GF
from sage.rings.polynomial.polynomial_ring_constructor import PolynomialRing

from claasp.cipher_modules.component_analysis_tests import (
    binary_matrix_of_linear_component,
    get_inverse_matrix_in_integer_representation,
    int_to_poly,
)
from claasp.component import Component
from claasp.components import (
    cipher_output_component,
    intermediate_output_component,
    linear_layer_component,
    modsub_component,
)
from claasp.input import Input
from claasp.name_mappings import (
    CIPHER_INPUT,
    CIPHER_OUTPUT,
    CONSTANT,
    INPUT_KEY,
    INPUT_PLAINTEXT,
    INPUT_STATE,
    INPUT_TWEAK,
    INTERMEDIATE_OUTPUT,
    LINEAR_LAYER,
    MIX_COLUMN,
    PERMUTATION_COMPONENT,
    SBOX,
    WORD_OPERATION,
)

from claasp.editor import get_key_schedule_component_ids


# ===========================================================================
# Inversion-engine internals: the cached indexed cipher view,
# the recovered-bit store and low-level bit lookups, and the bit-equivalence map.
# ===========================================================================


def _build_consumer_links(components):
    """Build a map from each component id to the list of components that read from it, with the bit offset and width of each link."""
    consumer_links = {}
    for component in components:
        accumulator = 0
        per_consumed = {}
        for index, link in enumerate(component.input_id_links):
            nbits = len(component.input_bit_positions[index])
            if isinstance(link, str):  # synthetic inputs carry [[]] placeholders, not strings
                per_consumed.setdefault(link, []).append((accumulator, nbits))
            accumulator += nbits
        for link, offsets in per_consumed.items():
            consumer_links.setdefault(link, []).append((component, offsets))
    return consumer_links


def _add_bit_name_entries(bit_names, source_id, consumer_id, source_pos, consumer_pos, include_source_updated):
    """Register the output, input, and output_updated bit name entries for one wiring connection."""
    bit_names.setdefault(f"{source_id}_{source_pos}_output", {"component_id": source_id, "position": source_pos, "type": "output"})
    bit_names.setdefault(f"{consumer_id}_{consumer_pos}_input", {"component_id": consumer_id, "position": consumer_pos, "type": "input"})
    if include_source_updated:
        bit_names.setdefault(f"{source_id}_{source_pos}_output_updated", {"component_id": source_id, "position": source_pos, "type": "output_updated"})
    bit_names.setdefault(f"{consumer_id}_{consumer_pos}_output_updated", {"component_id": consumer_id, "position": consumer_pos, "type": "output_updated"})


def _build_all_bit_names(components):
    """Build a map from every bit name in the cipher to its component id, position, and type (output / input / output_updated)."""
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
                _add_bit_name_entries(bit_names, input_id_link, c.id, i, starting_bit_position + j, c.type != CIPHER_OUTPUT)
            starting_bit_position += len(c.input_bit_positions[index])
    return bit_names


class _CipherView:
    """Cached, indexed read-only view of a cipher, purpose-built for the inversion engine:

    * **Inputs as nodes.** The inverter must *process* the cipher's inputs (turn the plaintext input
      into the inverse's cipher output, keep key/tweak inputs as inputs). But a cipher stores its
      inputs as id strings + bit sizes (``cipher.inputs`` / ``cipher.inputs_bit_size``), not as
      components. So the view appends one synthetic ``cipher_input`` ``Component`` per input, letting
      the whole engine treat inputs and real components through one uniform code path.
    * **Built-once indexes.** Inversion runs many repeated passes over every component, each doing
      id lookups, successor lookups, and bit-name lookups. Recomputing those per call would be
      O(n) each and dominate the run. The view precomputes them once:

        - ``components``    -- real components + the synthetic input nodes.
        - ``by_id``        -- ``{id: component}`` including inputs (O(1) resolve of any link,
                              ``None`` on miss, unlike ``Cipher.component_from_id`` which raises and
                              omits inputs).
        - ``consumer_links`` -- ``{id: [(consumer, [(offset, nbits), ...]), ...]}``: who reads each
                              component, with the offset/width of every reading link, so
                              availability checks know exactly which input bits to test.
        - ``all_bit_names`` -- the whole-cipher ``{bit_name: bit_dict}`` map over the engine's
                              ``output`` / ``output_updated`` / ``input`` bit model, used by the
                              equivalence lookups.

    These indexes are inversion-specific (especially ``consumer_links`` offsets and the
    ``output_updated`` bit model), which is why the view lives here and is not promoted onto
    ``Cipher``. The cipher is a fixed snapshot during inversion, so the view is built once and cached
    per cipher object.
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
        self.consumer_links = _build_consumer_links(components)
        self.all_bit_names = _build_all_bit_names(components)


_CIPHER_VIEW_CACHE = weakref.WeakKeyDictionary()


def _cipher_view(cipher):
    view = _CIPHER_VIEW_CACHE.get(cipher)
    if view is None:
        view = _CipherView(cipher)
        _CIPHER_VIEW_CACHE[cipher] = view
    return view


def _cipher_view_components_with_inputs(self):
    """Return the cipher's components plus one synthetic ``cipher_input`` component per cipher input.

    Inversion-engine internal: this is the node set the inversion loop walks. Unlike
    ``Cipher.get_all_components()`` (real components only), the cipher's inputs (plaintext, key, ...)
    appear here as first-class nodes, so the engine can process them uniformly (e.g. invert the
    plaintext input into the inverse's cipher output). A fresh shallow copy is returned so callers
    can use it as a mutable worklist without disturbing the cached view.
    """
    # Return a fresh shallow copy so callers can mutate the returned list without disturbing the
    # cached view's list and indexes.
    return list(_cipher_view(self).components)


class _AvailableBits:
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


def _is_bit_contained_in(bit, available_bits):
    keys = getattr(available_bits, "_keys", None)
    if keys is not None:  # fast path for _AvailableBits (O(1)); falls back for plain lists
        return (bit["component_id"], bit["position"], bit["type"]) in keys
    for b in available_bits:
        if bit["component_id"] == b["component_id"] and bit["position"] == b["position"] and bit["type"] == b["type"]:
            return True
    return False


def _add_bit_to_bit_list(bit, bit_list):
    if not _is_bit_contained_in(bit, bit_list):
        bit_list.append(bit)


def _are_all_bits_available(id, input_bit_positions_len, offset, available_bits):
    for j in range(input_bit_positions_len):
        bit = {"component_id": id, "position": offset + j, "type": "input"}
        if not _is_bit_contained_in(bit, available_bits):
            return False
    return True


def _get_available_output_components(component, available_bits, self, return_index=False):
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


# The equivalence relation is an adjacency dict kept as a union of cliques (every pair in a class
# linked directly), so direct membership already equals transitive closure.


def _bits_equivalent(bit_name, other_bit_name, all_equivalent_bits):
    """Whether ``other_bit_name`` is recorded as equivalent to ``bit_name`` (same value)."""
    return other_bit_name in all_equivalent_bits.get(bit_name, [])


def _equivalent_bit_names(bit_name, all_equivalent_bits):
    """The bit-names recorded as equivalent to ``bit_name`` (empty list if it has none)."""
    return all_equivalent_bits.get(bit_name, [])


def _add_equivalence(all_equivalent_bits, bit_a, bit_b, ensure_a=False, symmetric=True):
    """Record ``bit_b`` as the same value as ``bit_a``, linking it into ``bit_a``'s clique.

    ``ensure_a`` creates ``bit_a``'s entry if absent; ``symmetric`` also appends ``bit_b`` to each
    existing member's list (keeping each class a fully-connected clique).
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


def _is_bit_adjacent_to_list_of_bits(bit_name, list_of_bit_names, all_equivalent_bits):
    """Whether ``bit_name`` is the same value as any name in ``list_of_bit_names``."""
    return any(_bits_equivalent(bit_name, name, all_equivalent_bits) for name in list_of_bit_names)


def _equivalent_bits_in_common(bits_of_an_output_component, component_bits, all_equivalent_bits):
    bits_in_common = []
    for bit1 in bits_of_an_output_component:
        bit_name1 = f"{bit1['component_id']}_{bit1['position']}_{bit1['type']}"
        if bit_name1 not in all_equivalent_bits:
            return []
        for bit2 in component_bits:
            bit_name2 = f"{bit2['component_id']}_{bit2['position']}_{bit2['type']}"
            if _bits_equivalent(bit_name1, bit_name2, all_equivalent_bits):
                bits_in_common.append(bit1)
                break
    return bits_in_common


def _get_all_bit_names(self):
    return _cipher_view(self).all_bit_names


def _build_forward_equivalence_edges(cipher):
    """Walk the cipher's wiring and collect, for each output bit, the list of input bits it connects to."""
    dictio = {}
    for c in cipher.get_all_components():
        current_bit_position = 0
        for index, input_id_link in enumerate(c.input_id_links):
            input_bit_positions = list(range(c.output_bit_size)) if c.type == "constant" else c.input_bit_positions[index]
            for i in input_bit_positions:
                output_bit_name = f"{input_id_link}_{i}_output"
                input_bit_name = f"{c.id}_{current_bit_position}_input"
                current_bit_position += 1
                dictio.setdefault(output_bit_name, []).append(input_bit_name)
    return dictio


def _close_forward_edge(dictio):
    """Make the one-way connection map two-way: if A connects to B, then B connects to A and to every other bit A connects to."""
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


def _get_all_equivalent_bits(self):
    """Seed the bit-equivalence map from the cipher's wiring.

    Each output bit of a link and the input bit it feeds carry the same value, so they start out
    in the same equivalence class. Returns an adjacency dict ``{bit_name: [equivalent_bit_name,
    ...]}`` (each class stored as a fully-connected clique); the engine grows it as it recovers
    more bits.
    """
    return _close_forward_edge(_build_forward_equivalence_edges(self))


def _component_input_bits(component):
    component_input_bits_list = []
    for index, link in enumerate(component.input_id_links):
        tmp = []
        for position in component.input_bit_positions[index]:
            tmp.append({"component_id": link, "position": position, "type": "output_updated"})
        component_input_bits_list.append(tmp)
    return component_input_bits_list


def _component_output_bits(component, self):
    # set of list_bits needed to invert
    output_components = self.get_successor_components(component)
    component_output_bits_list = []
    for c in output_components:
        tmp = []
        for j in range(c.output_bit_size):
            bit = {"component_id": c.id, "position": j, "type": "output_updated"}
            tmp.append(bit)
        component_output_bits_list.append(tmp)
    return component_output_bits_list


def _are_these_bits_available(bits_list, available_bits):
    return all(bit in available_bits for bit in bits_list)


def _input_bit_value_is_recovered(link, position, available_bits, all_equivalent_bits):
    """
    True if the value of input bit ``{link}[position]`` is already known in the inverse cipher,
    either directly (its own ``output_updated`` is available) or through the equivalence map (some
    other recovered component carries the same value as an available ``output_updated`` bit).

    This lets the inversion-readiness credit a known operand even when it is only reachable through
    the equivalence map (e.g. a shift-register state bit that equals a ciphertext bit, as in
    TinyJambu), rather than requiring the operand's own link to be available.
    """
    if {"component_id": link, "position": position, "type": "output_updated"} in available_bits:
        return True
    for equivalent_bit in _equivalent_bit_names(f"{link}_{position}_output", all_equivalent_bits):
        if equivalent_bit.endswith("_output_updated"):
            source_id, source_position = equivalent_bit[: -len("_output_updated")].rsplit("_", 1)
            if {"component_id": source_id, "position": int(source_position), "type": "output_updated"} in available_bits:
                return True
    return False


def _register_consumer_input_bits(component_id, consumer, available_bits):
    """Add the input bits of ``consumer`` (where it reads from ``component_id``) to ``available_bits``."""
    accumulator = 0
    for i in range(len(consumer.input_id_links)):
        if consumer.input_id_links[i] == component_id:
            for j in range(len(consumer.input_bit_positions[i])):
                component_output_bit = {"component_id": component_id, "position": j, "type": "output"}
                if _is_bit_contained_in(component_output_bit, available_bits):
                    c_input_bit = {"component_id": consumer.id, "position": accumulator + j, "type": "input"}
                    _add_bit_to_bit_list(c_input_bit, available_bits)
        accumulator += len(consumer.input_bit_positions[i])


def _update_available_bits_with_component_output_bits(component, available_bits, cipher):
    output_components = cipher.get_successor_components(component)

    for i in range(component.output_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "output"}
        _add_bit_to_bit_list(bit, available_bits)

    for c in output_components:
        _register_consumer_input_bits(component.id, c, available_bits)


def _update_available_bits_with_component_input_bits(component, available_bits):
    for i in range(component.input_bit_size):
        bit = {"component_id": component.id, "position": i, "type": "input"}
        _add_bit_to_bit_list(bit, available_bits)

    # add bits of the connected input components
    for i in range(len(component.input_id_links)):
        for j in range(len(component.input_bit_positions[i])):
            bit1 = {
                "component_id": component.input_id_links[i],
                "position": component.input_bit_positions[i][j],
                "type": "output",
            }
            _add_bit_to_bit_list(bit1, available_bits)


def _all_output_bits_available(component, available_bits):
    return all(
        _is_bit_contained_in({"component_id": component.id, "position": i, "type": "output_updated"}, available_bits)
        for i in range(component.output_bit_size)
    )


def _is_output_bits_updated_equivalent_to_input_bits(output_bits_updated_list, input_bits_list, all_equivalent_bits):
    return all(
        _is_bit_adjacent_to_list_of_bits(bit, input_bits_list, all_equivalent_bits)
        for bit in output_bits_updated_list
    )


def _input_positions_from_source(c, source_id):
    """Return the input bit positions of ``c`` that are fed by ``source_id``."""
    positions = []
    accumulator = 0
    for index, link in enumerate(c.input_id_links):
        if link == source_id:
            positions += list(range(accumulator, accumulator + len(c.input_bit_positions[index])))
        accumulator += len(c.input_bit_positions[index])
    return positions


def _find_output_position_for_input(c, input_pos, all_equivalent_bits):
    """Given that input position ``input_pos`` of ``c`` carries the target value, return the output
    position of ``c`` that carries the same value, or ``None`` if none does."""
    input_bit = f"{c.id}_{input_pos}_input"
    if c.input_bit_size == c.output_bit_size:
        if _is_bit_adjacent_to_list_of_bits(input_bit, [f"{c.id}_{input_pos}_output_updated"], all_equivalent_bits):
            return input_pos
    else:
        for j in range(c.output_bit_size):
            if _is_bit_adjacent_to_list_of_bits(input_bit, [f"{c.id}_{j}_output_updated"], all_equivalent_bits):
                return j
    return None


def _find_component_carrying_bit(output_bit_name, source_id, candidates, all_equivalent_bits):
    """Among the candidate components, find the one whose recovered output carries the same value as
    ``output_bit_name``. Returns ``(component_id, output_position)`` or ``None`` if not found."""
    for c in candidates:
        if not _is_possibly_invertible_component(c):
            continue
        for i in _input_positions_from_source(c, source_id):
            consumer_input_bit = f"{c.id}_{i}_input"
            if not _is_bit_adjacent_to_list_of_bits(output_bit_name, [consumer_input_bit], all_equivalent_bits):
                continue
            output_pos = _find_output_position_for_input(c, i, all_equivalent_bits)
            if output_pos is not None:
                return c.id, output_pos
    return None


def _group_links_by_component(flat_ids, flat_positions):
    """Group flat (id, position) pairs so that consecutive bits from the same component share one entry."""
    input_id_links = [flat_ids[0]]
    input_bit_positions = []
    current_positions = []
    for link, pos in zip(flat_ids, flat_positions):
        if link == input_id_links[-1]:
            current_positions.append(pos)
        else:
            input_bit_positions.append(current_positions)
            input_id_links.append(link)
            current_positions = [pos]
    input_bit_positions.append(current_positions)
    return input_id_links, input_bit_positions


def _links_from_recovered_outputs(
    component, available_output_components, all_equivalent_bits, self
):
    flat_ids = []
    flat_positions = []
    for bit_position in range(component.output_bit_size):
        bit_name = f"{component.id}_{bit_position}_output"
        result = _find_component_carrying_bit(bit_name, component.id, available_output_components, all_equivalent_bits)
        if result is not None:
            component_id, position = result
            flat_ids.append(component_id)
            flat_positions.append(position)
    return _group_links_by_component(flat_ids, flat_positions)


def _positions_for_link(potential_unwanted_component, base_component, base_component_input_index, override_positions):
    """Return the input bit positions of the candidate component that this link covers.

    Three cases: an explicit subset supplied by the caller (partial-link override, e.g.
    Chaskey MODADD), a specific occurrence identified by index (e.g. a key whose words are
    reassembled from disjoint slices of one key-schedule component), or the first match by id.
    """
    if override_positions is not None:
        return override_positions
    if base_component_input_index is not None:
        return base_component.input_bit_positions[base_component_input_index]
    for index, input_id_link in enumerate(base_component.input_id_links):
        if input_id_link == potential_unwanted_component.id:
            return base_component.input_bit_positions[index]
    return []


def _is_valid_recovered_equivalent(bit_name, all_bit_names, base_component_id, available_bits, key_schedule_components):
    """Return True if ``bit_name`` is a recovered output bit usable as an alternative source.

    Rejects bits that belong to the component being inverted, bits not yet recovered,
    bits coming from key-schedule components, and bits whose type is not ``output_updated``
    (meaning the value has not yet been recovered by the inverse pass).
    """
    if bit_name not in all_bit_names:
        return False
    bit = all_bit_names[bit_name]
    return (
        bit["component_id"] != base_component_id
        and bit in available_bits
        and bit["component_id"] not in key_schedule_components
        and bit["type"] == "output_updated"
    )


def _get_equivalent_input_bit_from_output_bit(
    potential_unwanted_component,
    base_component,
    available_bits,
    all_equivalent_bits,
    key_schedule_components,
    self,
    base_component_input_index=None,
    override_positions=None,
):
    """Find a recovered component whose output bits are equivalent to those of the candidate link.

    Returns ``(component_id, positions)`` — either the original candidate (if no better
    source exists) or the recovered component that can substitute for it.
    """
    all_bit_names = _get_all_bit_names(self)
    positions = _positions_for_link(
        potential_unwanted_component, base_component, base_component_input_index, override_positions
    )
    link_bit_names = [f"{potential_unwanted_component.id}_{i}_output" for i in positions]

    equivalent_bits = []
    for bit_name in link_bit_names:
        for equivalent_bit in _equivalent_bit_names(bit_name, all_equivalent_bits):
            if _is_valid_recovered_equivalent(equivalent_bit, all_bit_names, base_component.id, available_bits, key_schedule_components):
                if not equivalent_bits or all_bit_names[equivalent_bit]["component_id"] == all_bit_names[equivalent_bits[0]]["component_id"]:
                    equivalent_bits.append(equivalent_bit)

    if not equivalent_bits:
        return potential_unwanted_component.id, positions
    input_bit_positions = sorted(all_bit_names[bit]["position"] for bit in equivalent_bits)
    return all_bit_names[equivalent_bits[0]]["component_id"], input_bit_positions


def _links_from_known_inputs(
    component, available_bits, all_equivalent_bits, key_schedule_components, self
):
    input_id_links = []
    input_bit_positions = []
    for i in range(len(component.input_id_links)):
        # Source the positions of this link that are already known (available as a forward
        # "output"). A fully-available link yields all its positions (unchanged behaviour); a
        # partially-available link yields only its known sub-range, which lets us invert an
        # operation whose packed input mixes a recovered operand with a known one (e.g. a Chaskey
        # MODADD where one half is the recovered output and the other half is a known operand
        # available through an equivalent recovered component).
        available_positions = [
            position
            for position in component.input_bit_positions[i]
            if _is_bit_contained_in(
                {"component_id": component.input_id_links[i], "position": position, "type": "output"},
                available_bits,
            )
        ]
        if not available_positions:
            continue
        potential_unwanted_component = _component_from_id(component.input_id_links[i], self)
        equivalent_component, input_bit_positions_of_equivalent_component = (
            _get_equivalent_input_bit_from_output_bit(
                potential_unwanted_component,
                component,
                available_bits,
                all_equivalent_bits,
                key_schedule_components,
                self,
                base_component_input_index=i,
                override_positions=available_positions,
            )
        )
        input_id_links.append(equivalent_component)
        input_bit_positions.append(input_bit_positions_of_equivalent_component)

    return input_id_links, input_bit_positions


def _inversion_stall_message(stuck_components):
    """Human-readable diagnostic for a ``cipher_inverse()`` that can no longer make progress.

    Lists how many components are stuck and of which kinds, plus a sample with their input
    links, instead of the opaque "Unable to invert cipher for now.".
    """
    from collections import Counter

    def _kind(component):
        description = component.description
        if isinstance(description, list) and description:
            return f"{component.type}/{description[0]}"
        return component.type

    by_kind = Counter(_kind(component) for component in stuck_components)
    lines = [
        f"Unable to invert cipher: {len(stuck_components)} component(s) could not be processed "
        "(neither evaluable forward nor invertible from the currently recovered bits).",
        "Stuck by kind: " + ", ".join(f"{kind}={count}" for kind, count in by_kind.most_common()),
    ]
    for component in stuck_components[:10]:
        lines.append(f"  {component.id} <- {component.input_id_links}")
    if len(stuck_components) > 10:
        lines.append(f"  ... and {len(stuck_components) - 10} more")
    return "\n".join(lines)


def _count_equivalent_available_bits(output_component, link_bit_names, available_bits, all_equivalent_bits):
    """Count how many of ``output_component``'s recovered output bits are equivalent to bits in ``link_bit_names``."""
    count = 0
    for i in range(output_component.output_bit_size):
        bit_name = f"{output_component.id}_{i}_output_updated"
        bit = {"component_id": output_component.id, "position": i, "type": "output_updated"}
        if _is_bit_adjacent_to_list_of_bits(bit_name, link_bit_names, all_equivalent_bits) and bit in available_bits:
            count += 1
    return count


def _link_is_sourceable_via_outputs(index, component, input_bits, available_bits, all_equivalent_bits, self):
    """Return True if the unavailable input link at ``index`` can be sourced through an equivalent recovered component.

    Scans the successors of the link's source for a component whose recovered output bits are
    equivalent to the link bits and cover the full link (or enough of it).
    """
    link = component.input_id_links[index]
    source = _component_from_id(link, self)
    link_bit_names = [f"{b['component_id']}_{b['position']}_output" for b in input_bits[index]]
    for output_component in self.get_successor_components(source):
        if (output_component.id in component.input_id_links
                or output_component.id == component.id
                or output_component.type == INTERMEDIATE_OUTPUT):
            continue
        n = _count_equivalent_available_bits(output_component, link_bit_names, available_bits, all_equivalent_bits)
        if n == output_component.output_bit_size or (link_bit_names and n >= len(link_bit_names)):
            return True
    return False


def _are_there_enough_available_inputs_to_perform_inversion(component, available_bits, all_equivalent_bits, self):
    """Return True if the currently recovered bits are sufficient to invert ``component``.

    Counts available credits from two sources — bits reachable through successor components
    (output path) and bits reachable through input links (directly or via equivalent recovered
    components) — and checks whether their total meets the inversion threshold.

    Assumes the component input size is a multiple of its output size.
    """
    if component.type == CIPHER_OUTPUT or component.id == INPUT_KEY:
        return True
    if component.type == INTERMEDIATE_OUTPUT and not self.get_successor_components(component):
        return False

    # Collect bits available via the output path (successor components already recovered).
    component_output_bits = [{"component_id": component.id, "position": i, "type": "output"} for i in range(component.output_bit_size)]
    available_from_output = [
        bit
        for bit_list in _component_output_bits(component, self)
        for bit in _equivalent_bits_in_common(bit_list, component_output_bits, all_equivalent_bits)
        if bit in available_bits
    ]

    # Determine which input links are usable (directly available or sourceable via outputs).
    input_bits = _component_input_bits(component)
    usable = [_are_these_bits_available(bits, available_bits) for bits in input_bits]
    for index in range(len(component.input_id_links)):
        if not usable[index]:
            usable[index] = _link_is_sourceable_via_outputs(index, component, input_bits, available_bits, all_equivalent_bits, self)

    # Merge credits: full link bits for usable links, individually known bits for unusable ones.
    total_available = list(available_from_output)
    for index, bits in enumerate(input_bits):
        if usable[index]:
            total_available += bits
        else:
            # A partially-available link still contributes the bits whose value is individually
            # known (directly or via the equivalence map).
            total_available += [
                b for b in bits
                if _input_bit_value_is_recovered(b["component_id"], b["position"], available_bits, all_equivalent_bits)
            ]

    threshold = component.output_bit_size if (component.id == INPUT_PLAINTEXT or INTERMEDIATE_OUTPUT in component.id) else component.input_bit_size
    return len(total_available) >= threshold


_ALWAYS_INVERTIBLE_TYPES = frozenset({
    LINEAR_LAYER, PERMUTATION_COMPONENT, MIX_COLUMN, CONSTANT,
    CIPHER_INPUT, CIPHER_OUTPUT, INTERMEDIATE_OUTPUT,
})
_INVERTIBLE_WORD_OPS = frozenset({"ROTATE", "XOR", "SIGMA", "MODADD", "NOT"})


def _is_possibly_invertible_component(component):
    """Return True if the engine has an inversion rule for this component type.

    For SBOX this means the S-box is a permutation (all output values distinct).
    For WORD_OPERATION this depends on the operation. All other invertible types
    are listed in ``_ALWAYS_INVERTIBLE_TYPES``.
    """
    if component.type == SBOX:
        return len(set(component.description)) == len(component.description)
    if component.type == WORD_OPERATION:
        return component.description[0] in _INVERTIBLE_WORD_OPS
    return component.type in _ALWAYS_INVERTIBLE_TYPES


def _find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits):
    bit_positions = []
    list_of_keys = []

    for index, input_id_link in enumerate(inverse_component.input_id_links):
        for position, i in enumerate(inverse_component.input_bit_positions[index]):
            potential_equivalent_bit_name = f"{input_id_link}_{i}_output_updated"
            list_of_keys += _equivalent_bit_names(potential_equivalent_bit_name, all_equivalent_bits)
    offset = 0
    for index, input_id_link in enumerate(component.input_id_links):
        for pos, i in enumerate(component.input_bit_positions[index]):
            output_bit_name = f"{input_id_link}_{i}_output"
            if output_bit_name in all_equivalent_bits and not any(
                "output_updated" in item for item in _equivalent_bit_names(output_bit_name, all_equivalent_bits)
            ):
                bit_positions.append(offset + pos)
        offset += len(component.input_bit_positions[index])
    return bit_positions


def _update_output_bits(inverse_component, self, all_equivalent_bits, available_bits):
    def _add_output_bit_equivalences(id, bit_positions, component, all_equivalent_bits, available_bits):
        for i in range(component.output_bit_size):
            output_bit_name_updated = f"{id}_{i}_output_updated"
            bit = {"component_id": id, "position": i, "type": "output_updated"}
            available_bits.append(bit)
            input_bit_name = f"{id}_{bit_positions[i]}_input"
            _add_equivalence(all_equivalent_bits, input_bit_name, output_bit_name_updated)

    id = inverse_component.id
    component = _component_from_id(id, self)

    if (
        (component.description == [INPUT_KEY])
        or (component.description == [INPUT_TWEAK])
        or (component.type == CONSTANT)
    ):
        for i in range(component.output_bit_size):
            output_bit_name_updated = f"{id}_{i}_output_updated"
            bit = {"component_id": id, "position": i, "type": "output_updated"}
            available_bits.append(bit)
            input_bit_name = f"{id}_{i}_output"
            _add_equivalence(
                all_equivalent_bits, input_bit_name, output_bit_name_updated, ensure_a=True, symmetric=False
            )
    elif component.input_bit_size == component.output_bit_size:
        _add_output_bit_equivalences(
            id, range(component.output_bit_size), component, all_equivalent_bits, available_bits
        )
    else:
        input_bit_positions = _find_input_id_link_bits_equivalent(inverse_component, component, all_equivalent_bits)
        _add_output_bit_equivalences(id, input_bit_positions, component, all_equivalent_bits, available_bits)


def _links_from_outputs(component, output_components, all_equivalent_bits, self):
    """Input links/positions for a reversed component, sourced from its (recovered) outputs."""
    return _links_from_recovered_outputs(
        component, output_components, all_equivalent_bits, self
    )


def _finalize_inverse(inverse_component, component, self, all_equivalent_bits, available_bits, klass, update=True):
    """Common epilogue: set the component's class, then register its recovered bits."""
    inverse_component.__class__ = klass
    if update:
        _update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    return inverse_component


def _invert_sbox(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(SBox(component.description).inverse()),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_linear_layer(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(inv_binary_matrix),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_permutation(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    permutation, word_size = component.description
    inverse_permutation = [0] * len(permutation)
    for source_word, destination_word in enumerate(permutation):
        inverse_permutation[destination_word] = source_word
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [inverse_permutation, word_size],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_mix_column(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    description = component.description
    x = PolynomialRing(GF(2), "x").gen()
    irr_poly = int_to_poly(int(description[1]), int(description[2]), x)
    if irr_poly and not irr_poly.is_irreducible():
        inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
        inverse_component = Component(
            component.id,
            LINEAR_LAYER,
            Input(component.input_bit_size, input_id_links, input_bit_positions),
            component.output_bit_size,
            list(inv_binary_matrix.transpose()),
        )
        klass = linear_layer_component.LinearLayer
    else:
        inv_matrix = get_inverse_matrix_in_integer_representation(component)
        inverse_component = Component(
            component.id,
            component.type,
            Input(component.input_bit_size, input_id_links, input_bit_positions),
            component.output_bit_size,
            [[list(row) for row in inv_matrix]] + component.description[1:],
        )
        klass = component.__class__
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, klass
    )


def _invert_sigma(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, oc, all_equivalent_bits, self)
    inv_binary_matrix = binary_matrix_of_linear_component(component).inverse()
    inverse_component = Component(
        component.id,
        LINEAR_LAYER,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        list(inv_binary_matrix.transpose()),
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_xor(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    links_out, positions_out = _links_from_outputs(component, oc, all_equivalent_bits, self)
    links_in, positions_in = _links_from_known_inputs(
        component, available_bits, all_equivalent_bits, key_schedule_components, self
    )
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, links_in + links_out, positions_in + positions_out),
        component.output_bit_size,
        component.description,
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_rotate(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.description[0], -component.description[1]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_not(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.description[0], component.description[1]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_modadd(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    links_out, positions_out = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    links_in, positions_in = _links_from_known_inputs(
        component, available_bits, all_equivalent_bits, key_schedule_components, self
    )
    # MODSUB is non-commutative: minuend - subtrahend. The minuend is the recovered output of the
    # original MODADD (sourced from output components); the subtrahend(s) are the known operands
    # (sourced from input components). Place the minuend first directly, rather than relying on a
    # positional reorder that conflates a producer's input- and output-bit spaces (which mis-orders
    # the operand whenever the minuend is read through a bit-reorganizing component, e.g. Sparx).
    inverse_component = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, links_out + links_in, positions_out + positions_in),
        component.output_bit_size,
        ["MODSUB", component.description[1], component.description[2]],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, modsub_component.ModSub
    )


def _invert_constant(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, component.type, Input(0, [[]], [[]]), component.output_bit_size, component.description
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_cipher_output(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, CIPHER_INPUT, Input(0, [[]], [[]]), component.output_bit_size, [CIPHER_INPUT]
    )
    _update_output_bits(inverse_component, self, all_equivalent_bits, available_bits)
    return inverse_component


def _invert_cipher_input_data(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        CIPHER_OUTPUT,
        Input(component.output_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        [component.id],
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits,
        cipher_output_component.CipherOutput, update=False,
    )


def _invert_cipher_input_key(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    inverse_component = Component(
        component.id, CIPHER_INPUT, Input(0, [[]], [[]]), component.output_bit_size, [component.id]
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits, component.__class__
    )


def _invert_intermediate_output(component, available_bits, all_equivalent_bits, key_schedule_components, self, oc, aoc):
    input_id_links, input_bit_positions = _links_from_outputs(component, aoc, all_equivalent_bits, self)
    inverse_component = Component(
        component.id,
        INTERMEDIATE_OUTPUT,
        Input(component.output_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        component.description,
    )
    return _finalize_inverse(
        inverse_component, component, self, all_equivalent_bits, available_bits,
        intermediate_output_component.IntermediateOutput
    )


def _inversion_rule_key(component):
    if component.type == WORD_OPERATION:
        return (WORD_OPERATION, component.description[0])
    if component.type == CIPHER_INPUT:
        if component.id in [INPUT_PLAINTEXT, INPUT_STATE] or INTERMEDIATE_OUTPUT in component.id:
            return (CIPHER_INPUT, "data")
        if component.description == [INPUT_KEY] or component.id == INPUT_TWEAK:
            return (CIPHER_INPUT, "key")
        return (CIPHER_INPUT, None)
    return component.type


_INVERSION_RULES = {
    SBOX: _invert_sbox,
    LINEAR_LAYER: _invert_linear_layer,
    PERMUTATION_COMPONENT: _invert_permutation,
    MIX_COLUMN: _invert_mix_column,
    (WORD_OPERATION, "SIGMA"): _invert_sigma,
    (WORD_OPERATION, "XOR"): _invert_xor,
    (WORD_OPERATION, "ROTATE"): _invert_rotate,
    (WORD_OPERATION, "NOT"): _invert_not,
    (WORD_OPERATION, "MODADD"): _invert_modadd,
    CONSTANT: _invert_constant,
    CIPHER_OUTPUT: _invert_cipher_output,
    (CIPHER_INPUT, "data"): _invert_cipher_input_data,
    (CIPHER_INPUT, "key"): _invert_cipher_input_key,
    INTERMEDIATE_OUTPUT: _invert_intermediate_output,
}


def _component_inverse(component, available_bits, all_equivalent_bits, key_schedule_components, self):
    """Return the reversed form of an invertible component (assumes it is actually invertible)."""
    handler = _INVERSION_RULES.get(_inversion_rule_key(component))
    if handler is None:
        return Component("NA", "NA", Input(0, [[]], [[]]), component.output_bit_size, ["NA"])
    output_components = self.get_successor_components(component)
    available_output_components = _get_available_output_components(component, available_bits, self)
    return handler(
        component,
        available_bits,
        all_equivalent_bits,
        key_schedule_components,
        self,
        output_components,
        available_output_components,
    )


def _try_evaluate(component, available_bits, all_equivalent_bits, self):
    """Attempt to forward-evaluate the component by sourcing every input bit from an
    already-recovered value. Returns the rebuilt component (committing its recovered outputs), or
    ``None`` if not all input bits can be sourced yet.

    Readiness is *derived* from the build attempt: the component is evaluable iff the pure wiring
    covers the whole input. There is no separate readiness predicate to keep in sync with the
    builder - the single ``_evaluate_wiring`` traversal decides both.
    """
    if component.type in (CONSTANT, CIPHER_INPUT):
        return None
    input_id_links, input_bit_positions = _evaluate_wiring(component, available_bits, all_equivalent_bits, self)
    if sum(len(positions) for positions in input_bit_positions) != component.input_bit_size:
        return None
    inverted_component = _build_evaluated_component(
        component, input_id_links, input_bit_positions, available_bits, all_equivalent_bits
    )
    _update_available_bits_with_component_output_bits(component, available_bits, self)
    return inverted_component


def _try_invert(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Invert the component when its output plus enough inputs are known (or it is a key/tweak
    input), then commit both its recovered input and output bits. Returns the reversed
    component, or ``None`` if it cannot be inverted yet. Readiness check, build and commit are
    deliberately co-located here.
    """
    is_invertible = _is_possibly_invertible_component(component) and _are_there_enough_available_inputs_to_perform_inversion(
        component, available_bits, all_equivalent_bits, self
    )
    is_key_or_tweak_input = component.type == CIPHER_INPUT and component.description[0] in (INPUT_KEY, INPUT_TWEAK)
    if not (is_invertible or is_key_or_tweak_input):
        return None
    inverted_component = _component_inverse(
        component, available_bits, all_equivalent_bits, key_schedule_component_ids, self
    )
    _update_available_bits_with_component_input_bits(component, available_bits)
    _update_available_bits_with_component_output_bits(component, available_bits, self)
    return inverted_component


def _apply_inversion_step(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self):
    """Process one component during inversion.

    Tries first to **evaluate it forward** (when all its inputs are known), otherwise to
    **invert it** (when its output plus enough inputs are known, or it is a key/tweak input).
    Each branch co-locates its readiness check with the build and the bit-availability commit
    (see ``_try_evaluate`` / ``_try_invert``). Returns the rebuilt/reversed component, or ``None``
    if the component cannot be processed yet.
    """
    inverted_component = _try_evaluate(component, available_bits, all_equivalent_bits, self)
    if inverted_component is not None:
        return inverted_component
    return _try_invert(component, available_bits, all_equivalent_bits, key_schedule_component_ids, self)


def _component_from_id(component_id, self):
    return _cipher_view(self).by_id.get(component_id)


def _find_recovered_bit_for(bit_name, all_equivalent_bits, available_output_updated):
    """Look up ``bit_name`` in the equivalence map and return the first already-recovered bit
    that carries the same value, as ``(component_id, position)``, or ``None`` if none is available."""
    for equivalent_bit in _equivalent_bit_names(bit_name, all_equivalent_bits):
        if equivalent_bit.endswith("_output_updated"):
            source_id, source_position = equivalent_bit[: -len("_output_updated")].rsplit("_", 1)
            if (source_id, int(source_position)) in available_output_updated:
                return source_id, int(source_position)
    return None


def _resolve_evaluated_input_via_equivalence(component, available_bits, all_equivalent_bits):
    """
    Wire a forward-evaluated component by resolving each of its input bits, through the bit
    equivalence map, to an already-recovered value (an available ``output_updated`` bit).

    Returns ``(input_id_links, input_bit_positions)`` reading from the components that actually
    carry the needed value in the inverse cipher, or ``None`` if any input bit cannot be resolved.

    This is needed when a component's declared input link does not itself carry the wanted value in
    the inverse cipher (e.g. a dead-end ``round_output`` snapshot whose source component was
    inverted, so the source's ``output_updated`` holds a different value than the snapshot captured,
    as in Threefish). All bits of an equivalence class hold the same value, so any available
    representative is correct.
    """
    available_output_updated = {
        (bit["component_id"], bit["position"]) for bit in available_bits if bit["type"] == "output_updated"
    }
    flat_sources = []
    for index, link in enumerate(component.input_id_links):
        for position in component.input_bit_positions[index]:
            resolved = _find_recovered_bit_for(
                f"{link}_{position}_output", all_equivalent_bits, available_output_updated
            )
            if resolved is None:
                return None
            flat_sources.append(resolved)

    input_id_links = []
    input_bit_positions = []
    for source_id, source_position in flat_sources:
        if input_id_links and input_id_links[-1] == source_id:
            input_bit_positions[-1].append(source_position)
        else:
            input_id_links.append(source_id)
            input_bit_positions.append([source_position])
    return input_id_links, input_bit_positions


def _find_correct_order(id1, list1, id2, list2, all_equivalent_bits):
    list2_ordered = []
    for i in list1:
        bit = f"{id1}_{i}_output"
        for j in list2:
            bit_potentially_equivalent = f"{id2}_{j}_input"
            if _bits_equivalent(bit, bit_potentially_equivalent, all_equivalent_bits):
                list2_ordered.append(j)
                break
    return list2_ordered


def _find_equivalent_output_updated_positions(link, link_positions, producer, all_equivalent_bits):
    """
    Map each requested bit ``{link}_{p}_output`` to the position ``q`` of ``producer`` such that
    ``{producer.id}_{q}_output_updated`` carries that value.

    Returns the ordered list of producer output positions, or ``[]`` if any requested bit is not
    covered. Unlike the input-space ``starting_bit`` heuristic, this resolves the value through the
    producer's output space, which is required when the recovered link is not the producer's first
    input (e.g. a size-reducing inverted multi-input XOR/MODADD).
    """
    positions = []
    for p in link_positions:
        link_bit_name = f"{link}_{p}_output"
        equivalents = _equivalent_bit_names(link_bit_name, all_equivalent_bits)
        found = None
        for q in range(producer.output_bit_size):
            if f"{producer.id}_{q}_output_updated" in equivalents:
                found = q
                break
        if found is None:
            return []
        positions.append(found)
    return positions


def _input_offset_of_link(component, link_index):
    """Return the flat input-bit offset where the link at index ``link_index`` begins in ``component``'s input."""
    return sum(len(component.input_bit_positions[j]) for j in range(link_index))


def _find_link_index_for_source(candidate, source_link, needed_positions):
    """Return the index of the link in ``candidate`` that comes from ``source_link`` and covers ``needed_positions``."""
    matches = [
        i for i, x in enumerate(candidate.input_id_links)
        if x == source_link and set(needed_positions) <= set(candidate.input_bit_positions[i])
    ]
    return matches[0] if matches else candidate.input_id_links.index(source_link)


def _try_direct_source(component, input_index, starting_bit_position, source, available_bits, all_equivalent_bits):
    """Return ``([source_id], [positions])`` if the declared source is already fully recovered with
    bits equivalent to what we need, otherwise ``None``."""
    output_bits_updated = [f"{source.id}_{j}_output_updated" for j in component.input_bit_positions[input_index]]
    input_bits = [
        f"{component.id}_{k}_input"
        for k in range(starting_bit_position, starting_bit_position + len(component.input_bit_positions[input_index]))
    ]
    if (_all_output_bits_available(source, available_bits)
            and _is_output_bits_updated_equivalent_to_input_bits(output_bits_updated, input_bits, all_equivalent_bits)):
        return [component.input_id_links[input_index]], [component.input_bit_positions[input_index]]
    return None


def _try_wire_via_candidate(candidate, link, needed_positions, link_bit_names, all_equivalent_bits):
    """Try to source ``needed_positions`` of ``link`` from a candidate alternative component.

    Returns ``(candidate_id, positions, is_complete)`` where ``is_complete=True`` means this fully
    resolves the link and the caller should stop scanning, or ``None`` if the candidate cannot help.

    Two sub-strategies:
    - Input-space heuristic (``is_complete=False``): the candidate's ``output_updated`` at the
      computed input offset is equivalent to the source bits; positions are derived from that offset.
      The caller keeps scanning because more candidates may be needed.
    - Output-space fallback (``is_complete=True``): used when the heuristic fails (e.g. the
      recovered link is not the candidate's first input, as in a size-reducing inverted XOR).
      Resolves through the candidate's output space; stops scanning on success.
    """
    link_index = _find_link_index_for_source(candidate, link, needed_positions)
    offset = _input_offset_of_link(candidate, link_index)
    probe_bit = f"{candidate.id}_{offset}_output_updated"

    if _is_bit_adjacent_to_list_of_bits(probe_bit, link_bit_names, all_equivalent_bits):
        if set(needed_positions) < set(candidate.input_bit_positions[link_index]):
            offset += needed_positions[0] - candidate.input_bit_positions[link_index][0]
        l = list(range(offset, offset + len(needed_positions)))
        ordered = _find_correct_order(link, needed_positions, candidate.id, l, all_equivalent_bits)
        return candidate.id, ordered, False

    out_positions = _find_equivalent_output_updated_positions(link, needed_positions, candidate, all_equivalent_bits)
    if len(out_positions) == len(needed_positions):
        return candidate.id, out_positions, True

    return None


def _wire_input_link_for_evaluation(
    component, input_index, starting_bit_position, available_bits, all_equivalent_bits, self
):
    """Resolve one input link of a forward-evaluated component to the recovered component(s) that
    carry its value, returning ``(ids, positions)`` to append to the rebuilt wiring.

    Strategy 1: use the declared source directly if it is already fully recovered and equivalent
    to what we need (see ``_try_direct_source``).
    Strategy 2: scan components that also read from the same source; for each valid candidate, try
    the input-space heuristic first (may accumulate multiple contributions), then the output-space
    fallback (stops on first full resolution). See ``_try_wire_via_candidate``.
    """
    link = component.input_id_links[input_index]
    needed_positions = component.input_bit_positions[input_index]
    source = _component_from_id(link, self)

    direct = _try_direct_source(component, input_index, starting_bit_position, source, available_bits, all_equivalent_bits)
    if direct is not None:
        return direct

    ids = []
    positions = []
    link_bit_names = [f"{link}_{l}_output" for l in range(source.output_bit_size)]
    for candidate in _get_available_output_components(source, available_bits, self):
        if candidate.id in component.input_id_links or candidate.id == component.id:
            continue
        result = _try_wire_via_candidate(candidate, link, needed_positions, link_bit_names, all_equivalent_bits)
        if result is None:
            continue
        candidate_id, candidate_positions, is_complete = result
        ids.append(candidate_id)
        positions.append(candidate_positions)
        if is_complete:
            break
    return ids, positions


def _evaluate_wiring(component, available_bits, all_equivalent_bits, self):
    """Compute the forward-evaluation wiring ``(input_id_links, input_bit_positions)`` for a
    component, sourcing each input bit from an already-recovered value.

    Pure: reads ``available_bits`` / ``all_equivalent_bits`` but mutates nothing. The returned
    wiring may not cover the whole input (when not enough is recovered yet) - callers check
    coverage. This is the single traversal both the builder (``_build_evaluated_component``) and the
    readiness check derive from, so the "can I evaluate?" decision and the construction can never
    drift apart.
    """
    input_id_links = []
    input_bit_positions = []

    if component.type != "cipher_input":
        starting_bit_position = 0
        for i in range(len(component.input_id_links)):
            ids, positions = _wire_input_link_for_evaluation(
                component, i, starting_bit_position, available_bits, all_equivalent_bits, self
            )
            starting_bit_position += len(component.input_bit_positions[i])
            input_id_links.extend(ids)
            input_bit_positions.extend(positions)
    else:
        input_id_links = [[]]
        input_bit_positions = [[]]

    empty_indices = [j for j, positions in enumerate(input_bit_positions) if positions == []]
    for index in sorted(empty_indices, reverse=True):
        del input_id_links[index]
        del input_bit_positions[index]

    # If the wiring assembled above does not cover the whole input (e.g. a dead-end round_output
    # snapshot whose source was inverted, so the value it captured is not the source's recovered
    # output but lives on other recovered components - as in Threefish), resolve the input bits
    # through the equivalence map to the components that actually carry that value.
    if component.type != "cipher_input" and sum(len(p) for p in input_bit_positions) != component.input_bit_size:
        resolved = _resolve_evaluated_input_via_equivalence(component, available_bits, all_equivalent_bits)
        if resolved is not None:
            input_id_links, input_bit_positions = resolved

    return input_id_links, input_bit_positions


def _build_evaluated_component(component, input_id_links, input_bit_positions, available_bits, all_equivalent_bits):
    """Build the rebuilt forward-evaluated component from its (already complete) wiring and commit
    its recovered output bits to the availability/equivalence state. Mutating counterpart to the
    pure ``_evaluate_wiring``."""
    evaluated = Component(
        component.id,
        component.type,
        Input(component.input_bit_size, input_id_links, input_bit_positions),
        component.output_bit_size,
        component.description,
    )
    evaluated.__class__ = component.__class__

    id = component.id
    for i in range(evaluated.output_bit_size):
        output_bit_name_updated = f"{id}_{i}_output_updated"
        available_bits.append({"component_id": id, "position": i, "type": "output_updated"})
        output_bit_name = f"{id}_{i}_output"
        _add_equivalence(
            all_equivalent_bits, output_bit_name, output_bit_name_updated, ensure_a=True, symmetric=False
        )

    return evaluated


