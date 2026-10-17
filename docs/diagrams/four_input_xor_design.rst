Four-input XOR: existing vocabulary and proposed word contract
=============================================================

Status: design proposal only. Persistent routed defaults are unchanged. No new
word binding schema, glyph, grouping convention or parser admission is enabled.

Boundary and catalog evidence
-----------------------------

``SimonBlockCipher(block_bit_size=32,key_bit_size=64,number_of_rounds=5)``
first needs a four-input XOR at native round index 4, node ``xor_4_4``. It has
16-bit output and 64-bit input. Four-round Simon remains admitted; five/six-round
Simon reject the current physical-port limit. This is a general arity issue,
not a cipher-name condition.

The builder catalog limits a single-word XOR to top/left/right inputs plus a
bottom output. Multi-word component frames exist with independently selected
top/bottom word slots. They do not automatically make a four-input, 16-bit
reduction into a single current word cell. The Python persistent parser reads
5-line, 11-character cells with side-name ports; merged-box footprints and
indexed top ports would need a separate parser/binding contract. A wide-box
choice cannot be inferred from the desired primitive name or a manual lookup.

Existing generic binary reduction semantics
------------------------------------------

The established R1 manual/builder convention already expresses associative
reduction using ordinary binary XOR boxes and visible group/step references.
A balanced four-word example is::

    G0.R0 = XOR(A, B)
    G0.R1 = XOR(C, D)
    G0.R2 = XOR(G0.R0, G0.R1)

These are not helper opcodes. The three visible binary calculations represent
one original native XOR with arity 4. Existing ``reductions.py`` validates shared
native fields, exactly arity-1 members, actual routed parenthood, one root,
one in-group consumer per nonroot, and complete ordered leaf coverage. Only
the root may be observed/reused externally. Original edge masks still recover
one actual source per mask; they preserve native edge segmentation separately
from logical port count. Existing R1 records contain no hidden leaf/source or
parent lists. The parser discovers these exclusively from actual wires.

Ordinary three/four-input R1 tests preserve one native XOR and an observed
root, with fresh exact IR and independently checked integer values. These
checks use the explicit historical serializer to verify the existing contract;
its old placements are not restored or proposed as the new persistent layout.

Why this is not a drop-in word implementation
--------------------------------------------

Current ``claasp-word-view-bindings/experimental-3`` requires one native
operation ordinal per visible box. Its strict operation record has only
``at``, ``definition``, ``ordinal``, ``operand_ports`` and ``operand_positions``.
It rejects duplicate native ordinals. It has no reduction kind/step ownership;
three unmarked XOR boxes would decode as three native operations, losing the
original node identity, arity, edge partition and observer attachment.

The historical human-footer decoder supports R1, but its final native-output
fragments must follow visible left-to-right order. Current routed word views
can finish on arbitrary real terminals, explicitly labelled C0,C1,... . Thus
changing only the footer serializer would not preserve the delivered routed
placement/packing contract.

Proposal for review
-------------------

Prefer explicitly adopting the existing visible R1 group/step convention in a
versioned word-binding extension, rather than inventing a wide-input glyph.
A proposed positive option would lower only oversized associative XOR nodes;
ordinary three-port XOR and all delivered defaults would stay byte-identical.
No option or version name is committed by this proposal.

The extension must:

* retain the current native header/input/observer/output packing contract;
* mark each member visibly with its canonical G-ordinal/R-step reference;
* repeat only the original local native facts, edge masks and ordered ports;
* derive the member tree/root and ordered leaf packets from fresh actual routes;
* reject contradictory fields, duplicate/missing members, repeated ownership,
  nonroot external use, cross-group links and wrong widths;
* attach observers and external consumers only to the actual root;
* rebuild exactly one original native node, not an expanded semantic graph;
* enforce existing bounds before projected expansion and preserve all old
  decoder behavior/version checks.

Approval/admission of this group convention in persistent word output is the
remaining decision. Work unaffected by that decision can continue: ordinary
three-port routing, deterministic scheduling, exact native parsing and normal
bounded cipher coverage. No DES representation or implicit semantic rewrite
is part of this proposal.
