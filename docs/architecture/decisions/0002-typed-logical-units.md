# ADR 0002: Use typed logical units on graph wires

Status: accepted

## Decision

A graph value has a `ValueType`: one immutable scalar `Domain` and a
homogeneous shape. Connections address logical units of this type rather than
assuming every position is a bit.

Domains describe mathematical semantics. Encoding and storage are separate
concerns. In particular, a byte does not imply either `GF(2^8)` or integer
arithmetic modulo 256.

The initial domains are bits, binary extension fields, and prime fields.
Bit-vectors and integers modulo powers of two will be added when traditional
cipher components are introduced.

## Consequences

- A permutation is generic over homogeneous value types.
- Field parameters, including modulus and basis, are explicit.
- Encoded bit length is metadata and may differ from logical size.
- Cross-domain reinterpretation or decomposition requires explicit components.
- Runtime values remain lightweight Python values rather than wrapped element
  objects.
