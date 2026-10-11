# Generic typed diagrams (initial implementation)

`claasp.diagrams` imports native component DAGs into a validated, width-aware
IR and reconstructs native `Cipher` objects. Ordered bit positions, constant
lexemes, component descriptions and round indices are explicit. Layout is a
separate dependency-layer mapping. No primitive names select a renderer.

```python
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher, to_tikz, state_view
ir = from_cipher(cipher, roles={'plaintext': 'data', 'key': 'key'})
restored = to_cipher(from_ascii(to_ascii(ir)))
print(to_tikz(ir, layer_spacing=2, slot_spacing=3))
print(state_view(ir))
```

Roles default to `unspecified`; names are never used to guess roles. Native
zero-length input links are omitted during import because they select no bits.
All nonempty selections preserve their order. Unsupported executable native
component types/operations raise `ValueError` rather than becoming free-text
functions. Reconstruction supports the tested arithmetic, Boolean, rotation,
shift, reverse, S-box, linear/mix-column, permutation and output components.
FSR import/reconstruction is implemented but not validated by this first corpus.

ASCII v1 is an explicit framed record dialect, not the legacy builder glyph
grid. Its inputs and individual operation/edge records are visible JSON fields;
there is no embedded original graph to bypass text parsing. The builder-side
`typedDiagram.js` parser validates actual exported files, but importing these
records into the legacy graphical editor remains unfinished. Do not claim
legacy glyph-grid compatibility for this dialect.

TikZ draws generic DAG layers and ordered bit-link labels with configurable
spacing. The mixed-selection smoke document compiled successfully with the
desktop LaTeX compiler; the broad corpus is not assessed for readability. Long selections
can produce unwieldy labels. State views expose native intermediate/output
selections. Geometry is `ambiguous-flat-fallback` unless an explicit shape covers
all bits. No cipher-specific state geometry is inferred. Numeric state evaluation
is supplied by native CLAASP, not this view metadata.

Conformance scripts and saved corpus are in the sibling ASCII builder repository
under `review/evidence/2026-10-11-builder-milestone3/`. They cover fourteen native
primitive configurations, independent scalar-operation and mixed-width bit-link
oracles, native intermediate outputs, identifier-renaming layout invariance,
malformed selection rejection, and a full-round Speck known-answer vector.
Native-vs-reconstructed comparisons validate serialization, not implementation
independence; the separate integer oracles and known-answer check serve that role.

No paper, PR, CI run or novelty claim is implied by this initial module.
