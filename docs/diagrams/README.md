# Generic glyph diagrams and state progression

`claasp.diagrams` preserves explicit native widths, ordered bit links, operation
parameters/tables/constants and rounds. No primitive name or manual fixture
selects the layout. Roles default to `unspecified`; supply them explicitly. Native classes reconstructed by this module retain those annotations on later `from_cipher` calls; an explicit `roles` mapping overrides them.

```python
from claasp.diagrams import (from_cipher, to_ascii, from_ascii, to_cipher,
                            to_tikz, evaluate_state_values, state_ascii, state_tikz)
ir = from_cipher(cipher, roles={'plaintext': 'data', 'key': 'key'})
glyphs = to_ascii(ir)  # actual builder-importable ASCII glyphs by default
restored = to_cipher(from_ascii(glyphs))
tikz = to_tikz(ir, columnSpacing=2, rowSpacing=1,
               wireStyle='orthogonal', roundedCorners=2, labels='operation')
values = evaluate_state_values(cipher, inputs)
print(state_ascii(ir, mode='round', word_bits=8, columns=8, values=values))
print(state_tikz(ir, mode='declared', word_bits=8, columns=8, values=values))
```

ASCII and TikZ use a bundled snapshot of the same JavaScript builder strategy;
`diagram_builder/SOURCE-MANIFEST.json` records upstream file hashes. Generation
and glyph parsing require Node.js on PATH (tested with Node 24). Each subprocess
has a 30-second default bound, configurable with `timeout`; `node` can select an
explicit executable. Executing a reconstructed native Cipher requires Sage and
CLAASP, but no Node subprocess. The retained `to_records`/`from_records` dialect
is an explicit diagnostic interchange format; `from_ascii` also accepts it.
`to_layered_tikz` retains the earlier separate dependency-layer visualization.

Glyph footers associate explicit semantic definitions with visible box anchors.
They contain no operand edges: actual wires and visible local operand bindings
supply every dependency. Lossless arbitrary placement inversion is not promised
from pseudocode alone. Identifier renaming does not select a different geometry.
Selection/join helpers preserve ordered MSB-first fragments and mixed widths.

Supported validated executable components: fixed rotation/shift, reverse/NOT,
XOR/AND/OR, modular arithmetic, constants, S-boxes, binary linear layers,
mix columns, permutations and explicit intermediate/final outputs. FSR and
variable-amount operations currently fail explicitly; their contracts need
additional validation rather than a silent rendering/execution guess. Tables
and arithmetic widths/arity are validated before download/reconstruction.

State rendering supports declared outputs or generic live-value cuts by round
or dependency layer. A live-value cut is not claimed to be an algorithm's state
matrix. With no explicit columns it reports `ambiguous-flat-fallback`.
`word_bits`, `columns` and `order='source'|'reverse'` specify generic shape/order;
word width must divide the selected bits. Unknown values are shown as `?`.
Provide `comparison` alongside `values` to annotate XOR differences; nonzero
words are marked `*` in ASCII and shaded in TikZ. Values come from native
component traces, never from a primitive-specific adapter.

The mixed-selection shared-layout/state TikZ smoke document compiles. Broad
TikZ readability and route geometry still require review; large circuits can be
very tall. Fifteen typed configurations recover complete native IR; fourteen
native configurations pass three serialization comparisons each. Most use two
rounds. Full-round Speck, Simon, PRESENT and AES known-answer vectors and native
intermediate traces pass through actual glyph text. These shared-evaluator
comparisons do not establish independent full-cipher correctness.

Run `tests/unit/diagrams_test.py` and `docs/diagrams/conformance.py` in the Sage
runtime. Additional frozen builder evidence is in the sibling repository's
`review/evidence/2026-10-11-builder-milestone5/`. The paper, graded visual metric,
held-out evaluation and complete interactive editing workflow remain unfinished;
no publication or novelty claim is implied by this implementation checkpoint.

Bundled ELK retains its EPL-2.0 OR GPL-3.0-or-later notices. Its source is bundled
because the shared compiler also has a legacy layout fallback; the native glyph
bridge uses the generic direct/conservative bus strategy.

## Bounded print exports

`to_tikz` accepts `rowsPerPanel` (default 16), `columnsPerPanel` (6),
`maxPanels` (256), and half-open `rowRange`/`columnRange` crops. Limits fail
explicitly instead of excluding primitive names. Bounds must align with complete
blocks. Matching `rROWcCOLUMN` or `cCOLUMNrROW` labels connect neighboring panels.
Long labels use exact coordinate keys and a wrapped legend. Use the returned
fragment directly in a document body with `\usepackage{tikz}`, not one float;
`pageBreaks=False` selects paragraph separation. Node parameters remain exact.

`state_tikz` separately accepts `rows_per_panel`, `columns_per_panel`,
`frame_range`, `max_panels` and `page_breaks`. Original state indices remain
visible; large hex values use exact keyed legends. These controls change
presentation only. Frontier modes retain future-live values and final outputs;
declared mode exposes intermediate observable taps separately.

Fourteen cropped and fourteen full paginated test documents compile without
overfull boxes. Representative pages and a complete 12-page circuit were
inspected; the 1,752-page full corpus was not exhaustively reviewed. Pagination
does not cure dense-grid footprint. A new eight-family reduced-round sweep
passes three native evaluations each; binary-string constants, FSRs and
inconsistent declared/output widths are reported explicitly. The sibling
builder evidence preserves original failures and subsequent prospective trials.

Run the additional reproducible integration sweep using:

```sh
python docs/diagrams/conformance_extended.py --output /tmp/claasp-extended-corpus
pytest tests/unit/diagrams_test.py -q
```

The sweep records actual configured rounds and byte footprints. Its shared
evaluator comparisons are integration evidence, not known-answer correctness
proofs. Representative browser flows cover wire/operand edits, deletion and
replacement, undo/redo, saved-text reimport and malformed import rejection;
exhaustive interactive coverage and stronger compactness remain open.
