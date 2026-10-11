# Native Python diagrams and state progression

`claasp.diagrams` extracts typed CLAASP component graphs, generates editable ASCII
circuits, reparses their visible wires, reconstructs working primitive classes,
and emits TikZ and generic state views. The contribution contains no JavaScript,
Node bridge, downloaded runtime or ELK dependency. Python's standard library
implements diagram planning, glyph parsing/rendering and vector emission.

```python
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher, to_tikz
ir = from_cipher(cipher, roles={'plaintext': 'data', 'key': 'key'})
text = to_ascii(ir)
assert from_ascii(text) == ir
restored = to_cipher(from_ascii(text))
figure = to_tikz(ir, rowsPerPanel=16, columnsPerPanel=6, columnSpacing=3)
```

Native records preserve widths, ordered bit fragments, constants, complete
operation parameters and round membership. Each glyph annotation defines one
local input, operation or independent parallel group. It contains no original dependency edges. Parsing
traces actual ports, crossings, forks and visible operand bindings. Renaming
identifiers does not select a different geometry; primitive names and manual
reference drawings never participate in placement.

The generic live-register planner counts uses, reuses expired lanes, copies
values that remain live and captures intermediate observations at production.
Constants wait for a ready consumer. Rigid horizontal segments retain their
per-column order during track compaction. `strategy='direct-bus'` provides a
baseline with fresh result lanes. Native generation accepts its output only
after an actual exported-text round trip recovers the complete IR.

`semantic-auto` compares four generic candidates by rectangular area plus
occupied cells: the legacy register schedule, local input selections,
independent parallel groups, and round-aware scheduling. It never consults a
primitive name or example. Explicit strategies `semantic-legacy`,
`semantic-ports`, `semantic-parallel`, and `semantic-round` expose these
candidates for reproducible comparisons. A parallel group contains adjacent
independent operations with equal type, width, parameters and round, drawing
from the same visible incoming values. It preserves each operation identity
and ordinal; observations and dependencies end a group. Local operand masks
index the bit stream traced from visible wires, including repeated and ordered
bits. Neither masks nor group members contain hidden source edges. Removing or
changing the visible wiring therefore changes parsing or fails validation.

The separate web editor uses JavaScript. It shares the typed interchange and
5-by-11 glyph specification, not a runtime dependency. Cross-language fixtures
must be tested separately; compatibility with every legacy multirow glyph is
not promised by the current native parser. Borderless directional wires are
resolved from neighboring ports, and ambiguous directions fail explicitly.

Supported executable components include fixed rotations/shifts, reverse/NOT,
XOR/AND/OR, modular arithmetic, constants, S-boxes, binary linear layers, mix
columns, permutations and intermediate/final outputs. FSR and variable-amount
operations fail explicitly. A scalar drawing alone cannot identify missing
native tables, widths, bit selections or round annotations. `to_records` and
`from_records` remain explicit diagnostic record interchange.

`to_ascii` accepts `max_cells` (1,000,000) and `max_calls` (20,000). Bit expansion
is bounded separately at 2,000,000 explicit bits. `from_ascii` accepts
`max_text_bytes` (64,000,000) and `max_grid_area` (2,000,000); export accepts
these bounds too and checks the rectangular area and byte count before rendering.
`max_cells` counts occupied cells, whereas `max_grid_area` includes empty cells
in the rendered rectangle. Diagnostic record imports apply the byte limit and
use the area limit as a bound on input and component records. Bounds reject work;
they never silently omit components. These are work/output limits, not wall
clock guarantees. Wider native graphs may require a revised representation.

TikZ accepts `rowsPerPanel`, `columnsPerPanel`, `maxPanels` (256), half-open
`rowRange`/`columnRange` crops, spacing and `pageBreaks=False`. Long definitions
use precise keyed legends. Native operation labels expose widths and parameters,
parallel labels expose member counts, and wires attach to box boundaries. Panel count is separate from PDF page count. Insert
the fragment directly in a document body with `\usepackage{tikz}`.

State views are native Python too. Declared outputs, round boundaries and
layer frontiers are generic choices. `word_bits`, `columns` and source order
are explicit shape annotations; absent identifiable geometry produces
`ambiguous-flat-fallback`. Evaluated values and XOR differences retain native
source identities. Unknown values remain unknown. No cipher-specific state
adapter is used.

Run in the CLAASP/Sage environment:

```sh
pytest tests/unit/diagrams_test.py -q
python docs/diagrams/conformance.py
python docs/diagrams/conformance_extended.py --output /tmp/claasp-python-corpus
```

JavaScript-backed results from the previous implementation are historical.
Native Python measurements, installed-package tests and cross-language
conformance are recorded separately. No general readability, exact layout
inversion or unseen-family guarantee follows from a successful semantic test.
