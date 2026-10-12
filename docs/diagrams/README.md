# Native Python diagrams and state progression

`claasp.diagrams` extracts typed CLAASP component graphs, generates editable ASCII
circuits, reparses their visible wires, reconstructs working primitive classes,
and emits TikZ and generic state views. The contribution contains no JavaScript,
Node bridge, downloaded runtime or ELK dependency. Python's standard library
implements diagram planning, glyph parsing/rendering and vector emission.

```python
from claasp.diagrams import from_cipher, to_ascii, from_ascii, to_cipher, to_tikz
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
cipher = SpeckBlockCipher(number_of_rounds=1)
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
Dependency-ready heaps update only consumers of each produced value; their
stable index/round/join priorities preserve deterministic scheduling. Constants
wait for a ready consumer, with a bounded fallback for constant-only cones. Rigid horizontal segments retain their
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

TikZ now defaults to `view='overview-detail'`: a generic round dependency
overview, a complete cross-stage dependency table, hyperlinked readable
native-member/input-fragment tables, and shared
parameter definitions. Adjacent-stage edges are drawn in the summary; longer dependencies stay explicit
in its complete table. It never selects stages or shapes from a primitive name.
Observation and final-output tags use readable member references and complete
shared parameter entries, so long tags do not widen the operation column.
All native operations remain in the member tables; ordinal references `n0`,
`n1`, etc. link fragments to those identities, and `I0`, `I1`, etc. follow declared
input order. Consecutive members of an independent bundle can be displayed as
a range, explicitly retaining one input fragment per member. Stride notation
`a:s:b` is inclusive and lossless; repetitions remain explicit.

`view='overview'` is explicitly a compact summary. `view='detail'` emits the
complete readable member/parameter tables. `view='wires'` emits the complete
low-level glyph grid with signed rotations, widths, numbered ports and visible
ordered-binding markers. Detailed wire views can use `rowsPerPanel`,
`columnsPerPanel`, `maxPanels` (256), half-open `rowRange`/`columnRange` crops,
spacing and `pageBreaks=False`. Crops apply to the wire view; they do not silently
remove member records from readable tables. Large wire views may need several
pages even when their generic round overview is compact.

Readable tables paginate with `tableLineBudget` (42) and `maxPages` (2048).
Cells use explicit 9-point monospaced line boxes with an 11-point baseline;
all columns, including identities and operation labels, contribute to pagination.
Long rows split into explicitly marked continuations. Declared inputs get their
own bounded pages. Use a document text width of at least 175 mm (for example,
A4 with 17 mm margins); paste the output in the document body, not a float.
`overviewStagesPerPanel` (6) and `stageMode='round'|'layer'` configure the summary.
Use a unique alphanumeric/hyphen `anchorPrefix` when combining multiple diagrams
in one document. Add `\usepackage{tikz,hyperref}` for clickable overview/detail
navigation; TikZ alone works with fallback navigation commands. Full local JSON
is no longer the default legend. `audit=True` or `legend='audit'` appends a
separate full local-definition audit; `legend='none'` omits tables in the wire
view. Typed ASCII remains the complete independent audit source. Long constant
values use shared references, with their complete values in the readable parameter tables.

```python
readable = to_tikz(ir)  # overview + every native member + parameter tables
compact = to_tikz(ir, view='overview', stageMode='layer')
wires = to_tikz(ir, view='wires', legend='none', rowsPerPanel=18,
                columnsPerPanel=10, columnSpacing=3, anchorPrefix='example')
with_audit = to_tikz(ir, audit=True)
```

Every vector export reparses its actual generated ASCII before presentation.
The selected layout is reused after exact IR validation: one generic candidate
search, one exported-text parse, and wire panels only for `view='wires'`.
The readable presentation preserves parameters and ordered input fragments;
it does not claim arbitrary original placement inversion or a human-study score.

State views are native Python too. Declared outputs, round boundaries and
layer frontiers are generic choices. `word_bits`, `columns` and source order
are explicit shape annotations; absent identifiable geometry produces
`ambiguous-flat-fallback`. Evaluated values and XOR differences retain native
source identities. Unknown values remain unknown. No cipher-specific state
adapter is used. `state_tikz` reserves `row_gap=0.25` cm between rows
for cell indices, avoiding an index overlapping the preceding value box.
`state_view` describes bits, whereas `state_snapshots` can group them into
words; an explicit bit-level shape must cover every selected observation.
For instance, Speck observations include different widths, so one shared
bit shape cannot cover both its key and data observations.

```python
from claasp.diagrams import evaluate_state_values, state_ascii, state_tikz
values = evaluate_state_values(cipher, [0x6574694c, 0x1918111009080100])
print(state_ascii(ir, mode='round', word_bits=16, columns=2, values=values))
state_figure = state_tikz(ir, mode='declared', word_bits=16, columns=2,
                          values=values, rows_per_panel=12)
```

The public API docstrings contain runnable Sage examples with inputs, outputs,
errors and visible snippets. Run them with `python -m sage.doctest
claasp/diagrams.py`; correctness and malformed-input cases remain in pytest.

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
