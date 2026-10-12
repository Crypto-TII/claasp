# Native Python diagrams and state progression

`claasp.cipher_modules.diagram` contains the implementation; `claasp.diagrams`
retains the public compatibility imports. It extracts typed CLAASP component graphs, generates editable ASCII
circuits, reparses their visible wires, reconstructs working primitive classes,
and emits TikZ and generic state views. The contribution contains no JavaScript,
Node bridge, downloaded runtime or ELK dependency. Python's standard library
implements diagram planning, glyph parsing/rendering and vector emission.

```python
from claasp.diagrams import from_cipher, to_ascii, to_audit_ascii, from_ascii, to_cipher, to_tikz
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
cipher = SpeckBlockCipher(number_of_rounds=1)
ir = from_cipher(cipher)
print(to_ascii(ir))  # human presentation is the default
text = to_audit_ascii(ir)  # explicit lossless editor/import encoding
assert from_ascii(text) == ir
restored = to_cipher(from_ascii(text))
figure = to_tikz(ir, rowsPerPanel=16, columnsPerPanel=6, columnSpacing=3)
```

## Docker workflow migration

Run this in the Sage Python environment where CLAASP is installed (the user's
container uses `/opt/conda/envs/sage/bin/python`). Updating this isolated branch
does not automatically update an existing container's mounted CLAASP checkout;
install or mount the reviewed revision before expecting the new API there.

```python
from claasp.ciphers.block_ciphers.speck_block_cipher import SpeckBlockCipher
# Canonical implementation package:
from claasp.cipher_modules.diagram import from_cipher, to_ascii, from_ascii
# Existing public imports remain supported:
# from claasp.diagrams import from_cipher, to_ascii, from_ascii

speck = SpeckBlockCipher(number_of_rounds=1)
ir = from_cipher(speck)
print(to_ascii(ir))                 # readable manual grid, no JSON
text = to_ascii(ir, annotations=True)  # exact native local metadata
assert from_ascii(text) == ir

from claasp.cipher_modules.diagram import to_audit_ascii, synthesis_report
legacy = to_audit_ascii(ir)         # explicit audit compatibility
assert from_ascii(legacy) == ir
print(synthesis_report(ir)['metrics'])
```

The human defaults are `annotations=False`, `word_bits=None`,
`operator_style='symbols'`, `wire_borders=False`, `alignment='left'`,
`layout_preference='balanced'`, and `strategy='semantic-auto'`. Work defaults:
`max_cells=1000000`, `max_calls=20000`, `max_grid_area=2000000`,
`max_text_bytes=64000000`. Choose `layout_preference='crossings'`, `'depth'` or
`'width'` for measured generic priorities; use `synthesis_report` to inspect
tradeoffs. Native source links always come from actual exported wires.
Final, intermediate and unused-value sinks visibly read `OUT`, `OBS` and `DEAD`.
A `DEAD` sink has a width-only local discard record; the actual wire supplies
its value and the unused computation remains in the recovered primitive. Final
anchors occupy the physical bottom block row. Native input fragments retain
ascending source-bit order by their visible word indices; reordered selections
require visible SEL helpers. Footer-only anchor or word reassignment rejects.
Manual constants use a visible hexadecimal literal across up to two seven-character
interior lines (14 characters including `x`). Values through the 52-bit maximum fit;
longer literals fail explicitly and require audit output. Capacity depends on the
value, not the declared operation width; no literal is truncated.

Migration notice: `to_ascii(ir)` now returns the readable manual block body.
It directly imports through the builder's existing scalar/manual decoder.
For exact native reconstruction, use `to_ascii(ir, annotations=True)` and
`from_ascii`, or retain `to_audit_ascii`/`to_ascii(format='audit')`. The conformance
corpus generators, independent oracle script and audit tests use the explicit
audit API, including native shapes outside the current human projection.

```python
body = to_ascii(ir)
annotated = to_ascii(ir, annotations=True)
assert from_ascii(annotated) == ir
```

The plain body retains visible scalar operations, fixed rotation/shift amounts,
constants, secrecy markers and directed connectivity. It cannot recover native
widths, identities, numeric rounds, input bundles or unused bits. `SELn`/`JOIN`
helpers need their coordinate-local masks/bundle widths to reconstruct executable
native semantics. The annotated format retains these details and parses actual
wires; it contains no original graph or source links. Pseudocode alone cannot
recover arbitrary original placement or missing native annotations.

Supported human controls are `operator_style='symbols'|'labels'`,
`wire_borders=False|True`, `alignment='left'|'right'`, an optional positive
`word_bits`, and `layout_preference='balanced'|'crossings'|'depth'|'width'`.
`semantic-auto` compares six generic schedules: declaration order, joins,
numeric rounds, liveness/width, dependency depth and estimated crossings.
Explicit strategies are `semantic-legacy`, `semantic-ports`, `semantic-round`,
`semantic-width`, `semantic-depth`, `semantic-crossings`; `direct-bus` is a
baseline. The preference selects by measured crossing-cell count, block-row
depth and lane width. Balanced minimizes rectangle area plus occupied cells.
These heuristics do not guarantee globally optimal drawings. `synthesis_report`
returns the selected variant, costs and candidate reports. Alignment prefers
expired operand lanes while respecting liveness and ordered arithmetic.

Lanes use the fixed manual 5-by-11 vocabulary; arbitrary column spacing and
whole-operation border removal are unsupported. Routing-cell frames are a
render option. Numeric rotation/shift arrows retain amounts in both styles.
Unsupported shapes, oversized parameter labels and custom moduli explicitly
require audit mode; human support currently covers uniform unary/binary words,
constants, selections and native boundary fragments.

Key roles come from explicit `roles`, retained `diagram_input_roles`, or CLAASP's
standard `INPUT_KEY`/`INPUT_PLAINTEXT` block-cipher interface conventions. Other
inputs remain unspecified; `roles={}` disables automatic conventions. Names
never select roles or layouts. Port-free readable labels give input/unused-word
legends, declared-round cues and observation markers. They have no computation
ports. Observation taps continue their live lanes; final output caps share a
common bottom row. Adjacent two-lane output cycles use a visible generic
exchange. Declared-round fences keep later-round constants within their stage.

`o` is duplication. Wire-cell `+` is a turn/crossing; arithmetic `+` is inside
its operation box. In one-round Speck the supplied key word is observed without
an expanded schedule. The five-round example shows the native key operations.

Complete default printouts: [one-round Speck](examples/speck-1-round-public-human.txt),
[five-round Speck](examples/speck-5-round-public-human.txt), and
[generic Feistel](examples/generic-feistel-f-chain-public-human.txt). The API
docstring prints every line, with a display margin solely to keep rotation
arrows from being interpreted as doctest prompts. Actual `to_ascii` output has
no added margin or default JSON dump.

Ordered native tuples/Sage vectors and integer scalars normalize to JSON-safe
lists/integers. Binary linear-layer entries convert only if exactly zero or one;
nonbinary field entries fail. Native containers remain unmodified, and this
storage normalization does not admit new operation types.

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
occupied cells, retaining only the current candidate and winner: the legacy
register schedule, local input selections,
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
columns, permutations and intermediate/final outputs. Binary constants and
variable rotations/shifts are supported: the ordered stream contains data bits
first, then control bits, and the signed multiplier is preserved. Native variable
shift reduces its control modulo the output width before multiplying by the
direction; this differs from saturating an arbitrary shift count.

`IDEA_MODMUL` requires exactly two logical operands and an explicit positive
modulus no larger than `2^width+1`; zero inputs map to `2^width`, and that result
maps back to zero. Descriptions with one/three operands or `None` modulus fail.
Binary FSRs preserve ordered synchronous registers, global bit-index ANF
feedback and optional clock conditions, with 1--100,000 clocks. Empty/`None`
binary clock conditions mean unconditional clocking, as in the native backend.
Word FSRs remain unsupported because current native replay drops registers
and fails across repeated clocks. Extra input bits and over-wide constant
literals fail rather than being silently truncated. A scalar drawing alone cannot identify missing
native tables, widths, bit selections or round annotations. `to_records` and
`from_records` remain explicit diagnostic record interchange.

`to_audit_ascii` accepts `max_cells` (1,000,000) and `max_calls` (20,000). Bit expansion
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
ordered-binding markers. Compact wire labels `VROT`, `VSHIFT` and `MAPMUL`
refer to variable rotate, variable shift and mapped modular multiplication;
readable tables retain the complete native operation names and parameters.
Detailed wire views can use `rowsPerPanel`,
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
claasp/cipher_modules/diagram/api.py`; correctness and malformed-input cases remain in pytest.

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

## Three-port word gates

Uniform XOR/AND/OR operations with three ordered operands use the existing
left/top/right manual ports. Source copies retain repeated operands explicitly,
and free three-lane regions are reused after their last use. Candidate schedules
with disconnected ports are rejected before cost comparison; `synthesis_report`
records their reasons in `rejected_candidates`. The selected diagram is still
reparsed from its actual exported glyphs. Other multi-input operations and mixed
word shapes remain explicit admission limits.
