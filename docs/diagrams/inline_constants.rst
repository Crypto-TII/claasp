Persistent two-line inline constants
====================================

The persistent word renderer uses the existing manual-library constant glyph:
labels of eight through fourteen characters put the first seven characters on
the upper interior row and the remaining characters on the middle row. The
leading ``x`` counts toward capacity. No new glyph, parameter registry or
reduction grouping is introduced. Longer literals remain unsupported here.
Previously accepted short constants retain their ``x`` plus minimum-two-digit
hexadecimal spelling and their exact pixels.

Parsing validates both visible rows and retains the complete visible literal.
Evaluation reads that literal through actual routes without native metadata.
Native reconstruction checks both rendered rows and their numeric consistency
with the original constant description; the original spelling stays in IR.
TikZ uses the same prefix/suffix arrangement only for newly supported long
literals. Layout selection remains generic.

Ordinary default Alzette and one-round Gimli now export with
``routed_words=True`` and fresh-parse exactly. Their default persistent path
still rejects earlier at live-operand spill. This is explicit routed admission,
not default activation. S-box, linear/permutation, mixed-width, four-input
grouping and other projection limits are unaffected. Declared/frontier state
serialization support must not be described as visual acceptance.

Reproduction
------------

With Sage-enabled Python and this checkout on ``PYTHONPATH``, run
``pytest -q tests/unit/diagram_inline_constants_test.py``. Tests cover every
eight-through-fourteen-character length in both default and routed modes,
three actual annotation round trips, identifier renaming, ordinary independent
integer formulas, native reconstruction and actual visible-glyph evaluation.

``check_inline_constants.py OUTPUT FROZEN_MATRIX_RESULTS`` writes ordinary
Alzette/Gimli evidence and compares all admitted frozen matrix artifacts byte
for byte. Baseline files are evaluation references only, never layout inputs.
``render_inline_constants.py OUTPUT`` writes a two-page actual-vector overview
document for ``pdflatex -no-shell-escape``. Overview scaling is not a readability
or minimum-font guarantee; Gimli remains dense.

The local checkpoint passed 387 diagram tests and 210 actual module doctests.
All eighteen admitted frozen matrix ASCII/TikZ artifacts were unchanged,
including Speck and ChaCha; the eight accepted Speck fixtures also passed.
Both new cipher cases agreed with native reconstruction and independent
integer formulas on three ordinary inputs each. These small samples do not
measure performance tails or establish broader primitive coverage.
