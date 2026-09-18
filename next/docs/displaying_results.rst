Presenting and exporting results
================================

CLAASP presents already-produced typed results. ``present(result)`` never runs
an analysis, solver, statistical program, or neural-training framework. The
returned ``ReportData`` is immutable and keeps evidence, applicability,
citations, realization identity, and execution metadata separate.

Trail and trace summaries
-------------------------

A trail report retains its kind, boundary patterns, total weight, proof bound,
ordered transitions, and method provenance. Graph locations are labelled as
optional evidence references rather than report identity:

.. doctest::

   >>> from claasp_next.presentation import render_section, trail_section
   >>> from claasp_next.semantics.cryptanalysis import (
   ...     Trail, TrailKind, TrailSearchResult, TrailStep, Transition, XorDifference,
   ... )
   >>> transition = Transition(
   ...     TrailKind.XOR_DIFFERENTIAL,
   ...     XorDifference(1, 4), XorDifference(3, 4), 4, 16,
   ... )
   >>> trail = Trail(
   ...     TrailKind.XOR_DIFFERENTIAL,
   ...     XorDifference(1, 4), XorDifference(3, 4),
   ...     (TrailStep("sbox_0_0", transition),),
   ... )
   >>> section = trail_section(TrailSearchResult(trail, 2.0, "fixed PRESENT evidence"))
   >>> "total weight" in render_section(section, format="terminal")
   True
   >>> section.tables[1].rows[0].cells[-1].text
   'sbox_0_0'

``trace_section(execution_trace)`` similarly follows the immutable annotation
order and labels source ids as graph-location evidence. It does not assume
that different realizations have corresponding internal component ids.

Exact, bounded, and unavailable properties
------------------------------------------

Property tables do not turn a bound or an unavailable value into an exact
score. The value column uses ``≤`` or ``≥`` for proved bounds, and unavailable
rows retain a typed diagnostic and applicability:

.. doctest::

   >>> from claasp_next.analysis import (
   ...     ComponentProperty, ComponentPropertyResult, PropertyClaim,
   ...     PropertyDomain, PropertyRequest,
   ... )
   >>> from claasp_next.analysis.component_properties import (
   ...     ComponentAnalysisProvenance, DiagnosticCode, PropertyDiagnostic,
   ... )
   >>> from claasp_next.presentation import component_property_section
   >>> provenance = ComponentAnalysisProvenance("AES MixColumns", "fixed field evidence")
   >>> request = PropertyRequest(
   ...     ComponentProperty.DIFFERENTIAL_BRANCH_NUMBER, PropertyDomain.WORD_LINEAR)
   >>> exact = ComponentPropertyResult(request, PropertyClaim.EXACT, 5, True, provenance)
   >>> bounded = ComponentPropertyResult(
   ...     request, PropertyClaim.PROVED_UPPER_BOUND, 5, False, provenance)
   >>> unavailable = ComponentPropertyResult(
   ...     PropertyRequest(ComponentProperty.BOOMERANG_UNIFORMITY, PropertyDomain.WORD_LINEAR),
   ...     PropertyClaim.UNAVAILABLE, None, False, provenance,
   ...     PropertyDiagnostic(DiagnosticCode.INAPPLICABLE_DOMAIN, "not a lookup table"),
   ... )
   >>> rows = component_property_section((exact, bounded, unavailable)).tables[0].rows
   >>> [row.cells[3].text for row in rows]
   ['5', '≤5', 'inapplicable: not a lookup table']
   >>> [row.cells[4].text for row in rows]
   ['exact', 'proved_bound', 'unavailable']

Avalanche and statistical summaries
-----------------------------------

Avalanche matrices always remain empirical and retain sample count and seed.
NIST STS and Dieharder adapters preserve every parser row, including weak,
failed, and unavailable observations. A ``StatisticalTestRun`` also contributes
dataset SHA-256, suite/tool version, command, and runtime.

.. doctest::

   >>> from claasp_next.analysis.avalanche import AvalancheResult
   >>> from claasp_next.presentation import avalanche_section
   >>> avalanche = AvalancheResult(
   ...     "speck", "plaintext", 4, 9, ((0.0, 0.5), (1.0, 0.25)))
   >>> summary, matrix = avalanche_section(avalanche).tables
   >>> (summary.rows[2].cells[1].text, summary.rows[3].cells[1].text)
   ('4', '9')
   >>> matrix.rows[1].cells[2].text
   '0.25'

Text and report-data export
---------------------------

Terminal, Markdown, and CSV consume the same immutable table. ``report_data``
returns ordinary JSON-compatible dictionaries and lists; it is a presentation
export, not the versioned graph/result serialization owned by M10.15.

.. doctest::

   >>> from claasp_next.presentation import (
   ...     MathematicalProvenance, PresentationProvenance, ReportData,
   ...     ReportSection, Table, TableColumn, TableRow, render_csv_table,
   ...     render_markdown_table, report_data,
   ... )
   >>> table = Table((TableColumn("property", "Property"), TableColumn("value", "Value")),
   ...               (TableRow.of("branch number", "5"),))
   >>> render_markdown_table(table).splitlines()[-1]
   '| branch number | 5 |'
   >>> render_csv_table(table)
   'Property,Value\nbranch number,5\n'
   >>> report = ReportData(
   ...     "Component report", (ReportSection("Properties", tables=(table,)),),
   ...     PresentationProvenance(MathematicalProvenance("fixed evidence")),
   ... )
   >>> report_data(report)["provenance"]["mathematical"]["method"]
   'fixed evidence'

``write_report`` is separate from adaptation and rendering. It requires an
explicit format and matching extension, writes UTF-8 with deterministic
newlines, does not create parents unless requested, and refuses to overwrite
unless ``overwrite=True``. It never derives directories from primitive or test
names and never adds an implicit timestamp.

Optional plotting
-----------------

Plotting is requested explicitly and imports Matplotlib only inside the driver
method. Set a noninteractive backend before importing ``pyplot`` in headless
programs::

   import matplotlib
   matplotlib.use("Agg")
   from claasp_next.drivers.renderers import MatplotlibPresentationDriver

   artifact = MatplotlibPresentationDriver().avalanche_matrix(avalanche)
   artifact.figure.savefig("avalanche.png")

Radar charts additionally require one ``RadarScale`` per included property.
Each scale states its mathematical domain, finite range, and whether higher or
lower is better. Axis labels show that contract and the evidence class.
Unavailable, inapplicable, unscaled, or nonnumeric properties are omitted and
listed in ``artifact.omitted``; unrelated domains are never normalized by an
implicit common formula.
