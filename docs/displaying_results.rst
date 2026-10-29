Reporting and exporting results
===============================

CLAASP presents already-produced typed results. ``present(result)`` never runs
an analysis, solver, statistical program, or neural-training framework. The
returned ``ReportData`` is immutable and keeps evidence, applicability,
citations, realization identity, and execution metadata separate.

Present a result
----------------

Start with an analysis result, adapt it into report data with ``present()``,
then render that report for a terminal or another supported destination:

.. doctest::

   >>> from claasp.presentation import present, render_report
   >>> from claasp.primitives import Speck
   >>> result = Speck(number_of_rounds=2).analysis.find_optimal_trail(
   ...     kind="xor_differential", backend="dependency_free"
   ... )
   >>> report = present(result)
   >>> report.title, report.sections[0].title
   ('Trail', 'Trail')
   >>> rendered = render_report(report)
   >>> "Round | Difference | Relative probability | Cumulative probability" in rendered
   True
   >>> "Proved optimal." in rendered
   True

``ReportData`` can be rendered, exported, combined with other report sections,
or passed to an application without parsing terminal text.

Terminal and detailed reports
-----------------------------

Use ``result.to_terminal()`` for the default report and
``result.to_terminal(details=True)`` for detailed data where supported.
Topic-specific reports and plots are demonstrated in each analysis guide.
To save terminal output, pass an open text stream as ``file=``.

Saving plots
------------

For a plottable analysis result, use
``result.plot(show=False, save_to="analysis.png")`` to save a plot without
opening a window. Plotting reuses the retained result. Select the view and
metric as described in the corresponding advanced guide.

Markdown, CSV and JSON report data
----------------------------------

Terminal, Markdown, and CSV consume the same immutable table. ``report_data``
returns ordinary JSON-compatible dictionaries and lists. It is a presentation
export, not the versioned graph/result serialization format.

.. doctest::

   >>> from claasp.presentation import (
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

Combining reports
-----------------

**TODO**

LaTeX tables
------------

Use the same report with ``format="latex"``. The export is a LaTeX fragment
containing sections, aligned ``tabular`` tables, notes and provenance. Include
it in a UTF-8 LaTeX document with ``\input{analysis.tex}``. No TeX executable
is needed to export it. Text is escaped, including underscores, percentages,
and backslashes; report values are never treated as raw TeX commands.

.. code-block:: python

   from claasp.presentation import present, write_report
   from claasp.primitives import Speck

   result = Speck(number_of_rounds=7).analysis.avalanche()
   report = present(result)
   write_report(report, "analysis.tex", format="latex")

For a string instead of a file, use ``render_report(report, format="latex")``.
For just one section, use ``render_section(section, format="latex")``.
Unicode text is preserved; select a TeX engine and fonts supporting that text
(for example LuaLaTeX). Column alignment follows the report's table model.
